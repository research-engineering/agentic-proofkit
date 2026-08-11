package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const compactV2WireManifestPath = "internal/app/testdata/compact-v2-wire-deltas.json"

type compactWireManifest struct {
	Baseline                        compactWireBaseline `json:"baseline"`
	Deltas                          []compactWireDelta  `json:"deltas"`
	OwnedBreakingChangeIDs          []string            `json:"ownedBreakingChangeIds"`
	OwnedMigrationStepDigests       []string            `json:"ownedMigrationStepDigests"`
	ProductionConsumerCandidates    []string            `json:"productionConsumerCandidates"`
	ProductionConsumerEvidenceClass string              `json:"productionConsumerEvidenceClass"`
	ProductionConsumerNonClaims     []string            `json:"productionConsumerNonClaims"`
	ReleaseVersion                  string              `json:"releaseVersion"`
	SchemaVersion                   int                 `json:"schemaVersion"`
}

type compactWireBaseline struct {
	CLIContractDirectionDigestsSHA256 string   `json:"cliContractDirectionDigestsSha256"`
	EvidenceClass                     string   `json:"evidenceClass"`
	NonClaims                         []string `json:"nonClaims"`
	ObservationsSHA256                string   `json:"observationsSha256"`
	SourceVersion                     string   `json:"sourceVersion"`
}

const compactWireBaselineEvidenceClass = "owner_authored_frozen_observation"

const compactWireBaselineNonClaim = "The frozen baseline observation is checksum-bound owner-authored migration evidence; it does not independently authenticate Git history or reproduce prior executable behavior."

const compactWireBaselineSourceVersion = "0.3.0"

type compactWireDelta struct {
	BreakingChangeID    string           `json:"breakingChangeId"`
	Class               string           `json:"class"`
	DeltaID             string           `json:"deltaId"`
	Direction           string           `json:"direction"`
	GroupID             string           `json:"groupId"`
	JSONPointer         string           `json:"jsonPointer"`
	MigrationStepDigest string           `json:"migrationStepDigest"`
	New                 compactWireState `json:"new"`
	Old                 compactWireState `json:"old"`
	Surface             string           `json:"surface"`
	Variant             string           `json:"variant"`
}

type compactWireState struct {
	Presence    string          `json:"presence"`
	Value       json.RawMessage `json:"value,omitempty"`
	ValueSHA256 string          `json:"valueSha256,omitempty"`
}

type compactReleaseOwner struct {
	BreakingChangeID    string
	MigrationStepDigest string
}

var compactReleaseOwners = map[string]compactReleaseOwner{
	"consumer-contract": {
		BreakingChangeID:    "proofkit.compact.consumer-contract-v2",
		MigrationStepDigest: "sha256:75e15bf1ac4e7803d4e82460730d9414f15b4298bfb05edd926b32c68b387051",
	},
	"declaration-fields": {
		BreakingChangeID:    "proofkit.compact.declaration-contract-v2",
		MigrationStepDigest: "sha256:6f08e4203a79328b0b1102a915318145d4267e46a5d9dc61d77548c4364a2d8b",
	},
	"declaration-root": {
		BreakingChangeID:    "proofkit.compact.declaration-contract-v2",
		MigrationStepDigest: "sha256:a4a556ee77d2a8c5bea219df76eb24a945d2d2e1cecfc4a088b6374535aa2800",
	},
	"identity-role": {
		BreakingChangeID:    "proofkit.compact.identity-role-closure",
		MigrationStepDigest: "sha256:2e5f489aaab8712ce3b124e4ad818ca1afcb00b65b9aade0cda3b2c5cba4ab21",
	},
	"source-set": {
		BreakingChangeID:    "proofkit.compact.source-set-v2",
		MigrationStepDigest: "sha256:5062c5587aa4c92b98e4fc78597b8d8d3f039f833673ae58cd29567ea918c0fc",
	},
}

var expectedCompactMetadataFreshnessDirections = []string{
	"adoption-contract-envelope|output",
	"evidence-graph|input",
	"evidence-graph|output",
	"proof-slice|input",
	"proof-slice|output",
	"requirement-bindings|input",
	"requirement-bindings|output",
}

func TestCompactV2WireDeltaReleaseAndParentContractClosure(t *testing.T) {
	manifest := readCompactWireManifest(t)
	root := repoRoot(t)
	record, err := releasechange.Read(filepath.Join(root, releasechange.RecordPath))
	if err != nil {
		t.Fatalf("read release change record: %v", err)
	}
	if manifest.ReleaseVersion != record.Version {
		t.Fatalf("wire manifest releaseVersion=%s want %s", manifest.ReleaseVersion, record.Version)
	}

	breaking := make(map[string]struct{}, len(record.BreakingChanges))
	for _, change := range record.BreakingChanges {
		if _, duplicate := breaking[change.ChangeID]; duplicate {
			t.Fatalf("duplicate release breaking change %s", change.ChangeID)
		}
		breaking[change.ChangeID] = struct{}{}
	}
	additions := make(map[string]struct{}, len(record.Additions))
	for _, change := range record.Additions {
		additions[change.ChangeID] = struct{}{}
	}
	migrationSteps := make(map[string]string, len(record.Migration.Steps))
	for _, step := range record.Migration.Steps {
		digest := sha256Text(step)
		if prior, duplicate := migrationSteps[digest]; duplicate {
			t.Fatalf("migration steps have duplicate digest %s for %q and %q", digest, prior, step)
		}
		migrationSteps[digest] = step
	}

	contract := readCLIContract(t)
	commands := make(map[string]cliContractCommand, len(contract.Commands))
	for _, command := range contract.Commands {
		commands[command.Command] = command
	}
	referencedBreaking := map[string]struct{}{}
	referencedSteps := map[string]struct{}{}
	previousDeltaID := ""
	for _, delta := range manifest.Deltas {
		if previousDeltaID != "" && previousDeltaID >= delta.DeltaID {
			t.Fatalf("wire deltas must be sorted and unique: %s before %s", previousDeltaID, delta.DeltaID)
		}
		previousDeltaID = delta.DeltaID
		assertCompactWireDeltaSemantics(t, delta)
		if err := validateCompactReleaseOwner(delta); err != nil {
			t.Fatal(err)
		}
		if delta.Class != "metadata_freshness" {
			if _, ok := breaking[delta.BreakingChangeID]; !ok {
				if _, addition := additions[delta.BreakingChangeID]; addition {
					t.Fatalf("delta %s references addition %s as a breaking owner", delta.DeltaID, delta.BreakingChangeID)
				}
				t.Fatalf("delta %s references unknown breaking change %s", delta.DeltaID, delta.BreakingChangeID)
			}
			if _, ok := migrationSteps[delta.MigrationStepDigest]; !ok {
				t.Fatalf("delta %s references unknown migration step digest %s", delta.DeltaID, delta.MigrationStepDigest)
			}
			referencedBreaking[delta.BreakingChangeID] = struct{}{}
			referencedSteps[delta.MigrationStepDigest] = struct{}{}
		}
		if delta.Class == "parent_contract" || delta.Class == "metadata_freshness" {
			assertCompactParentContractDelta(t, commands, delta)
		}
	}
	assertCompactParentContractChangeSetClosure(t, manifest)
	assertCompactParentContractSemanticClassification(t, manifest)
	assertExactStringSet(t, sortedSetKeys(referencedBreaking), manifest.OwnedBreakingChangeIDs, "wire-delta owned breaking-change closure")
	assertExactStringSet(t, sortedSetKeys(referencedSteps), manifest.OwnedMigrationStepDigests, "wire-delta owned migration-step closure")
	assertExactStringSet(t, manifest.OwnedBreakingChangeIDs, compactReleaseOwnerBreakingIDs(), "wire-delta declared breaking-change owner set")
	assertExactStringSet(t, manifest.OwnedMigrationStepDigests, compactReleaseOwnerStepDigests(), "wire-delta declared migration-step owner set")
}

func TestCompactWireDeltaRejectsSwappedReleaseForeignKeys(t *testing.T) {
	manifest := readCompactWireManifest(t)
	if len(manifest.Deltas) == 0 {
		t.Fatal("compact wire manifest has no deltas")
	}
	mutant := manifest.Deltas[0]
	mutant.BreakingChangeID = "proofkit.compact.source-set-v2"
	mutant.MigrationStepDigest = compactReleaseOwners["source-set"].MigrationStepDigest
	if err := validateCompactReleaseOwner(mutant); err == nil {
		t.Fatal("release owner validator accepted foreign keys from another compact delta group")
	}
}

func validateCompactReleaseOwner(delta compactWireDelta) error {
	if delta.Class == "metadata_freshness" {
		if delta.GroupID != "" || delta.BreakingChangeID != "" || delta.MigrationStepDigest != "" {
			return fmt.Errorf("metadata freshness delta %s must not claim a breaking or migration owner", delta.DeltaID)
		}
		return nil
	}
	owner, ok := compactReleaseOwners[delta.GroupID]
	if !ok {
		return fmt.Errorf("delta %s references unknown release owner group %s", delta.DeltaID, delta.GroupID)
	}
	if delta.BreakingChangeID != owner.BreakingChangeID || delta.MigrationStepDigest != owner.MigrationStepDigest {
		return fmt.Errorf("delta %s release owner=(%s,%s) want group %s owner=(%s,%s)", delta.DeltaID, delta.BreakingChangeID, delta.MigrationStepDigest, delta.GroupID, owner.BreakingChangeID, owner.MigrationStepDigest)
	}
	return nil
}

func readCompactWireManifest(t *testing.T) compactWireManifest {
	t.Helper()
	path := filepath.Join(repoRoot(t), compactV2WireManifestPath)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read compact wire manifest: %v", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), 4<<20)
	if err != nil {
		t.Fatalf("admit compact wire manifest: %v", err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatal("compact wire manifest must be an object")
	}
	assertExactObjectKeys(t, record, []string{"baseline", "deltas", "ownedBreakingChangeIds", "ownedMigrationStepDigests", "productionConsumerCandidates", "productionConsumerEvidenceClass", "productionConsumerNonClaims", "releaseVersion", "schemaVersion"}, "compact wire manifest")
	baseline, ok := record["baseline"].(map[string]any)
	if !ok {
		t.Fatal("compact wire manifest baseline must be an object")
	}
	assertExactObjectKeys(t, baseline, []string{"cliContractDirectionDigestsSha256", "evidenceClass", "nonClaims", "observationsSha256", "sourceVersion"}, "compact wire manifest baseline")
	if number, ok := record["schemaVersion"].(json.Number); !ok || number.String() != "2" {
		t.Fatalf("compact wire manifest schemaVersion=%v want 2", record["schemaVersion"])
	}
	rawDeltas, ok := record["deltas"].([]any)
	if !ok || len(rawDeltas) == 0 {
		t.Fatal("compact wire manifest deltas must be a non-empty array")
	}
	for index, raw := range rawDeltas {
		delta, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("compact wire manifest delta %d must be an object", index)
		}
		expectedKeys := []string{"class", "deltaId", "direction", "jsonPointer", "new", "old", "surface", "variant"}
		if delta["class"] != "metadata_freshness" {
			expectedKeys = append(expectedKeys, "breakingChangeId", "groupId", "migrationStepDigest")
		}
		assertExactObjectKeys(t, delta, expectedKeys, fmt.Sprintf("compact wire manifest delta %d", index))
		for _, stateName := range []string{"old", "new"} {
			state, ok := delta[stateName].(map[string]any)
			if !ok {
				t.Fatalf("compact wire manifest delta %d %s must be an object", index, stateName)
			}
			presence, _ := state["presence"].(string)
			expected := []string{"presence"}
			if presence == "present" {
				_, hasValue := state["value"]
				_, hasDigest := state["valueSha256"]
				if hasValue == hasDigest {
					t.Fatalf("compact wire manifest delta %d %s must have exactly one of value or valueSha256", index, stateName)
				}
				if hasValue {
					expected = append(expected, "value")
				} else {
					expected = append(expected, "valueSha256")
				}
			}
			assertExactObjectKeys(t, state, expected, fmt.Sprintf("compact wire manifest delta %d %s", index, stateName))
		}
	}
	manifest, err := admission.DecodeTypedJSON[compactWireManifest](bytes.NewReader(content), 4<<20)
	if err != nil {
		t.Fatalf("decode typed compact wire manifest: %v", err)
	}
	if !sort.StringsAreSorted(manifest.ProductionConsumerCandidates) || hasAdjacentDuplicate(manifest.ProductionConsumerCandidates) {
		t.Fatal("compact wire manifest productionConsumerCandidates must be sorted and unique")
	}
	if manifest.ProductionConsumerEvidenceClass != compactProductionConsumerEvidenceClass {
		t.Fatalf("compact wire manifest productionConsumerEvidenceClass=%q want %q", manifest.ProductionConsumerEvidenceClass, compactProductionConsumerEvidenceClass)
	}
	if !slices.Equal(manifest.ProductionConsumerNonClaims, []string{compactProductionConsumerNonClaim}) {
		t.Fatalf("compact wire manifest productionConsumerNonClaims=%q want bounded candidate non-claim", manifest.ProductionConsumerNonClaims)
	}
	if manifest.Baseline.EvidenceClass != compactWireBaselineEvidenceClass {
		t.Fatalf("compact wire manifest baseline evidenceClass=%q want %q", manifest.Baseline.EvidenceClass, compactWireBaselineEvidenceClass)
	}
	if !slices.Equal(manifest.Baseline.NonClaims, []string{compactWireBaselineNonClaim}) {
		t.Fatalf("compact wire manifest baseline nonClaims=%q want the bounded provenance non-claim", manifest.Baseline.NonClaims)
	}
	if manifest.Baseline.SourceVersion != compactWireBaselineSourceVersion {
		t.Fatalf("compact wire manifest baseline sourceVersion=%q want %q", manifest.Baseline.SourceVersion, compactWireBaselineSourceVersion)
	}
	if !validSHA256Digest(manifest.Baseline.ObservationsSHA256) {
		t.Fatalf("compact wire manifest baseline observations digest=%q", manifest.Baseline.ObservationsSHA256)
	}
	if !validSHA256Digest(manifest.Baseline.CLIContractDirectionDigestsSHA256) {
		t.Fatalf("compact wire manifest baseline CLI contract direction digest=%q", manifest.Baseline.CLIContractDirectionDigestsSHA256)
	}
	for name, values := range map[string][]string{
		"ownedBreakingChangeIds":    manifest.OwnedBreakingChangeIDs,
		"ownedMigrationStepDigests": manifest.OwnedMigrationStepDigests,
	} {
		if !sort.StringsAreSorted(values) || hasAdjacentDuplicate(values) {
			t.Fatalf("compact wire manifest %s must be sorted and unique", name)
		}
	}
	return manifest
}

func assertCompactWireDeltaSemantics(t *testing.T, delta compactWireDelta) {
	t.Helper()
	if delta.DeltaID == "" || delta.Surface == "" || delta.Direction == "" || delta.Variant == "" {
		t.Fatalf("wire delta has an empty identity field: %#v", delta)
	}
	if delta.Class != "metadata_freshness" && (delta.GroupID == "" || delta.BreakingChangeID == "") {
		t.Fatalf("semantic wire delta has an empty release-owner field: %#v", delta)
	}
	if !strings.HasPrefix(delta.JSONPointer, "/") {
		t.Fatalf("wire delta %s has non-absolute JSON pointer %q", delta.DeltaID, delta.JSONPointer)
	}
	if delta.Class != "metadata_freshness" {
		if len(delta.MigrationStepDigest) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(delta.MigrationStepDigest, "sha256:") {
			t.Fatalf("wire delta %s has invalid migration digest %q", delta.DeltaID, delta.MigrationStepDigest)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(delta.MigrationStepDigest, "sha256:")); err != nil {
			t.Fatalf("wire delta %s has invalid migration digest: %v", delta.DeltaID, err)
		}
	}
	wantPresence := map[string][2]string{
		"add":                {"absent", "present"},
		"metadata_freshness": {"present", "present"},
		"parent_contract":    {"present", "present"},
		"remove":             {"present", "absent"},
		"replace":            {"present", "present"},
	}
	want, ok := wantPresence[delta.Class]
	if !ok {
		t.Fatalf("wire delta %s has unknown class %s", delta.DeltaID, delta.Class)
	}
	if delta.Old.Presence != want[0] || delta.New.Presence != want[1] {
		t.Fatalf("wire delta %s class=%s has presence %s->%s want %s->%s", delta.DeltaID, delta.Class, delta.Old.Presence, delta.New.Presence, want[0], want[1])
	}
	for name, state := range map[string]compactWireState{"old": delta.Old, "new": delta.New} {
		if state.Presence == "present" && (len(state.Value) == 0) == (state.ValueSHA256 == "") {
			t.Fatalf("wire delta %s %s present state must have exactly one value representation", delta.DeltaID, name)
		}
		if state.Presence == "absent" && (len(state.Value) != 0 || state.ValueSHA256 != "") {
			t.Fatalf("wire delta %s %s absent state has a value", delta.DeltaID, name)
		}
		if state.ValueSHA256 != "" {
			assertSHA256Ref(t, state.ValueSHA256, fmt.Sprintf("wire delta %s %s valueSha256", delta.DeltaID, name))
		}
	}
}

func compactReleaseOwnerBreakingIDs() []string {
	values := map[string]struct{}{}
	for _, owner := range compactReleaseOwners {
		values[owner.BreakingChangeID] = struct{}{}
	}
	return sortedSetKeys(values)
}

func compactReleaseOwnerStepDigests() []string {
	values := map[string]struct{}{}
	for _, owner := range compactReleaseOwners {
		values[owner.MigrationStepDigest] = struct{}{}
	}
	return sortedSetKeys(values)
}

func assertSHA256Ref(t *testing.T, value, context string) {
	t.Helper()
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		t.Fatalf("%s=%q is not a sha256 reference", context, value)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:")); err != nil {
		t.Fatalf("%s=%q is not a sha256 reference: %v", context, value, err)
	}
}

func assertCompactParentContractDelta(t *testing.T, commands map[string]cliContractCommand, delta compactWireDelta) {
	t.Helper()
	command, ok := commands[delta.Surface]
	if !ok {
		t.Fatalf("parent-contract delta %s references unknown command %s", delta.DeltaID, delta.Surface)
	}
	raw := command.InputContract
	if delta.Direction == "output" {
		raw = command.OutputContract
	} else if delta.Direction != "input" {
		t.Fatalf("parent-contract delta %s has invalid direction %s", delta.DeltaID, delta.Direction)
	}
	if raw == nil {
		t.Fatalf("parent-contract delta %s references absent %s contract", delta.DeltaID, delta.Direction)
	}
	content, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("encode parent-contract delta %s source: %v", delta.DeltaID, err)
	}
	actual, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("admit parent-contract delta %s source: %v", delta.DeltaID, err)
	}
	encoded, err := stablejson.Marshal(actual)
	if err != nil {
		t.Fatalf("encode parent-contract delta %s: %v", delta.DeltaID, err)
	}
	if delta.New.ValueSHA256 != sha256Text(string(encoded)) {
		t.Fatalf("parent-contract delta %s digest=%s want %s", delta.DeltaID, sha256Text(string(encoded)), delta.New.ValueSHA256)
	}
}

func assertCompactParentContractChangeSetClosure(t *testing.T, manifest compactWireManifest) {
	t.Helper()
	baseline := readCompactV1WireObservationDocument(t)
	baselineJSON, err := json.Marshal(baseline.CLIContractDirectionDigests)
	if err != nil {
		t.Fatalf("encode baseline CLI contract direction digests: %v", err)
	}
	baselineValue, err := admission.DecodeJSON(bytes.NewReader(baselineJSON), int64(len(baselineJSON)))
	if err != nil {
		t.Fatalf("admit baseline CLI contract direction digests: %v", err)
	}
	encodedBaseline, err := stablejson.Marshal(baselineValue)
	if err != nil {
		t.Fatalf("canonicalize baseline CLI contract direction digests: %v", err)
	}
	if got := sha256Text(string(encodedBaseline)); got != manifest.Baseline.CLIContractDirectionDigestsSHA256 {
		t.Fatalf("baseline CLI contract direction digest=%s want %s", got, manifest.Baseline.CLIContractDirectionDigestsSHA256)
	}
	current := currentCLIContractDirectionDigests(t)
	allKeys := map[string]struct{}{}
	for key := range baseline.CLIContractDirectionDigests {
		allKeys[key] = struct{}{}
	}
	for key := range current {
		allKeys[key] = struct{}{}
	}
	changed := []string{}
	for _, key := range sortedSetKeys(allKeys) {
		if baseline.CLIContractDirectionDigests[key] != current[key] {
			changed = append(changed, key)
		}
	}
	declared := []string{}
	for _, delta := range manifest.Deltas {
		if delta.Class == "parent_contract" || delta.Class == "metadata_freshness" {
			declared = append(declared, delta.Surface+"|"+delta.Direction)
		}
	}
	sort.Strings(declared)
	if hasAdjacentDuplicate(declared) {
		t.Fatalf("parent-contract delta directions must be unique: %v", declared)
	}
	assertExactStringSet(t, declared, changed, "changed CLI parent-contract direction closure")
}

func assertCompactParentContractSemanticClassification(t *testing.T, manifest compactWireManifest) {
	t.Helper()
	oldObservations := readCompactV1WireObservations(t)
	currentObservations := currentCompactV2WireObservations(t)
	metadataOnly := []string{}
	for _, delta := range manifest.Deltas {
		if delta.Class != "parent_contract" && delta.Class != "metadata_freshness" {
			continue
		}
		key := compactWireObservationKey(delta.Surface, delta.Direction, delta.Variant)
		oldValue := compactWithoutNativeSourceDigest(t, oldObservations[key], key+" frozen")
		currentValue := compactWithoutNativeSourceDigest(t, currentObservations[key], key+" current")
		equalWithoutDigest := compactJSONEqual(oldValue, currentValue)
		if equalWithoutDigest != (delta.Class == "metadata_freshness") {
			t.Fatalf("parent-contract delta %s class=%s does not match metadata-only=%t", delta.DeltaID, delta.Class, equalWithoutDigest)
		}
		if equalWithoutDigest {
			metadataOnly = append(metadataOnly, delta.Surface+"|"+delta.Direction)
		}
	}
	sort.Strings(metadataOnly)
	assertExactStringSet(t, metadataOnly, expectedCompactMetadataFreshnessDirections, "metadata-only CLI parent-contract direction closure")
}

func compactWithoutNativeSourceDigest(t *testing.T, value any, context string) any {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode %s: %v", context, err)
	}
	clone, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("clone %s: %v", context, err)
	}
	record, ok := clone.(map[string]any)
	if !ok {
		t.Fatalf("%s must be an object", context)
	}
	contract, ok := record["contract"].(map[string]any)
	if !ok {
		t.Fatalf("%s must contain a contract object", context)
	}
	nativeSource, ok := contract["nativeSource"].(map[string]any)
	if !ok {
		return record
	}
	if _, ok := nativeSource["canonicalDigest"]; !ok {
		return record
	}
	delete(nativeSource, "canonicalDigest")
	return record
}

func currentCLIContractDirectionDigests(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, command := range readCLIContract(t).Commands {
		for _, item := range []struct {
			direction string
			value     any
		}{{direction: "input", value: command.InputContract}, {direction: "output", value: command.OutputContract}} {
			if item.value == nil {
				continue
			}
			content, err := json.Marshal(item.value)
			if err != nil {
				t.Fatalf("encode %s %s contract: %v", command.Command, item.direction, err)
			}
			canonical, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
			if err != nil {
				t.Fatalf("admit %s %s contract: %v", command.Command, item.direction, err)
			}
			encoded, err := stablejson.Marshal(canonical)
			if err != nil {
				t.Fatalf("canonicalize %s %s contract: %v", command.Command, item.direction, err)
			}
			result[command.Command+"|"+item.direction] = sha256Text(string(encoded))
		}
	}
	return result
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func assertExactObjectKeys(t *testing.T, record map[string]any, want []string, context string) {
	t.Helper()
	actual := make([]string, 0, len(record))
	for key := range record {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if !slices.Equal(actual, sortedWant) {
		t.Fatalf("%s keys=%v want %v", context, actual, sortedWant)
	}
}

func assertExactStringSet(t *testing.T, actual, want []string, context string) {
	t.Helper()
	if !slices.Equal(actual, want) {
		t.Fatalf("%s=%v want %v", context, actual, want)
	}
}

func sortedSetKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sha256Text(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hasAdjacentDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}
