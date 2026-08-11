package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const compactV1WireObservationsPath = "internal/app/testdata/compact-v1-wire-observations.json"

type compactWireObservations struct {
	CLIContractDirectionDigests map[string]string        `json:"cliContractDirectionDigests"`
	Observations                []compactWireObservation `json:"observations"`
	SchemaVersion               int                      `json:"schemaVersion"`
}

type compactWireObservation struct {
	Direction string `json:"direction"`
	Document  any    `json:"document"`
	Surface   string `json:"surface"`
	Variant   string `json:"variant"`
}

var expectedCompactWireObservationKeys = []string{
	"adoption-contract-envelope|input|aggregate",
	"adoption-contract-envelope|input|union",
	"adoption-contract-envelope|output|union",
	"compact-contract|input|direct",
	"compact-resolver|output|resolver",
	"conformance-profile|input|direct",
	"conformance-profile|input|union",
	"conformance-profile|output|profile",
	"conformance-profile|output|union",
	"evidence-graph|input|union",
	"evidence-graph|output|union",
	"impact|input|direct",
	"impact|input|union",
	"impact|output|direct",
	"impact|output|union",
	"pilot-admission|input|direct",
	"pilot-admission|input|envelope",
	"pilot-admission|input|union",
	"pilot-admission|output|union",
	"proof-slice|input|union",
	"proof-slice|output|union",
	"requirement-bindings|input|union",
	"requirement-bindings|output|union",
	"requirement-browser-server|input|union",
	"requirement-browser-server|output|workspace-runtime",
	"requirement-context-compose|output|coverage-runtime",
	"requirement-context-slice|output|coverage-runtime",
	"requirement-coverage-input-compose|input|union",
	"requirement-coverage-input-compose|input|wrapper",
	"requirement-coverage-input-compose|output|union",
	"requirement-coverage-input-compose|output|wrapper",
	"requirement-coverage-view|input|union",
	"requirement-coverage-view|input|wrapper",
	"requirement-coverage-view|output|compact-scenario",
	"requirement-coverage-view|output|root",
	"requirement-coverage-view|output|union",
	"requirement-impact-input-compose|input|union",
	"requirement-impact-input-compose|input|wrapper",
	"requirement-impact-input-compose|output|union",
	"requirement-impact-input-compose|output|wrapper",
	"requirement-proof-resolver|input|union",
	"requirement-proof-resolver|output|resolver",
	"requirement-proof-resolver|output|union",
	"requirement-proof-source-set|input|canonical-envelope",
	"requirement-proof-source-set|input|fragment",
	"requirement-proof-source-set|input|source-row",
	"requirement-proof-source-set|input|source-set",
	"requirement-proof-source-set|input|union",
	"requirement-proof-source-set|input|wrapper",
	"requirement-proof-source-set|output|union",
	"requirement-proof-source-set|output|wrapper",
	"requirement-proof-view|input|compact",
	"requirement-proof-view|input|union",
	"requirement-proof-view|output|compact",
	"requirement-proof-view|output|union",
	"requirement-semantic-diff|output|coverage-runtime",
	"requirement-traceability-graph|output|coverage-runtime",
	"test-evidence-inventory|input|proof-binding",
	"test-evidence-inventory|input|union",
	"test-evidence-inventory|output|normalized",
	"test-evidence-inventory|output|union",
}

func TestCompactV2WireDeltasResolveAgainstFrozenAndCurrentObservations(t *testing.T) {
	manifest := readCompactWireManifest(t)
	oldObservations := readCompactV1WireObservations(t)
	currentObservations := currentCompactV2WireObservations(t)
	baselineBytes, err := stablejson.Marshal(oldObservations)
	if err != nil {
		t.Fatalf("encode normalized compact v1 observations: %v", err)
	}
	if digest := sha256Text(string(baselineBytes)); digest != manifest.Baseline.ObservationsSHA256 {
		t.Fatalf("wire baseline observation digest=%s want %s", digest, manifest.Baseline.ObservationsSHA256)
	}
	if !sort.StringsAreSorted(expectedCompactWireObservationKeys) || hasAdjacentDuplicate(expectedCompactWireObservationKeys) {
		t.Fatal("expected compact wire observation keys must be independently sorted and unique")
	}
	manifestKeys := map[string]struct{}{}
	for _, delta := range manifest.Deltas {
		key := compactWireObservationKey(delta.Surface, delta.Direction, delta.Variant)
		manifestKeys[key] = struct{}{}
		oldDocument, ok := oldObservations[key]
		if !ok {
			t.Fatalf("wire delta %s has no frozen old observation %s", delta.DeltaID, key)
		}
		currentDocument, ok := currentObservations[key]
		if !ok {
			t.Fatalf("wire delta %s has no current owner observation %s", delta.DeltaID, key)
		}
		assertCompactObservedState(t, delta, "old", oldDocument, delta.Old)
		assertCompactObservedState(t, delta, "new", currentDocument, delta.New)
	}
	assertExactStringSet(t, sortedSetKeys(manifestKeys), expectedCompactWireObservationKeys, "wire manifest observation-key closure")
	assertExactStringSet(t, sortedSetKeys(oldObservations), expectedCompactWireObservationKeys, "frozen wire observation-key closure")
	assertExactStringSet(t, sortedSetKeys(currentObservations), expectedCompactWireObservationKeys, "current wire observation-key closure")
	assertCompactWireDeltaFrontierClosure(t, manifest.Deltas, oldObservations, currentObservations)
}

func readCompactV1WireObservations(t *testing.T) map[string]any {
	t.Helper()
	decoded := readCompactV1WireObservationDocument(t)
	result := make(map[string]any, len(decoded.Observations))
	previous := ""
	for _, observation := range decoded.Observations {
		key := compactWireObservationKey(observation.Surface, observation.Direction, observation.Variant)
		if previous != "" && previous >= key {
			t.Fatalf("compact v1 wire observations must be sorted and unique: %s before %s", previous, key)
		}
		previous = key
		result[key] = observation.Document
	}
	return result
}

func readCompactV1WireObservationDocument(t *testing.T) compactWireObservations {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), compactV1WireObservationsPath))
	if err != nil {
		t.Fatalf("read compact v1 wire observations: %v", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("admit compact v1 wire observations: %v", err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatal("compact v1 wire observations must be an object")
	}
	assertExactObjectKeys(t, record, []string{"cliContractDirectionDigests", "observations", "schemaVersion"}, "compact v1 wire observations")
	if number, ok := record["schemaVersion"].(json.Number); !ok || number.String() != "1" {
		t.Fatalf("compact v1 wire observations schemaVersion=%v want 1", record["schemaVersion"])
	}
	raw, ok := record["observations"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatal("compact v1 wire observations must contain observations")
	}
	for index, value := range raw {
		observation, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("compact v1 wire observation %d must be an object", index)
		}
		assertExactObjectKeys(t, observation, []string{"direction", "document", "surface", "variant"}, fmt.Sprintf("compact v1 wire observation %d", index))
	}
	decoded, err := admission.DecodeTypedJSON[compactWireObservations](bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("decode compact v1 wire observations: %v", err)
	}
	if len(decoded.CLIContractDirectionDigests) == 0 {
		t.Fatal("compact v1 wire observations must contain CLI contract direction digests")
	}
	for key, value := range decoded.CLIContractDirectionDigests {
		parts := strings.Split(key, "|")
		if len(parts) != 2 || (parts[1] != "input" && parts[1] != "output") || !validSHA256Digest(value) {
			t.Fatalf("compact v1 CLI contract direction digest %s=%q is invalid", key, value)
		}
	}
	return decoded
}

func currentCompactV2WireObservations(t *testing.T) map[string]any {
	t.Helper()
	compactInput := compactV2WireContract()
	contract, err := compactproofcontract.Admit(compactInput)
	if err != nil {
		t.Fatalf("admit current compact wire contract: %v", err)
	}
	resolver, err := contract.ResolverProjection(compactproofcontract.ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("build current compact resolver observation: %v", err)
	}
	adoptionInput := strictJSONObjectFromText(t, cliAdoptionContractEnvelopeInput(), "current adoption aggregate input")
	pilotDirect := cliPilotInput("proofkit.cli.pilot.first", false)
	pilotEnvelope := strictJSONObjectFromText(t, cliPilotContractEnvelopeInput("all"), "current pilot envelope input")
	conformanceInput := strictJSONObjectFromText(t, cliConformanceProfileInput(), "current conformance input")
	conformanceOutput := runCLIForJSON(t, []string{"conformance-profile", "--input", "-", "--profile", "local"}, cliJSON(conformanceInput))

	impactFixture := strings.Replace(
		cliImpactInputComposeInput(),
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json"]`,
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json","internal/app/cli_abi_test.go"]`,
		1,
	)
	impactComposeInput := strictJSONObjectFromText(t, impactFixture, "current impact compose input")
	impactInput := runCLIForJSON(t, []string{"requirement-impact-input-compose", "--input", "-"}, cliJSON(impactComposeInput))
	impactOutput := runCLIForJSON(t, []string{"impact", "--input", "-"}, cliJSON(impactInput))

	sourceInput := cliProofSourceSetInput(t, "canonical_contract")
	sourceOutput := runAppJSON(t, []string{"requirement-proof-source-set", "--input", "-"}, sourceInput)
	sourceFragment := strictJSONObjectFromText(t, sourceInput["sources"].([]any)[0].(map[string]any)["text"].(string), "current compact source fragment")
	sourceRow := compactSourceRoleObservation(t, sourceInput["sourceSet"].(map[string]any))

	coverageComposeInput := strictJSONObjectFromText(t, cliCoverageInputComposeInput(), "current coverage compose input")
	coverageInput := runCLIForJSON(t, []string{"requirement-coverage-input-compose", "--input", "-"}, cliJSON(coverageComposeInput))
	coverageOutput := runCLIForJSON(t, []string{"requirement-coverage-view", "--input", "-", "--format", "json"}, cliJSON(coverageInput))
	coverageScenario := firstCompactCoverageScenario(t, coverageOutput)

	inventoryInput := strictJSONObjectFromText(t, cliProofBindingDerivedInventoryInput(), "current proof-binding inventory input")
	inventoryOutput := runCLIForJSON(t, []string{"test-evidence-inventory", "--input", "-", "--projection", "proof-binding-derived", "--normalized-inventory"}, cliJSON(inventoryInput))
	proofViewOutput := runCLIForJSON(t, []string{"requirement-proof-view", "--input", "-", "--format", "json", "--local-environment-class", "local-go"}, cliJSON(compactInput))

	result := map[string]any{
		compactWireObservationKey("adoption-contract-envelope", "input", "aggregate"):            adoptionInput,
		compactWireObservationKey("compact-contract", "input", "direct"):                         compactInput,
		compactWireObservationKey("compact-resolver", "output", "resolver"):                      resolver,
		compactWireObservationKey("conformance-profile", "input", "direct"):                      conformanceInput,
		compactWireObservationKey("conformance-profile", "output", "profile"):                    conformanceOutput,
		compactWireObservationKey("impact", "input", "direct"):                                   impactInput,
		compactWireObservationKey("impact", "output", "direct"):                                  impactOutput,
		compactWireObservationKey("pilot-admission", "input", "direct"):                          pilotDirect,
		compactWireObservationKey("pilot-admission", "input", "envelope"):                        pilotEnvelope,
		compactWireObservationKey("requirement-coverage-input-compose", "input", "wrapper"):      coverageComposeInput,
		compactWireObservationKey("requirement-coverage-input-compose", "output", "wrapper"):     coverageInput,
		compactWireObservationKey("requirement-coverage-view", "input", "wrapper"):               coverageInput,
		compactWireObservationKey("requirement-coverage-view", "output", "compact-scenario"):     coverageScenario,
		compactWireObservationKey("requirement-coverage-view", "output", "root"):                 coverageOutput,
		compactWireObservationKey("requirement-impact-input-compose", "input", "wrapper"):        impactComposeInput,
		compactWireObservationKey("requirement-impact-input-compose", "output", "wrapper"):       impactInput,
		compactWireObservationKey("requirement-proof-resolver", "output", "resolver"):            resolver,
		compactWireObservationKey("requirement-proof-source-set", "input", "canonical-envelope"): sourceInput["canonicalEnvelope"],
		compactWireObservationKey("requirement-proof-source-set", "input", "fragment"):           sourceFragment,
		compactWireObservationKey("requirement-proof-source-set", "input", "source-row"):         sourceRow,
		compactWireObservationKey("requirement-proof-source-set", "input", "source-set"):         sourceInput["sourceSet"],
		compactWireObservationKey("requirement-proof-source-set", "input", "wrapper"):            sourceInput,
		compactWireObservationKey("requirement-proof-source-set", "output", "wrapper"):           sourceOutput,
		compactWireObservationKey("requirement-proof-view", "input", "compact"):                  compactInput,
		compactWireObservationKey("requirement-proof-view", "output", "compact"):                 proofViewOutput,
		compactWireObservationKey("test-evidence-inventory", "input", "proof-binding"):           inventoryInput,
		compactWireObservationKey("test-evidence-inventory", "output", "normalized"):             inventoryOutput,
	}
	for key, observation := range currentCompactParentContractObservations(t) {
		result[key] = observation
	}
	for key, observation := range currentCompactContextChainObservations(t) {
		result[key] = observation
	}
	return result
}

func currentCompactContextChainObservations(t *testing.T) map[string]any {
	t.Helper()
	root := t.TempDir()
	coverageCompose := strictJSONObjectFromText(t, cliCoverageInputComposeInput(), "compact context coverage compose input")
	coverageInput := runCLIForJSON(t, []string{"requirement-coverage-input-compose", "--input", "-"}, cliJSON(coverageCompose))
	requirementSource := coverageCompose["requirementSource"].(map[string]any)
	sourceID := requirementSource["sourceId"].(string)
	tree := map[string]any{
		"schemaVersion": json.Number("2"), "treeId": "proofkit.compact.context-tree", "rootNodeId": "proofkit.compact.context-root",
		"callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{},
		"nodes": []any{map[string]any{
			"nodeId": "proofkit.compact.context-root", "nodeKind": "meta_spec", "label": "Compact context fixture", "displayOrder": json.Number("1"),
			"callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{
				"sourceRefId": "proofkit.compact.context-root.requirements", "sourceRefKind": "source_id",
				"sourceRole": "requirements", "sourceId": sourceID,
			}},
		}},
	}
	writeCLIJSONFixture(t, root, "proofkit/spec-tree.json", tree)
	writeCLIJSONFixture(t, root, "docs/specs/compact/requirements.v1.json", requirementSource)
	writeCLIJSONFixture(t, root, "proofkit/coverage-input.json", coverageInput)
	catalog := map[string]any{
		"schemaVersion": json.Number("1"), "catalogId": "proofkit.compact.context",
		"specTree": map[string]any{"path": "proofkit/spec-tree.json"},
		"requirementSources": []any{map[string]any{
			"nodeId": "proofkit.compact.context-root", "path": "docs/specs/compact/requirements.v1.json",
		}},
		"coverage": map[string]any{"path": "proofkit/coverage-input.json"},
	}
	base := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	sliceInput := map[string]any{
		"schemaVersion": json.Number("1"), "sliceId": "proofkit.compact.context.slice", "context": base,
		"query": map[string]any{"profile": "coverage", "requirementIds": []any{"REQ-PROOFKIT-CLI-COVERAGE-001"}},
	}
	sliceOutput := runAppJSON(t, []string{"requirement-context-slice", "--input", "-"}, sliceInput)

	requirements := requirementSource["requirements"].([]any)
	requirements[0].(map[string]any)["invariant"] = "Compact context fixture changed invariant."
	writeCLIJSONFixture(t, root, "docs/specs/compact/requirements.v1.json", requirementSource)
	current := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	diffInput := map[string]any{
		"schemaVersion": json.Number("2"), "diffId": "proofkit.compact.context.diff",
		"baseContext": base, "currentContext": current,
	}
	diffOutput := runAppJSON(t, []string{"requirement-semantic-diff", "--input", "-"}, diffInput)
	graphInput := map[string]any{
		"schemaVersion": json.Number("2"), "graphId": "proofkit.compact.context.graph", "context": current,
	}
	graphOutput := runAppJSON(t, []string{"requirement-traceability-graph", "--input", "-"}, graphInput)
	workspaceInput := map[string]any{
		"schemaVersion": json.Number("2"), "workspaceId": "proofkit.compact.context.workspace", "context": current,
		"diffInput": diffInput, "graphInput": graphInput,
	}
	browserHandle, err := requirementbrowser.StartServer(workspaceInput, requirementbrowser.Options{Host: "127.0.0.1", Port: 0, PortSet: true, View: "workspace"})
	if err != nil {
		t.Fatalf("start compact context workspace server: %v", err)
	}
	closeCompactObservationServer(t, browserHandle)

	baseCoverage := jsonObjectField(t, jsonObjectField(t, base, "projections"), "coverage")
	currentCoverage := jsonObjectField(t, jsonObjectField(t, current, "projections"), "coverage")
	sliceCoverage := jsonObjectField(t, jsonObjectField(t, sliceOutput, "projections"), "coverage")
	baseIdentity := compactCoverageIdentityObservation(t, baseCoverage)
	assertCompactIdentityObservation(t, sliceCoverage, baseIdentity, "context slice output")
	assertCompactIdentityObservation(t, currentCoverage, baseIdentity, "current context output")
	if diffOutput["baseSnapshotId"] != base["snapshotId"] || diffOutput["currentSnapshotId"] != current["snapshotId"] {
		t.Fatalf("semantic diff output lost context identity: base=%v current=%v", diffOutput["baseSnapshotId"], diffOutput["currentSnapshotId"])
	}
	if graphOutput["snapshotId"] != current["snapshotId"] {
		t.Fatalf("traceability graph output snapshotId=%v want %v", graphOutput["snapshotId"], current["snapshotId"])
	}
	if browserHandle.SnapshotID != current["snapshotId"] {
		t.Fatalf("browser runtime snapshotId=%v want %v", browserHandle.SnapshotID, current["snapshotId"])
	}
	baseCoverageDigest := compactWireValueDigest(t, baseCoverage)
	return map[string]any{
		compactWireObservationKey("requirement-browser-server", "output", "workspace-runtime"): map[string]any{
			"snapshotId": browserHandle.SnapshotID,
		},
		compactWireObservationKey("requirement-context-compose", "output", "coverage-runtime"): map[string]any{
			"coverageSha256": baseCoverageDigest, "identities": baseIdentity,
		},
		compactWireObservationKey("requirement-context-slice", "output", "coverage-runtime"): map[string]any{
			"coverageSha256": compactWireValueDigest(t, sliceCoverage), "identities": compactCoverageIdentityObservation(t, sliceCoverage),
		},
		compactWireObservationKey("requirement-semantic-diff", "output", "coverage-runtime"): map[string]any{
			"baseSnapshotId": diffOutput["baseSnapshotId"], "currentSnapshotId": diffOutput["currentSnapshotId"],
			"outputSha256": compactWireValueDigest(t, diffOutput),
		},
		compactWireObservationKey("requirement-traceability-graph", "output", "coverage-runtime"): map[string]any{
			"outputSha256": compactWireValueDigest(t, graphOutput), "snapshotId": graphOutput["snapshotId"],
		},
	}
}

func compactCoverageIdentityObservation(t *testing.T, value any) map[string]any {
	t.Helper()
	bindingIDs := map[string]struct{}{}
	routeIDs := map[string]struct{}{}
	collectCompactIdentityValues(value, bindingIDs, routeIDs)
	if len(bindingIDs) == 0 || len(routeIDs) == 0 {
		t.Fatalf("compact coverage projection has no stable identities: bindings=%v routes=%v", sortedSetKeys(bindingIDs), sortedSetKeys(routeIDs))
	}
	return map[string]any{
		"bindingRecordIds": stringsToAny(sortedSetKeys(bindingIDs)),
		"witnessRouteIds":  stringsToAny(sortedSetKeys(routeIDs)),
	}
}

func collectCompactIdentityValues(value any, bindingIDs, routeIDs map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				switch key {
				case "bindingRecordId":
					bindingIDs[text] = struct{}{}
				case "witnessRouteId":
					routeIDs[text] = struct{}{}
				}
			}
			collectCompactIdentityValues(child, bindingIDs, routeIDs)
		}
	case []any:
		for _, child := range typed {
			collectCompactIdentityValues(child, bindingIDs, routeIDs)
		}
	}
}

func assertCompactIdentityObservation(t *testing.T, value any, want map[string]any, context string) {
	t.Helper()
	got := compactCoverageIdentityObservation(t, value)
	if !compactJSONEqual(got, want) {
		t.Fatalf("%s identity projection=%v want %v", context, got, want)
	}
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func closeCompactObservationServer(t *testing.T, handle requirementbrowser.ServerHandle) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := handle.Close(ctx); err != nil {
		t.Fatalf("close compact context workspace server: %v", err)
	}
	select {
	case err := <-handle.Done():
		if err != nil {
			t.Fatalf("wait for compact context workspace server: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for compact context workspace server: %v", ctx.Err())
	}
}

func compactWireValueDigest(t *testing.T, value any) string {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode compact nested wire value: %v", err)
	}
	return sha256Text(string(content))
}

func currentCompactParentContractObservations(t *testing.T) map[string]any {
	t.Helper()
	contract := readCLIContract(t)
	commands := make(map[string]cliContractCommand, len(contract.Commands))
	for _, command := range contract.Commands {
		commands[command.Command] = command
	}
	result := map[string]any{}
	for _, key := range expectedCompactWireObservationKeys {
		parts := strings.Split(key, "|")
		if len(parts) != 3 || parts[2] != "union" {
			continue
		}
		command, ok := commands[parts[0]]
		if !ok {
			t.Fatalf("expected parent observation references unknown command %s", parts[0])
		}
		raw := command.InputContract
		if parts[1] == "output" {
			raw = command.OutputContract
		}
		if raw == nil {
			t.Fatalf("expected parent observation %s has no contract", key)
		}
		content, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("encode expected parent observation %s: %v", key, err)
		}
		value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatalf("admit expected parent observation %s: %v", key, err)
		}
		record := value.(map[string]any)
		result[key] = map[string]any{"contract": record}
	}
	return result
}

func compactV2WireContract() map[string]any {
	return map[string]any{
		"schema_version":        json.Number("2"),
		"authority_state":       "caller_owned_declaration",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_route_declaration",
		"normalization_profile": "proofkit.compact.declaration.v2",
		"non_claims":            []any{"Compact test input does not execute witnesses."},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.surface", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"},
		"bindings": []any{[]any{
			"REQ-PROOFKIT-COMPACT-001",
			"proofkit.surface",
			"proofkit.surface::scenario.compact",
			"contract",
			"proofkit.compact",
			"blocking",
			[]any{"local-go"},
			[]any{"tests/proofkit_positive_test.go::TestAcceptsCompactContract", []any{"local-go"}, []any{"go test ./..."}, json.Number("0")},
			[]any{"tests/proofkit_falsification_test.go::TestRejectsCompactRegression", []any{"local-go"}, []any{"go test ./..."}, json.Number("1")},
			[]any{"go test ./..."},
			"no_known_advisory_gap",
		}},
	}
}

func strictJSONObjectFromText(t *testing.T, text, context string) map[string]any {
	t.Helper()
	value, err := admission.DecodeJSON(strings.NewReader(text), int64(len(text)))
	if err != nil {
		t.Fatalf("decode %s: %v", context, err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s must be an object", context)
	}
	return record
}

func compactSourceRoleObservation(t *testing.T, sourceSet map[string]any) map[string]any {
	t.Helper()
	columns := sourceSet["source_columns"].([]any)
	rows := sourceSet["sources"].([]any)
	if len(rows) == 0 {
		t.Fatal("current source set has no source rows")
	}
	row := rows[0].([]any)
	for index, raw := range columns {
		if raw == "role" {
			return map[string]any{"role": row[index]}
		}
	}
	t.Fatal("current source set has no role column")
	return nil
}

func firstCompactCoverageScenario(t *testing.T, report map[string]any) map[string]any {
	t.Helper()
	requirements := report["requirementCoverage"].([]any)
	if len(requirements) == 0 {
		t.Fatal("current compact coverage report has no requirements")
	}
	scenarios := requirements[0].(map[string]any)["scenarios"].([]any)
	if len(scenarios) == 0 {
		t.Fatal("current compact coverage report has no scenarios")
	}
	return scenarios[0].(map[string]any)
}

func assertCompactObservedState(t *testing.T, delta compactWireDelta, side string, document any, want compactWireState) {
	t.Helper()
	actual, exists := selectCompactWirePointer(t, document, delta.JSONPointer, want.Presence == "absent")
	if want.Presence == "absent" {
		if exists {
			t.Fatalf("wire delta %s %s pointer %s is present with value %#v", delta.DeltaID, side, delta.JSONPointer, actual)
		}
		return
	}
	if !exists {
		t.Fatalf("wire delta %s %s pointer %s is absent", delta.DeltaID, side, delta.JSONPointer)
	}
	encoded, err := stablejson.Marshal(actual)
	if err != nil {
		t.Fatalf("encode wire delta %s %s observed value: %v", delta.DeltaID, side, err)
	}
	if want.ValueSHA256 != "" {
		actualDigest := sha256Text(string(encoded))
		if actualDigest != want.ValueSHA256 {
			t.Fatalf("wire delta %s %s value digest=%s want %s", delta.DeltaID, side, actualDigest, want.ValueSHA256)
		}
		return
	}
	wantValue, err := admission.DecodeJSON(bytes.NewReader(want.Value), int64(len(want.Value)))
	if err != nil {
		t.Fatalf("decode wire delta %s %s expected value: %v", delta.DeltaID, side, err)
	}
	wantEncoded, err := stablejson.Marshal(wantValue)
	if err != nil {
		t.Fatalf("encode wire delta %s %s expected value: %v", delta.DeltaID, side, err)
	}
	if !bytes.Equal(encoded, wantEncoded) {
		t.Fatalf("wire delta %s %s value=%s want %s", delta.DeltaID, side, encoded, wantEncoded)
	}
}

func assertCompactWireDeltaFrontierClosure(t *testing.T, deltas []compactWireDelta, oldObservations, currentObservations map[string]any) {
	t.Helper()
	frontiers := make(map[string]map[string]string)
	allUncovered := []string{}
	allUnused := []string{}
	for _, delta := range deltas {
		key := compactWireObservationKey(delta.Surface, delta.Direction, delta.Variant)
		if frontiers[key] == nil {
			frontiers[key] = map[string]string{}
		}
		if prior, duplicate := frontiers[key][delta.JSONPointer]; duplicate {
			t.Fatalf("wire deltas %s and %s declare the same frontier %s for %s", prior, delta.DeltaID, delta.JSONPointer, key)
		}
		frontiers[key][delta.JSONPointer] = delta.DeltaID
	}
	for _, key := range expectedCompactWireObservationKeys {
		observationFrontiers := frontiers[key]
		pointers := sortedSetKeys(observationFrontiers)
		for left := 0; left < len(pointers); left++ {
			for right := left + 1; right < len(pointers); right++ {
				if compactPointerContains(pointers[left], pointers[right]) || compactPointerContains(pointers[right], pointers[left]) {
					t.Fatalf("wire observation %s has overlapping delta frontiers %s and %s", key, pointers[left], pointers[right])
				}
			}
		}
		used := map[string]struct{}{}
		uncovered := []string{}
		collectUncoveredCompactWireDiffs(oldObservations[key], true, currentObservations[key], true, "", observationFrontiers, used, &uncovered)
		sort.Strings(uncovered)
		for _, pointer := range uncovered {
			allUncovered = append(allUncovered, key+pointer)
		}
		if unused := compactStringDifference(pointers, sortedSetKeys(used)); len(unused) != 0 {
			for _, pointer := range unused {
				allUnused = append(allUnused, key+pointer)
			}
		}
	}
	if len(allUncovered) != 0 || len(allUnused) != 0 {
		t.Fatalf("wire delta frontier is not exact: undeclared=%v unchanged_or_unreachable=%v", allUncovered, allUnused)
	}
}

func collectUncoveredCompactWireDiffs(oldValue any, oldPresent bool, currentValue any, currentPresent bool, pointer string, frontiers map[string]string, used map[string]struct{}, uncovered *[]string) {
	if oldPresent == currentPresent && (!oldPresent || compactJSONEqual(oldValue, currentValue)) {
		return
	}
	if _, covered := frontiers[pointer]; covered {
		used[pointer] = struct{}{}
		return
	}
	if !oldPresent || !currentPresent {
		*uncovered = append(*uncovered, compactDisplayPointer(pointer))
		return
	}
	oldRecord, oldObject := oldValue.(map[string]any)
	currentRecord, currentObject := currentValue.(map[string]any)
	if oldObject && currentObject {
		keys := make(map[string]struct{}, len(oldRecord)+len(currentRecord))
		for key := range oldRecord {
			keys[key] = struct{}{}
		}
		for key := range currentRecord {
			keys[key] = struct{}{}
		}
		for _, key := range sortedSetKeys(keys) {
			oldChild, oldOK := oldRecord[key]
			currentChild, currentOK := currentRecord[key]
			collectUncoveredCompactWireDiffs(oldChild, oldOK, currentChild, currentOK, pointer+"/"+escapeCompactPointerToken(key), frontiers, used, uncovered)
		}
		return
	}
	oldArray, oldIsArray := oldValue.([]any)
	currentArray, currentIsArray := currentValue.([]any)
	if oldIsArray && currentIsArray && len(oldArray) == len(currentArray) {
		for index := range oldArray {
			collectUncoveredCompactWireDiffs(oldArray[index], true, currentArray[index], true, pointer+"/"+fmt.Sprint(index), frontiers, used, uncovered)
		}
		return
	}
	*uncovered = append(*uncovered, compactDisplayPointer(pointer))
}

func compactJSONEqual(left, right any) bool {
	leftBytes, leftErr := stablejson.Marshal(left)
	rightBytes, rightErr := stablejson.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func compactPointerContains(parent, child string) bool {
	return strings.HasPrefix(child, parent+"/")
}

func escapeCompactPointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func compactDisplayPointer(pointer string) string {
	if pointer == "" {
		return "/"
	}
	return pointer
}

func compactStringDifference(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, value := range right {
		rightSet[value] = struct{}{}
	}
	result := []string{}
	for _, value := range left {
		if _, ok := rightSet[value]; !ok {
			result = append(result, value)
		}
	}
	return result
}

func selectCompactWirePointer(t *testing.T, document any, pointer string, allowAbsent bool) (any, bool) {
	t.Helper()
	value, err := jsonpointer.Select(document, pointer)
	if err == nil {
		return value, true
	}
	if !allowAbsent {
		t.Fatalf("resolve wire pointer %s: %v", pointer, err)
	}
	separator := strings.LastIndex(pointer, "/")
	if separator < 0 {
		t.Fatalf("wire pointer %s has no parent", pointer)
	}
	parentPointer := pointer[:separator]
	key := pointer[separator+1:]
	parent, parentErr := jsonpointer.Select(document, parentPointer)
	if parentErr != nil {
		t.Fatalf("wire pointer %s has unresolved parent %s: %v", pointer, parentPointer, parentErr)
	}
	record, ok := parent.(map[string]any)
	if !ok {
		t.Fatalf("wire pointer %s absent check parent=%T want object", pointer, parent)
	}
	if _, present := record[key]; present {
		t.Fatalf("wire pointer %s resolver failed despite present key", pointer)
	}
	return nil, false
}

func compactWireObservationKey(surface, direction, variant string) string {
	return strings.Join([]string{surface, direction, variant}, "|")
}
