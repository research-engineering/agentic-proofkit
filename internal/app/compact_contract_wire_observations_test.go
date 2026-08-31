package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	compactV1WireObservationsPath = "internal/app/testdata/compact-v1-wire-observations.json"
	compactV2WireObservationsPath = "internal/app/testdata/compact-v2-wire-observations.json"
)

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

func TestCompactV2WireDeltasResolveAgainstFrozenVersionEdgeObservations(t *testing.T) {
	manifest := readCompactWireManifest(t)
	oldObservations := readCompactV1WireObservations(t)
	currentObservations := readCompactV2WireObservations(t)
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
	return compactWireObservationMap(t, readCompactV1WireObservationDocument(t), "compact v1")
}

func readCompactV2WireObservations(t *testing.T) map[string]any {
	t.Helper()
	return compactWireObservationMap(t, readCompactV2WireObservationDocument(t), "compact v2")
}

func compactWireObservationMap(t *testing.T, decoded compactWireObservations, context string) map[string]any {
	t.Helper()
	result := make(map[string]any, len(decoded.Observations))
	previous := ""
	for _, observation := range decoded.Observations {
		key := compactWireObservationKey(observation.Surface, observation.Direction, observation.Variant)
		if previous != "" && previous >= key {
			t.Fatalf("%s wire observations must be sorted and unique: %s before %s", context, previous, key)
		}
		previous = key
		result[key] = observation.Document
	}
	return result
}

func readCompactV1WireObservationDocument(t *testing.T) compactWireObservations {
	t.Helper()
	return readCompactWireObservationDocument(t, compactV1WireObservationsPath, 1, "compact v1")
}

func readCompactV2WireObservationDocument(t *testing.T) compactWireObservations {
	t.Helper()
	return readCompactWireObservationDocument(t, compactV2WireObservationsPath, 2, "compact v2")
}

func readCompactWireObservationDocument(t *testing.T, relativePath string, schemaVersion int, context string) compactWireObservations {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), relativePath))
	if err != nil {
		t.Fatalf("read %s wire observations: %v", context, err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("admit %s wire observations: %v", context, err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s wire observations must be an object", context)
	}
	assertExactObjectKeys(t, record, []string{"cliContractDirectionDigests", "observations", "schemaVersion"}, context+" wire observations")
	if number, ok := record["schemaVersion"].(json.Number); !ok || number.String() != strconv.Itoa(schemaVersion) {
		t.Fatalf("%s wire observations schemaVersion=%v want %d", context, record["schemaVersion"], schemaVersion)
	}
	raw, ok := record["observations"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("%s wire observations must contain observations", context)
	}
	for index, value := range raw {
		observation, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%s wire observation %d must be an object", context, index)
		}
		assertExactObjectKeys(t, observation, []string{"direction", "document", "surface", "variant"}, fmt.Sprintf("%s wire observation %d", context, index))
	}
	decoded, err := admission.DecodeTypedJSON[compactWireObservations](bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("decode %s wire observations: %v", context, err)
	}
	if len(decoded.CLIContractDirectionDigests) == 0 {
		t.Fatalf("%s wire observations must contain CLI contract direction digests", context)
	}
	for key, value := range decoded.CLIContractDirectionDigests {
		parts := strings.Split(key, "|")
		if len(parts) != 2 || (parts[1] != "input" && parts[1] != "output") || !validSHA256Digest(value) {
			t.Fatalf("%s CLI contract direction digest %s=%q is invalid", context, key, value)
		}
	}
	return decoded
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
