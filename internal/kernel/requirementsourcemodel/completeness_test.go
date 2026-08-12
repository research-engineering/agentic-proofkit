package requirementsourcemodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

type completenessManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	Kind          string            `json:"kind"`
	Projections   []string          `json:"projections"`
	Fields        []manifestField   `json:"fields"`
	Variants      []manifestVariant `json:"variants"`
	NonClaims     []string          `json:"nonClaims"`
}

type manifestField struct {
	FieldID             string   `json:"fieldId"`
	RequiredProjections []string `json:"requiredProjections"`
}

type manifestVariant struct {
	VariantID           string   `json:"variantId"`
	Values              []string `json:"values"`
	RequiredProjections []string `json:"requiredProjections"`
}

type mutantCorpus struct {
	SchemaVersion int            `json:"schemaVersion"`
	Kind          string         `json:"kind"`
	Mutants       []mutantRecord `json:"mutants"`
	NonClaims     []string       `json:"nonClaims"`
}

type mutantRecord struct {
	MutantID           string   `json:"mutantId"`
	MutatedFields      []string `json:"mutatedFields"`
	ProvenFields       []string `json:"provenFields"`
	RelationIDs        []string `json:"relationIds"`
	ChangedProjections []string `json:"changedProjections"`
}

func TestIndependentManifestClosesEveryFieldThroughRealMutants(t *testing.T) {
	manifest := readStrictJSON[completenessManifest](t, "testdata/field-projection-manifest.v1.json")
	corpus := readStrictJSON[mutantCorpus](t, "testdata/model-mutants.v1.json")
	if manifest.SchemaVersion != 1 || manifest.Kind != "proofkit.requirement-source-model-field-projection-manifest" {
		t.Fatal("unexpected completeness manifest identity")
	}
	if corpus.SchemaVersion != 1 || corpus.Kind != "proofkit.requirement-source-model-mutant-corpus" {
		t.Fatal("unexpected mutant corpus identity")
	}
	if !reflect.DeepEqual(manifest.Projections, []string{"atomic", "layout", "references"}) {
		t.Fatalf("projection inventory = %#v", manifest.Projections)
	}

	fields := map[string][]string{}
	for _, field := range manifest.Fields {
		if field.FieldID == "" || len(field.RequiredProjections) == 0 {
			t.Fatalf("invalid field row %#v", field)
		}
		if _, exists := fields[field.FieldID]; exists {
			t.Fatalf("duplicate field %q", field.FieldID)
		}
		assertProjectionSet(t, field.RequiredProjections)
		fields[field.FieldID] = field.RequiredProjections
	}

	baseline, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]map[string]struct{}{}
	seenMutants := map[string]struct{}{}
	seenRelations := map[string]struct{}{}
	for _, mutant := range corpus.Mutants {
		if _, exists := seenMutants[mutant.MutantID]; exists {
			t.Fatalf("duplicate mutant %q", mutant.MutantID)
		}
		seenMutants[mutant.MutantID] = struct{}{}
		assertSortedUniqueStrings(t, mutant.MutatedFields, mutant.MutantID+" mutatedFields")
		assertSortedUniqueStrings(t, mutant.ProvenFields, mutant.MutantID+" provenFields")
		assertSortedUniqueStrings(t, mutant.RelationIDs, mutant.MutantID+" relationIds")
		assertProjectionSet(t, mutant.ChangedProjections)
		if len(mutant.ProvenFields) != 0 {
			if len(mutant.MutatedFields) != 1 || len(mutant.ProvenFields) != 1 || mutant.MutatedFields[0] != mutant.ProvenFields[0] || len(mutant.RelationIDs) != 0 {
				t.Fatalf("mutant %q attributes independent causality to a correlated edit", mutant.MutantID)
			}
		} else if len(mutant.RelationIDs) == 0 {
			t.Fatalf("mutant %q proves neither a field nor a relation", mutant.MutantID)
		}
		for _, relationID := range mutant.RelationIDs {
			if _, exists := seenRelations[relationID]; exists {
				t.Fatalf("duplicate relation %q", relationID)
			}
			seenRelations[relationID] = struct{}{}
		}
		draft := validDraft()
		if !applyMutant(mutant.MutantID, &draft) {
			t.Fatalf("mutant %q has no independently implemented edit", mutant.MutantID)
		}
		changed, err := Normalize(draft)
		if err != nil {
			t.Fatalf("mutant %q is not an admitted semantic mutation: %v", mutant.MutantID, err)
		}
		actual := changedProjectionIDs(baseline, changed)
		if !reflect.DeepEqual(actual, mutant.ChangedProjections) {
			t.Fatalf("mutant %q changed projections %v, want %v", mutant.MutantID, actual, mutant.ChangedProjections)
		}
		baselineDraft := validDraft()
		actualMutatedFields := changedDraftFieldIDs(baselineDraft, draft, fields)
		if !reflect.DeepEqual(actualMutatedFields, mutant.MutatedFields) {
			t.Fatalf("mutant %q changed input fields %v, declared %v", mutant.MutantID, actualMutatedFields, mutant.MutatedFields)
		}
		if err := validateMutantRelations(mutant, baselineDraft, draft); err != nil {
			t.Fatalf("mutant %q relation proof failed: %v", mutant.MutantID, err)
		}
		proven := map[string]struct{}{}
		for _, fieldID := range mutant.ProvenFields {
			proven[fieldID] = struct{}{}
		}
		for _, fieldID := range mutant.MutatedFields {
			required, exists := fields[fieldID]
			if !exists {
				t.Fatalf("mutant %q covers unknown field %q", mutant.MutantID, fieldID)
			}
			observed := false
			for _, projection := range required {
				if !contains(mutant.ChangedProjections, projection) {
					continue
				}
				baselineObservation, handled := observeManifestField(baseline, fieldID, projection)
				if !handled {
					t.Fatalf("field %q has no independent %q observer", fieldID, projection)
				}
				changedObservation, handled := observeManifestField(changed, fieldID, projection)
				if !handled || reflect.DeepEqual(baselineObservation, changedObservation) {
					t.Fatalf("mutant %q did not change field-specific %s observation for %s", mutant.MutantID, projection, fieldID)
				}
				observed = true
				if _, independentlyProven := proven[fieldID]; independentlyProven || len(mutant.RelationIDs) != 0 {
					if covered[fieldID] == nil {
						covered[fieldID] = map[string]struct{}{}
					}
					covered[fieldID][projection] = struct{}{}
				}
			}
			if !observed {
				t.Fatalf("mutant %q has no field-specific changed observation for %s", mutant.MutantID, fieldID)
			}
		}
	}
	for fieldID, projections := range fields {
		for _, projection := range projections {
			if _, exists := covered[fieldID][projection]; !exists {
				t.Fatalf("field %q lacks a real mutant reaching %q", fieldID, projection)
			}
		}
	}
	if len(seenMutants) != len(mutantImplementations()) {
		t.Fatalf("mutant corpus has %d rows, implementation registry has %d", len(seenMutants), len(mutantImplementations()))
	}
	if len(seenRelations) != len(mutantRelationRegistry()) {
		t.Fatalf("mutant corpus uses %d relations, registry has %d", len(seenRelations), len(mutantRelationRegistry()))
	}
}

func assertSortedUniqueStrings(t *testing.T, values []string, label string) {
	t.Helper()
	if len(values) == 0 {
		return
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(values, sorted) {
		t.Fatalf("%s is not sorted: %v", label, values)
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			t.Fatalf("%s contains duplicate %q", label, values[index])
		}
	}
}

func TestIndependentManifestClosesEnumAndPresenceVariants(t *testing.T) {
	manifest := readStrictJSON[completenessManifest](t, "testdata/field-projection-manifest.v1.json")
	type expectedVariant struct {
		values      []string
		projections []string
	}
	expected := map[string]expectedVariant{
		"claimLevel":     {values: []string{"advisory", "blocking", "deferred"}, projections: []string{"atomic", "layout"}},
		"riskClass":      {values: []string{"critical", "high", "low", "medium"}, projections: []string{"atomic", "layout"}},
		"lifecycleState": {values: []string{"active", "deprecated", "removed", "superseded"}, projections: []string{"atomic", "layout"}},
		"termKind":       {values: []string{"action", "observable", "state", "subject", "value"}, projections: []string{"atomic"}},
		"sourceKind":     {values: []string{"clarification", "code_snapshot", "design", "owner_decision", "plan"}, projections: []string{"references"}},
		"objectFormat":   {values: []string{"sha1", "sha256"}, projections: []string{"references"}},
		"entityKind":     {values: []string{"derivation", "group", "nonclaim", "profile", "requirement", "scenario", "source", "term"}, projections: []string{"references"}},
		"referenceKind":  {values: []string{"derivation_nonclaim", "derivation_requirement", "group_member", "group_profile", "lifecycle_replacement", "requirement_nonclaim", "scenario_nonclaim", "scenario_requirement", "scenario_vocabulary", "source_nonclaim"}, projections: []string{"references"}},
		"metadataOwner":  {values: []string{"member", "profile"}, projections: []string{"layout"}},
		"deferral":       {values: []string{"explicit_null", "record"}, projections: []string{"atomic", "layout"}},
		"profileRef":     {values: []string{"absent", "present"}, projections: []string{"layout", "references"}},
		"scenarioValue":  {values: []string{"string"}, projections: []string{"atomic"}},
	}
	actual := map[string]expectedVariant{}
	for _, variant := range manifest.Variants {
		if _, exists := actual[variant.VariantID]; exists {
			t.Fatalf("duplicate variant %q", variant.VariantID)
		}
		assertProjectionSet(t, variant.RequiredProjections)
		actual[variant.VariantID] = expectedVariant{variant.Values, variant.RequiredProjections}
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("variant manifest = %#v, want %#v", actual, expected)
	}
}

func readStrictJSON[T any](t *testing.T, path string) T {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := decodeExactTestJSON[T](source)
	if err != nil {
		t.Fatalf("strict typed JSON admission failed for %s: %v", path, err)
	}
	return result
}

func decodeExactTestJSON[T any](source []byte) (T, error) {
	result, err := admission.DecodeTypedJSON[T](bytes.NewReader(source), 1<<20)
	if err != nil {
		return result, err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	if err := validateExactCompletenessRecord(source, result); err != nil {
		return result, err
	}
	return result, nil
}

func validateExactCompletenessRecord[T any](source []byte, result T) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(source, &object); err != nil {
		return err
	}
	var requiredKeys []string
	var nonClaims []string
	switch value := any(result).(type) {
	case completenessManifest:
		requiredKeys = []string{"fields", "kind", "nonClaims", "projections", "schemaVersion", "variants"}
		nonClaims = value.NonClaims
	case mutantCorpus:
		requiredKeys = []string{"kind", "mutants", "nonClaims", "schemaVersion"}
		nonClaims = value.NonClaims
	default:
		return fmt.Errorf("unsupported completeness record type %T", result)
	}
	actualKeys := make([]string, 0, len(object))
	for key := range object {
		actualKeys = append(actualKeys, key)
	}
	sort.Strings(actualKeys)
	if !reflect.DeepEqual(actualKeys, requiredKeys) {
		return fmt.Errorf("top-level keys %v do not match %v", actualKeys, requiredKeys)
	}
	if len(nonClaims) == 0 {
		return fmt.Errorf("nonClaims must be a non-empty array")
	}
	for index, value := range nonClaims {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("nonClaims[%d] is not canonical text", index)
		}
		if index > 0 && nonClaims[index-1] >= value {
			return fmt.Errorf("nonClaims must be sorted and unique")
		}
	}
	return nil
}

func TestCompletenessRecordsUseExactStrictJSONAdmission(t *testing.T) {
	tests := []struct {
		name   string
		decode func() error
	}{
		{name: "case folded", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"SchemaVersion":1}`))
			return err
		}},
		{name: "duplicate", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"schemaVersion":1,"schemaVersion":1}`))
			return err
		}},
		{name: "trailing value", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"schemaVersion":1}{}`))
			return err
		}},
		{name: "unknown", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"schemaVersion":1,"unexpected":true}`))
			return err
		}},
		{name: "missing nonclaims", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"fields":[],"kind":"manifest","projections":[],"schemaVersion":1,"variants":[]}`))
			return err
		}},
		{name: "null nonclaims", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"fields":[],"kind":"manifest","nonClaims":null,"projections":[],"schemaVersion":1,"variants":[]}`))
			return err
		}},
		{name: "empty nonclaims", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"fields":[],"kind":"manifest","nonClaims":[],"projections":[],"schemaVersion":1,"variants":[]}`))
			return err
		}},
		{name: "unsorted nonclaims", decode: func() error {
			_, err := decodeExactTestJSON[completenessManifest]([]byte(`{"fields":[],"kind":"manifest","nonClaims":["Second.","First."],"projections":[],"schemaVersion":1,"variants":[]}`))
			return err
		}},
		{name: "mutant corpus missing nonclaims", decode: func() error {
			_, err := decodeExactTestJSON[mutantCorpus]([]byte(`{"kind":"corpus","mutants":[],"schemaVersion":1}`))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(); err == nil {
				t.Fatal("malformed completeness record was admitted")
			}
		})
	}
}

func assertProjectionSet(t *testing.T, values []string) {
	t.Helper()
	if len(values) == 0 {
		t.Fatal("projection set is empty")
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(values, sorted) {
		t.Fatalf("projection set is not sorted: %v", values)
	}
	for index, value := range values {
		if value != "atomic" && value != "layout" && value != "references" {
			t.Fatalf("unknown projection %q", value)
		}
		if index > 0 && values[index-1] == value {
			t.Fatalf("duplicate projection %q", value)
		}
	}
}

func changedProjectionIDs(left Model, right Model) []string {
	changed := []string{}
	if !reflect.DeepEqual(left.Atomic(), right.Atomic()) {
		changed = append(changed, "atomic")
	}
	if !reflect.DeepEqual(left.Layout(), right.Layout()) {
		changed = append(changed, "layout")
	}
	if !reflect.DeepEqual(left.References(), right.References()) {
		changed = append(changed, "references")
	}
	return changed
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
