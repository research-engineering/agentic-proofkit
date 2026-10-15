package requirementsourceconversion

import (
	"encoding/json"
	"strings"
	"testing"
)

// Format identity is the admitted kind and schemaVersion pair. The retired
// flat v1 source is recognized only to refuse it; no v1 reader exists.
func TestFormatIdentityRefusals(t *testing.T) {
	cases := []conversionCase{
		{name: "legacy v1 export", export: true, code: "legacy_source_unsupported", pointer: "/schemaVersion", grouped: func(t *testing.T, grouped map[string]any) {
			replaceAll(grouped, fixture(t, "legacy.v1.json"))
		}},
		{name: "legacy v1 import", code: "legacy_source_unsupported", pointer: "/schemaVersion", flat: func(t *testing.T, flat map[string]any) {
			replaceAll(flat, fixture(t, "legacy.v1.json"))
		}},
		{name: "flat to flat", export: true, code: "same_format", pointer: "/kind", grouped: func(t *testing.T, grouped map[string]any) {
			replaceAll(grouped, fixture(t, "source.flat.json"))
		}},
		{name: "grouped to grouped", code: "same_format", pointer: "/kind", flat: func(t *testing.T, flat map[string]any) {
			replaceAll(flat, fixture(t, "source.grouped.json"))
		}},
		{name: "future grouped version", export: true, code: "unsupported_source_format", grouped: func(t *testing.T, grouped map[string]any) {
			grouped["schemaVersion"] = jsonNumber(3)
		}},
		{name: "future flat version", code: "unsupported_source_format", flat: func(t *testing.T, flat map[string]any) {
			flat["schemaVersion"] = jsonNumber(2)
		}},
		{name: "textual version", export: true, code: "unsupported_source_format", grouped: func(t *testing.T, grouped map[string]any) {
			grouped["schemaVersion"] = "2"
		}},
		{name: "unknown kind", code: "unsupported_source_format", flat: func(t *testing.T, flat map[string]any) {
			flat["kind"] = "proofkit.requirement-source-table"
		}},
		{name: "kind with legacy version", export: true, code: "unsupported_source_format", grouped: func(t *testing.T, grouped map[string]any) {
			grouped["schemaVersion"] = jsonNumber(1)
		}},
	}
	for _, item := range cases {
		if problem := conversionCaseProblem(t, item); problem != "" {
			t.Fatal(problem)
		}
	}
	for _, input := range []any{nil, "grouped", json.Number("2"), []any{}} {
		if failure := refusalOf(t, func() error { _, err := ExportFlat(input); return err }()); failure.Code != "unsupported_source_format" || failure.Pointer != "" {
			t.Fatalf("non-object export input refusal = %#v", failure)
		}
		if failure := refusalOf(t, func() error { _, err := ImportFlat(fixture(t, "source.flat.json"), input); return err }()); failure.Document != documentBaseline || failure.Code != "unsupported_source_format" {
			t.Fatalf("non-object baseline refusal = %#v", failure)
		}
	}
}

// Coordinates must close exactly over the flat records before any value is
// interpreted; ambiguity is refused rather than resolved by position or value.
func TestFlatCoordinateRefusals(t *testing.T) {
	cases := []conversionCase{
		{name: "duplicate requirement record", code: "duplicate_requirement_row", pointer: "/requirements/6/requirementId", flat: func(t *testing.T, flat map[string]any) {
			flat["requirements"] = append(flat["requirements"].([]any), clone(t, at(t, flat, "/requirements/0")))
		}},
		{name: "duplicate profile coordinate", code: "duplicate_profile_coordinate", pointer: "/profiles/2/profileId", flat: func(t *testing.T, flat map[string]any) {
			flat["profiles"] = append(flat["profiles"].([]any), clone(t, at(t, flat, "/profiles/0")))
		}},
		{name: "duplicate profile field", code: "duplicate_profile_field", pointer: "/profiles/0/fieldIds/1", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/profiles/0/fieldIds", values("claimLevel", "claimLevel", "ownerId", "riskClass", "updatePolicy"))
		}},
		{name: "unknown profile coordinate", code: "unknown_profile_coordinate", pointer: "/groups/0/profileId", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/0/profileId", "RPROF-CONV-MISSING")
		}},
		{name: "unknown requirement coordinate", code: "unknown_requirement_coordinate", pointer: "/groups/0/requirementIds/0", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/0/requirementIds", values("REQ-CONV-999"))
		}},
		{name: "requirement claimed twice", code: "duplicate_requirement_coordinate", pointer: "/groups/2/requirementIds/1", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/2/requirementIds", values("REQ-CONV-004", "REQ-CONV-003"))
		}},
		{name: "unassigned requirement record", code: "unassigned_requirement_row", pointer: "/requirements/2", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/0/requirementIds", values())
		}},
		{name: "profile without observing members", code: "unobserved_profile_coordinate", pointer: "/profiles/2", flat: func(t *testing.T, flat map[string]any) {
			flat["profiles"] = append(flat["profiles"].([]any), map[string]any{"profileId": "RPROF-CONV-SPARE", "fieldIds": values("riskClass")})
		}},
		{name: "stem bytes inside a word", code: "invalid_statement_stem_bytes", pointer: "/requirements/0/invariant", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/1/statementStemBytes", jsonNumber(15))
		}},
		{name: "stem bytes beyond the statement", code: "invalid_statement_stem_bytes", pointer: "/requirements/0/invariant", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/1/statementStemBytes", jsonNumber(1000))
		}},
		{name: "stem bytes inside a UTF-8 sequence", code: "invalid_statement_stem_bytes", pointer: "/requirements/4/invariant", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/3/statementStemBytes", jsonNumber(8))
		}},
		{name: "empty completion after the stem", code: "invalid_text", pointer: "/requirements/0/invariant", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/0/invariant", "The service must ")
		}},
	}
	for _, item := range cases {
		if problem := conversionCaseProblem(t, item); problem != "" {
			t.Fatal(problem)
		}
	}
}

// Structural admission distinguishes absent, null and empty values and admits
// no unknown field; it owns no semantic rule.
func TestFlatStructureRefusals(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(t *testing.T, flat map[string]any)
		detail string
	}{
		{"unknown root field", func(t *testing.T, flat map[string]any) { flat["groupedLayout"] = values() }, "contains an unsupported field"},
		{"unknown record field", func(t *testing.T, flat map[string]any) { set(t, flat, "/requirements/0/groupId", "RGRP-CONV-REQUESTS") }, "flat document.requirements[0] contains an unsupported field"},
		{"absent deferral", func(t *testing.T, flat map[string]any) { remove(t, flat, "/requirements/0/fields/deferral") }, "flat document.requirements[0].fields.deferral is required"},
		{"absent empty section", func(t *testing.T, flat map[string]any) { remove(t, flat, "/vocabulary") }, "flat document.vocabulary is required"},
		{"null premises", func(t *testing.T, flat map[string]any) { set(t, flat, "/requirements/2/sharedPremises", nil) }, "flat document.requirements[2].sharedPremises must be an array"},
		{"null coordinates", func(t *testing.T, flat map[string]any) { set(t, flat, "/groups/0/requirementIds", nil) }, "flat document.groups[0].requirementIds must be an array"},
		{"textual stem bytes", func(t *testing.T, flat map[string]any) { set(t, flat, "/groups/1/statementStemBytes", "16") }, "flat document.groups[1].statementStemBytes must be a decimal int64 integer token"},
		{"negative stem bytes", func(t *testing.T, flat map[string]any) { set(t, flat, "/groups/1/statementStemBytes", jsonNumber(-1)) }, "flat document.groups[1].statementStemBytes must be a decimal int64 integer between"},
		{"unknown profile field", func(t *testing.T, flat map[string]any) { set(t, flat, "/profiles/0/fieldIds", values("severity")) }, "flat document.profiles[0].fieldIds[0] must be a declared enum value"},
		{"uppercase basis digest", func(t *testing.T, flat map[string]any) {
			flat["basisDigest"] = "sha256:" + strings.Repeat("A", 64)
		}, "flat document.basisDigest must match the declared text grammar"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			flat := fixture(t, "source.flat.json")
			item.edit(t, flat)
			_, err := ImportFlat(flat, fixture(t, "source.grouped.json"))
			failure := refusalOf(t, err)
			if failure.Code != "invalid_flat_structure" || failure.Pointer != "" || !strings.Contains(failure.Detail, item.detail) {
				t.Fatalf("refusal = %v", err)
			}
		})
	}
	// Explicit empty arrays and explicit null deferral are admitted values.
	flat := fixture(t, "source.flat.json")
	if _, err := ImportFlat(flat, fixture(t, "source.grouped.json")); err != nil {
		t.Fatal(err)
	}
}

// Semantic refusals come from the grouped codec and model unchanged; only
// their coordinates are translated to the flat record that states the value.
func TestModelRefusalsUseFlatCoordinates(t *testing.T) {
	cases := []conversionCase{
		{name: "member-owned invalid identifier", code: "invalid_id", pointer: "/requirements/2/fields/ownerId", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/2/fields/ownerId", "not an identifier")
		}},
		{name: "profile-owned invalid variant", code: "invalid_claim_level", pointer: "/requirements/0/fields/claimLevel", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/0/fields/claimLevel", "mandatory")
			set(t, flat, "/requirements/1/fields/claimLevel", "mandatory")
		}},
		{name: "duplicate shared premise", code: "duplicate_value", pointer: "/requirements/4/sharedPremises", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/4/sharedPremises", values("Le journal est disponible.", "Le journal est disponible."))
			set(t, flat, "/requirements/5/sharedPremises", values("Le journal est disponible.", "Le journal est disponible."))
		}},
		{name: "empty profile", code: "empty_profile", pointer: "/profiles/1/fieldIds", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/profiles/1/fieldIds", values())
		}},
		{name: "invalid group identifier", code: "invalid_id", pointer: "/groups/0/groupId", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/0/groupId", "GROUP-CONV-DEFERRED")
		}},
		{name: "dangling scenario requirement", code: "dangling_requirement_ref", pointer: "/scenarios/0/requirementIds", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/scenarios/0/requirementIds", values("REQ-CONV-404"))
		}},
		{name: "source policy violation", code: "missing_proof_binding", pointer: "/requirements/0", detail: "2 source policy violation(s)", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/0/fields/proofBindingRefs", values())
			set(t, flat, "/requirements/1/fields/proofBindingRefs", values())
		}},
		{name: "grouped member invalid identifier", export: true, code: "invalid_id", pointer: "/groups/0/members/0/fields/ownerId", grouped: func(t *testing.T, grouped map[string]any) {
			set(t, grouped, "/groups/0/members/0/fields/ownerId", "not an identifier")
		}},
		{name: "grouped source policy violation", export: true, code: "missing_proof_binding", pointer: "/groups/1/members/1", detail: "1 source policy violation(s)", grouped: func(t *testing.T, grouped map[string]any) {
			set(t, grouped, "/groups/1/members/1/fields/proofBindingRefs", values())
		}},
		{name: "grouped unknown field", export: true, code: "unknown_field", pointer: "/groups/0/<unknown>", grouped: func(t *testing.T, grouped map[string]any) {
			remove(t, grouped, "/groups/0/statementStem")
			set(t, grouped, "/groups/0/layoutHint", "flat")
		}},
		{name: "grouped surplus field", export: true, code: "collection_limit_exceeded", pointer: "/groups/0", grouped: func(t *testing.T, grouped map[string]any) {
			set(t, grouped, "/groups/0/layoutHint", "flat")
		}},
	}
	for _, item := range cases {
		if problem := conversionCaseProblem(t, item); problem != "" {
			t.Fatal(problem)
		}
	}
}

// Refusals are deterministic and never echo caller-authored keys or values.
func TestRefusalsAreBoundedAndDeterministic(t *testing.T) {
	const marker = "CallerMarkerValue"
	edits := []func(t *testing.T, flat map[string]any){
		func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/2/fields/ownerId", marker+" text")
		},
		func(t *testing.T, flat map[string]any) { set(t, flat, "/requirements/0/"+marker, marker) },
		func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/0/requirementIds", values("REQ-"+marker))
		},
		func(t *testing.T, flat map[string]any) {
			set(t, flat, "/scenarios/0/examples/0/values/"+marker, marker)
		},
	}
	for index, edit := range edits {
		messages := map[string]struct{}{}
		for attempt := 0; attempt < 3; attempt++ {
			flat := fixture(t, "source.flat.json")
			edit(t, flat)
			_, err := ImportFlat(flat, fixture(t, "source.grouped.json"))
			if err == nil {
				t.Fatalf("edit %d was admitted", index)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("edit %d refusal echoes caller text: %v", index, err)
			}
			messages[err.Error()] = struct{}{}
		}
		if len(messages) != 1 {
			t.Fatalf("edit %d refusal is not deterministic: %v", index, messages)
		}
	}
}

func replaceAll(target map[string]any, source map[string]any) {
	for key := range target {
		delete(target, key)
	}
	for key, value := range source {
		target[key] = value
	}
}
