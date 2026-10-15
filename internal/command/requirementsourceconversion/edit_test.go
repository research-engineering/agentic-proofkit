package requirementsourceconversion

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

// Flat rows (source.flat.json): 0 REQ-CONV-001, 1 REQ-CONV-002, 2 REQ-CONV-003,
// 3 REQ-CONV-004, 4 REQ-CONV-005, 5 REQ-CONV-006. Flat groups and grouped
// groups: 0 DEFERRED, 1 REQUESTS, 2 SUPERSEDED, 3 UNICODE. Profiles: 0
// BLOCKING, 1 EVIDENCE.

// Each permitted value edit is stated twice, independently: once on flat rows
// and once on the grouped owner that the import must change.
func TestImportAppliesValueEditsUnderBaselineOwnership(t *testing.T) {
	premises := func() []any {
		return values("Donn\u00e9es conserv\u00e9es.", "Le journal est disponible.", "Le stockage est chiffr\u00e9.")
	}
	flat := fixture(t, "source.flat.json")
	set(t, flat, "/requirements/0/invariant", "The service must accept well-formed requests.")
	set(t, flat, "/requirements/0/fields/riskClass", "critical")
	set(t, flat, "/requirements/1/fields/riskClass", "critical")
	set(t, flat, "/requirements/4/sharedPremises", premises())
	set(t, flat, "/requirements/5/sharedPremises", premises())
	set(t, flat, "/requirements/4/fields/riskClass", "medium")
	set(t, flat, "/requirements/2/fields/deferral/reviewCondition", "Review after the second conversion pilot.")
	set(t, flat, "/scenarios/0/expectedObservations", values("The request is accepted once."))
	set(t, flat, "/nonClaimDefinitions/2/statement", "Scenario examples are illustrative, not exhaustive proof.")

	expected := fixture(t, "source.grouped.json")
	set(t, expected, "/groups/1/members/0/statementCompletion", "accept well-formed requests.")
	set(t, expected, "/profiles/0/fields/riskClass", "critical")
	set(t, expected, "/groups/3/sharedPremises", premises())
	set(t, expected, "/groups/3/members/0/fields/riskClass", "medium")
	set(t, expected, "/groups/0/members/0/fields/deferral/reviewCondition", "Review after the second conversion pilot.")
	set(t, expected, "/scenarios/0/expectedObservations", values("The request is accepted once."))
	set(t, expected, "/nonClaimDefinitions/2/statement", "Scenario examples are illustrative, not exhaustive proof.")

	grouped, err := ImportFlat(flat, fixture(t, "source.grouped.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !sameModel(groupedModel(t, grouped), groupedModel(t, expected)) {
		t.Fatalf("edited import differs from the independently edited grouped source:\n got %s", canonicalJSON(t, grouped))
	}
}

// The baseline is identified by its admitted model, so caller order and
// formatting of an unchanged baseline are not staleness.
func TestReorderedBaselineIsNotStale(t *testing.T) {
	baseline := fixture(t, "source.grouped.json")
	slices.Reverse(at(t, baseline, "/groups").([]any))
	slices.Reverse(at(t, baseline, "/profiles").([]any))
	if _, err := ImportFlat(fixture(t, "source.flat.json"), baseline); err != nil {
		t.Fatal(err)
	}
}

type conversionCase struct {
	name     string
	export   bool
	flat     func(t *testing.T, flat map[string]any)
	grouped  func(t *testing.T, grouped map[string]any)
	baseline func(t *testing.T, baseline map[string]any) any
	document string
	code     string
	pointer  string
	detail   string
}

// conversionCaseProblem runs one refusal case and describes any difference
// from its expected document, code, pointer and detail.
func conversionCaseProblem(t *testing.T, item conversionCase) string {
	t.Helper()
	var err error
	if item.export {
		grouped := fixture(t, "source.grouped.json")
		if item.grouped != nil {
			item.grouped(t, grouped)
		}
		_, err = ExportFlat(grouped)
	} else {
		flat := fixture(t, "source.flat.json")
		if item.flat != nil {
			item.flat(t, flat)
		}
		var baseline any = fixture(t, "source.grouped.json")
		if item.baseline != nil {
			baseline = item.baseline(t, baseline.(map[string]any))
		}
		_, err = ImportFlat(flat, baseline)
	}
	if err == nil {
		return item.name + ": conversion was not refused"
	}
	var failure *Error
	if !errors.As(err, &failure) {
		return fmt.Sprintf("%s: untyped refusal %v", item.name, err)
	}
	document := item.document
	if document == "" {
		document = documentInput
	}
	if failure.Document != document || failure.Code != item.code || failure.Pointer != item.pointer {
		return fmt.Sprintf("%s: refusal = %s/%s at %q, want %s/%s at %q (%v)", item.name, failure.Document, failure.Code, failure.Pointer, document, item.code, item.pointer, err)
	}
	if item.detail != "" && !strings.Contains(failure.Detail, item.detail) {
		return fmt.Sprintf("%s: refusal detail %q does not contain %q", item.name, failure.Detail, item.detail)
	}
	return ""
}

// Every prohibited case is a same-shape near miss of a permitted edit: the
// flat document still admits structurally, but ownership, identity, freshness
// or member agreement changed, so no output exists.
func TestImportRefusesOwnershipChangesAndDisagreements(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.074292220989818234271972473598212701800131941516663907828360074544360181772640")
	cases := []conversionCase{
		{name: "divergent profile-owned edit", code: "profile_value_disagreement", pointer: "/requirements/1/fields/riskClass", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/0/fields/riskClass", "critical")
		}},
		{name: "shared premise drift", code: "shared_premises_disagreement", pointer: "/requirements/5/sharedPremises", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/4/sharedPremises", values("Donn\u00e9es conserv\u00e9es."))
		}},
		{name: "premise order is not agreement", code: "shared_premises_disagreement", pointer: "/requirements/5/sharedPremises", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/5/sharedPremises", values("Le journal est disponible.", "Donn\u00e9es conserv\u00e9es."))
		}},
		{name: "one member changes the stem", code: "statement_stem_disagreement", pointer: "/requirements/1/invariant", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/1/invariant", "The backend must reject malformed requests.")
		}},
		{name: "every member changes the stem", code: "statement_stem_changed", pointer: "/groups/1/statementStemBytes", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/requirements/0/invariant", "The backend must accept requests.")
			set(t, flat, "/requirements/1/invariant", "The backend must reject malformed requests.")
		}},
		{name: "shorter stem coordinate", code: "statement_stem_changed", pointer: "/groups/1/statementStemBytes", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/1/statementStemBytes", jsonNumber(3))
		}},
		{name: "removed stem coordinate", code: "statement_stem_changed", pointer: "/groups/1/statementStemBytes", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/1/statementStemBytes", jsonNumber(0))
		}},
		{name: "swapped membership", code: "group_membership_changed", pointer: "/groups/2/requirementIds/0", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/groups/0/requirementIds", values("REQ-CONV-004"))
			set(t, flat, "/groups/2/requirementIds", values("REQ-CONV-003"))
		}},
		{name: "renamed profile", code: "group_profile_changed", pointer: "/groups/3/profileId", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/profiles/1/profileId", "RPROF-CONV-RENAMED")
			set(t, flat, "/groups/3/profileId", "RPROF-CONV-RENAMED")
		}},
		{name: "narrowed profile fields", code: "profile_fields_changed", pointer: "/profiles/1/fieldIds", flat: func(t *testing.T, flat map[string]any) {
			set(t, flat, "/profiles/1/fieldIds", values("nonClaims"))
		}},
		{name: "added requirement", code: "requirement_set_changed", pointer: "/requirements/6", flat: func(t *testing.T, flat map[string]any) {
			row := clone(t, at(t, flat, "/requirements/3"))
			row["requirementId"] = "REQ-CONV-007"
			flat["requirements"] = append(flat["requirements"].([]any), row)
			set(t, flat, "/groups/2/requirementIds", values("REQ-CONV-004", "REQ-CONV-007"))
		}},
		{name: "removed requirement", code: "requirement_set_changed", pointer: "/requirements", flat: func(t *testing.T, flat map[string]any) {
			rows := flat["requirements"].([]any)
			flat["requirements"] = append(append([]any{}, rows[:2]...), rows[3:]...)
			flat["groups"] = flat["groups"].([]any)[1:]
		}},
		{name: "changed source identity", code: "source_identity_changed", pointer: "/sourceId", flat: func(t *testing.T, flat map[string]any) {
			flat["sourceId"] = "fixture.conversion.other"
		}},
		{name: "changed package path", code: "source_identity_changed", pointer: "/specPackagePath", flat: func(t *testing.T, flat map[string]any) {
			flat["specPackagePath"] = "docs/specs/other"
		}},
		{name: "baseline changed after export", code: "stale_baseline", pointer: "/basisDigest", baseline: func(t *testing.T, baseline map[string]any) any {
			set(t, baseline, "/groups/0/members/0/statementCompletion", "Deferred behavior remains reviewed.")
			return baseline
		}},
		{name: "foreign basis digest", code: "stale_baseline", pointer: "/basisDigest", flat: func(t *testing.T, flat map[string]any) {
			flat["basisDigest"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{name: "flat baseline", document: documentBaseline, code: "baseline_not_grouped_source", pointer: "/kind", baseline: func(t *testing.T, _ map[string]any) any {
			return fixture(t, "source.flat.json")
		}},
		{name: "legacy baseline", document: documentBaseline, code: "legacy_source_unsupported", pointer: "/schemaVersion", baseline: func(t *testing.T, _ map[string]any) any {
			return fixture(t, "legacy.v1.json")
		}},
		{name: "policy-failing baseline", document: documentBaseline, code: "missing_proof_binding", pointer: "/groups/1/members/0", detail: "1 source policy violation(s)", baseline: func(t *testing.T, baseline map[string]any) any {
			set(t, baseline, "/groups/1/members/0/fields/proofBindingRefs", values())
			return baseline
		}},
	}
	for _, item := range cases {
		if problem := conversionCaseProblem(t, item); problem != "" {
			t.Fatal(problem)
		}
	}
}
