package documentlifecycle

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func TestBuildAdmitsCurrentDurableDocumentAndRejectsAuthorityDrift(t *testing.T) {
	record, exitCode, err := Build(validDocumentLifecycleInput())
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		message string
	}{
		{
			name: "archived active authority",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["lifecycleState"] = "archived_historical"
				document["authorityRole"] = "durable_meaning"
			},
			message: "archived document must not keep active authority",
		},
		{
			name: "generated lookup without freshness",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.generated.requirement-graph"
				document["kind"] = "generated_lookup"
				document["authorityRole"] = "generated_lookup"
				document["routingRole"] = "lookup_projection"
				document["sourceRefs"] = []any{"docs/specs/review/requirements.v1.json"}
				document["freshnessCheckRefs"] = []any{}
			},
			message: "generated_lookup document must declare freshness check refs",
		},
		{
			name: "generated lookup without source refs",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.generated.requirement-graph"
				document["kind"] = "generated_lookup"
				document["authorityRole"] = "generated_lookup"
				document["routingRole"] = "lookup_projection"
				document["sourceRefs"] = []any{}
			},
			message: "generated_lookup document must declare source refs",
		},
		{
			name: "generated lookup routed as owner surface",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.generated.requirement-graph"
				document["kind"] = "generated_lookup"
				document["authorityRole"] = "generated_lookup"
				document["routingRole"] = "owner_surface"
				document["sourceRefs"] = []any{"docs/specs/review/requirements.v1.json"}
			},
			message: "generated_lookup document must use lookup_projection or none routing",
		},
		{
			name: "rendered view owns durable meaning",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.rendered.review-spec"
				document["kind"] = "rendered_view"
				document["authorityRole"] = "durable_meaning"
				document["routingRole"] = "presentation_view"
				document["sourceRefs"] = []any{"docs/specs/review/requirements.v1.json"}
			},
			message: "rendered_view document must use presentation_only authority role",
		},
		{
			name: "rendered view without source refs",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.rendered.review-spec"
				document["kind"] = "rendered_view"
				document["authorityRole"] = "presentation_only"
				document["routingRole"] = "presentation_view"
				document["sourceRefs"] = []any{}
			},
			message: "rendered_view document must declare source refs",
		},
		{
			name: "rendered view without freshness",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.rendered.review-spec"
				document["kind"] = "rendered_view"
				document["authorityRole"] = "presentation_only"
				document["routingRole"] = "presentation_view"
				document["sourceRefs"] = []any{"docs/specs/review/requirements.v1.json"}
				document["freshnessCheckRefs"] = []any{}
			},
			message: "rendered_view document must declare freshness check refs",
		},
		{
			name: "rendered view routed as owner surface",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.rendered.review-spec"
				document["kind"] = "rendered_view"
				document["authorityRole"] = "presentation_only"
				document["routingRole"] = "owner_surface"
				document["sourceRefs"] = []any{"docs/specs/review/requirements.v1.json"}
			},
			message: "rendered_view document must use presentation_view or none routing",
		},
		{
			name: "primary router without navigation authority",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.router"
				document["kind"] = "router"
				document["authorityRole"] = "durable_meaning"
				document["routingRole"] = "primary_router"
			},
			message: "primary router must use navigation authority role",
		},
		{
			name: "current durable missing freshness",
			mutate: func(input map[string]any) {
				firstDocument(input)["freshnessCheckRefs"] = []any{}
			},
			message: "current durable document must declare freshness check refs",
		},
		{
			name: "active design doc keeps durable authority",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.design.active"
				document["kind"] = "design_doc"
				document["lifecycleState"] = "active_pr_local"
				document["authorityRole"] = "durable_meaning"
				document["routingRole"] = "pr_local_input"
				document["freshnessCheckRefs"] = []any{}
			},
			message: "active PR-local design_doc must use temporary_pr_reasoning authority",
		},
		{
			name: "active implementation plan routed as owner surface",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.plan.active"
				document["kind"] = "implementation_plan"
				document["lifecycleState"] = "active_pr_local"
				document["authorityRole"] = "temporary_pr_reasoning"
				document["routingRole"] = "owner_surface"
				document["freshnessCheckRefs"] = []any{}
			},
			message: "active PR-local implementation_plan must use pr_local_input or none routing",
		},
		{
			name: "retained implementation plan keeps active routing",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.plan.retained"
				document["kind"] = "implementation_plan"
				document["lifecycleState"] = "merged_retained"
				document["authorityRole"] = "historical_evidence"
				document["routingRole"] = "owner_surface"
				document["freshnessCheckRefs"] = []any{}
			},
			message: "retained implementation_plan must not be routed as current authority",
		},
		{
			name: "temporary document claims current lifecycle",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.design.current"
				document["kind"] = "design_doc"
				document["lifecycleState"] = "current"
				document["authorityRole"] = "temporary_pr_reasoning"
				document["routingRole"] = "pr_local_input"
				document["freshnessCheckRefs"] = []any{}
			},
			message: "temporary design_doc must not use current lifecycle state",
		},
		{
			name: "archived document keeps current routing",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["lifecycleState"] = "archived_historical"
				document["authorityRole"] = "historical_evidence"
				document["routingRole"] = "owner_surface"
			},
			message: "archived document must not keep current routing role",
		},
		{
			name: "work ledger without open work authority",
			mutate: func(input map[string]any) {
				document := firstDocument(input)
				document["documentId"] = "docs.backlog"
				document["kind"] = "work_ledger"
				document["authorityRole"] = "durable_meaning"
				document["routingRole"] = "owner_surface"
				document["path"] = "BACKLOG.md"
			},
			message: "work ledger must use open_work_truth authority role",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validDocumentLifecycleInput()
			item.mutate(input)

			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			if !diagnosticFailureContains(record.Diagnostics, item.message) {
				t.Fatalf("diagnostics=%#v, want %q", record.Diagnostics, item.message)
			}
		})
	}
}

func TestBuildRejectsMissingRequiredLifecycleMetadata(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		message string
	}{
		{
			name: "forbidden payload boundaries",
			mutate: func(input map[string]any) {
				firstDocument(input)["forbiddenPayloads"] = []any{}
			},
			message: "forbiddenPayloads must be non-empty",
		},
		{
			name: "non claims",
			mutate: func(input map[string]any) {
				firstDocument(input)["nonClaims"] = []any{}
			},
			message: "nonClaims must be non-empty",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validDocumentLifecycleInput()
			item.mutate(input)

			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.message) {
				t.Fatalf("Build() error=%v, want %q", err, item.message)
			}
		})
	}
}

func validDocumentLifecycleInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"boundaryId":    "docs.lifecycle.boundary",
		"nonClaims":     []any{"Document lifecycle test input does not read document content."},
		"documents": []any{
			map[string]any{
				"authorityRole":      "durable_meaning",
				"documentId":         "docs.review.requirements",
				"forbiddenPayloads":  []any{"local agent run notes", "temporary PR decisions"},
				"freshnessCheckRefs": []any{"scripts/verify_requirement_sources.sh"},
				"kind":               "requirement_records",
				"lifecycleState":     "current",
				"mutationTriggers":   []any{"requirement invariant changes"},
				"nonClaims":          []any{"Requirement records do not execute witnesses."},
				"owner":              "review-system-owners",
				"path":               "docs/specs/review/requirements.v1.json",
				"routingRole":        "owner_surface",
				"sourceRefs":         []any{},
			},
		},
	}
}

func firstDocument(input map[string]any) map[string]any {
	return input["documents"].([]any)[0].(map[string]any)
}

func diagnosticFailureContains(diagnostics []report.Diagnostic, needle string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Key != "failures" {
			continue
		}
		for _, value := range diagnostic.Value.([]any) {
			if strings.Contains(value.(string), needle) {
				return true
			}
		}
	}
	return false
}
