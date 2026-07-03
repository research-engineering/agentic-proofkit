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
