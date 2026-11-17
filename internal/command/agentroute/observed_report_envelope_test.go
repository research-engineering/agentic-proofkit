package agentroute

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestBlockedRouteEvidenceResolvesExactObservedPaths(t *testing.T) {
	paths := []string{strings.Repeat("segment/", 80) + "a.json", strings.Repeat("segment/", 80) + "b.json", "inputs/task-validation.json"}
	input := structuralRouteInput("validate_requirement_source", true)
	reports := []any{}
	for _, path := range paths {
		reports = append(reports, map[string]any{"kind": "evidence", "ref": path, "state": "failed"})
	}
	input["observedReports"] = reports
	envelope, code, err := BuildEnvelope(input)
	if err != nil || code != 1 {
		t.Fatalf("route exit=%d err=%v", code, err)
	}
	wire := routeEnvelopeWire(t, envelope)
	contexts := map[string]string{}
	for _, raw := range wire["contextRefs"].([]any) {
		ref := raw.(map[string]any)
		if ref["role"] == observedReportRole {
			path := ref["path"].(string)
			if ref["selector"] != path {
				t.Fatal("observed report selector differs from its path")
			}
			contexts[ref["refId"].(string)] = path
		}
	}
	remaining := map[string]bool{}
	for _, path := range paths {
		remaining[path] = true
	}
	for _, raw := range wire["blockedPreconditions"].([]any) {
		blocker := raw.(map[string]any)
		refs := blocker["evidenceRefs"].([]any)
		if len(refs) != 1 {
			t.Fatalf("observed blocker lost its exact evidence: %v", blocker)
		}
		path, exists := contexts[refs[0].(string)]
		if !exists || !remaining[path] {
			t.Fatalf("unresolved, duplicate or altered evidence: %v", blocker)
		}
		delete(remaining, path)
	}
	if len(remaining) != 0 || len(contexts) != len(paths) || len(wire["omitted"].([]any)) != 0 {
		t.Fatalf("observed path inventory changed: remaining=%v contexts=%d", remaining, len(contexts))
	}
	if err := schemacheck.Validate(FullEnvelopeStructure(), envelope); err != nil {
		t.Fatal(err)
	}
}

func TestObservedReportContextsRespectNativeBoundAndReferenceClosure(t *testing.T) {
	input := structuralRouteInput("validate_requirement_source", true)
	reports := []any{}
	for index := range agentenvelope.MaxContextRefs * 2 {
		reports = append(reports, map[string]any{"kind": "evidence", "ref": fmt.Sprintf("reports/%03d.json", index), "state": "failed"})
	}
	input["observedReports"] = reports
	envelope, _, err := BuildEnvelope(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope["contextRefs"].([]any)) != agentenvelope.MaxContextRefs || envelope["bounds"].(map[string]any)["fanout"] != "wide_or_full_gate_required" {
		t.Fatalf("observed context bound was not exercised: %v", envelope["costContract"])
	}
	if err := schemacheck.Validate(FullEnvelopeStructure(), envelope); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, raw := range envelope["contextRefs"].([]any) {
		ids[raw.(map[string]any)["refId"].(string)] = true
	}
	for _, raw := range envelope["blockedPreconditions"].([]any) {
		for _, ref := range raw.(map[string]any)["evidenceRefs"].([]any) {
			if !ids[ref.(string)] {
				t.Fatal("bounded blocker retained an unavailable context")
			}
		}
	}
}
