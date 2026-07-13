package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestRequirementContextCommandsComposeThroughWholeCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.078417255856588541640488533337296521071324425566921898314006295059346651375053")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.026918779924949500817883735459777435749569395463462098851750112168717349371591")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.037106612382996619981621102911104931496378404893868406197919247815645123874441")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.023947615033231006584057272018250251823714544315759467896512469485975523531624")
	root := t.TempDir()
	tree := map[string]any{
		"schemaVersion": json.Number("2"), "treeId": "consumer.spec-tree", "rootNodeId": "consumer.root",
		"callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{},
		"nodes": []any{map[string]any{
			"nodeId": "consumer.root", "nodeKind": "meta_spec", "label": "Consumer specification", "displayOrder": json.Number("1"),
			"callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{
				"sourceRefId": "consumer.root.requirements", "sourceRefKind": "source_id",
				"sourceRole": "requirements", "sourceId": "consumer.requirements",
			}},
		}},
	}
	requirementSource := cliRequirementSource("The CLI composes the baseline requirement context.")
	writeCLIJSONFixture(t, root, "proofkit/spec-tree.json", tree)
	writeCLIJSONFixture(t, root, "docs/specs/consumer/requirements.v1.json", requirementSource)
	catalog := map[string]any{
		"schemaVersion": json.Number("1"), "catalogId": "consumer.context",
		"specTree": map[string]any{"path": "proofkit/spec-tree.json"},
		"requirementSources": []any{map[string]any{
			"nodeId": "consumer.root", "path": "docs/specs/consumer/requirements.v1.json",
		}},
	}

	base := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	if _, err := requirementcontext.AdmitSnapshot(base); err != nil {
		t.Fatalf("whole-CLI context output failed owner admission: %v", err)
	}
	slice := runAppJSON(t, []string{"requirement-context-slice", "--input", "-"}, map[string]any{
		"schemaVersion": json.Number("1"), "sliceId": "consumer.context.slice", "context": base,
		"query": map[string]any{"profile": "specification", "requirementIds": []any{"REQ-CONSUMER-001"}},
	})
	if slice["contextKind"] != "proofkit.requirement-context-slice" || slice["state"] != "selected" || slice["snapshotId"] != base["snapshotId"] {
		t.Fatalf("unexpected whole-CLI context slice: %#v", slice)
	}

	requirementSource["requirements"].([]any)[0].(map[string]any)["invariant"] = "The CLI composes the current requirement context."
	writeCLIJSONFixture(t, root, "docs/specs/consumer/requirements.v1.json", requirementSource)
	current := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	diff := runAppJSON(t, []string{"requirement-semantic-diff", "--input", "-"}, map[string]any{
		"schemaVersion": json.Number("1"), "diffId": "consumer.requirement.diff",
		"baseContext": base, "currentContext": current,
	})
	if diff["changeCount"] != json.Number("1") {
		t.Fatalf("whole-CLI semantic diff changeCount=%v, want 1", diff["changeCount"])
	}
	if _, err := requirementdiff.AdmitOutput(diff, current["snapshotId"].(string)); err != nil {
		t.Fatalf("whole-CLI semantic diff failed owner admission: %v", err)
	}

	graph := runAppJSON(t, []string{"requirement-traceability-graph", "--input", "-"}, map[string]any{
		"schemaVersion": json.Number("2"), "graphId": "consumer.requirement.graph", "context": current,
	})
	if _, err := requirementgraph.AdmitOutput(graph, current["snapshotId"].(string)); err != nil {
		t.Fatalf("whole-CLI traceability graph failed owner admission: %v", err)
	}
}

func cliRequirementSource(invariant string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"), "sourceId": "consumer.requirements",
		"specPackagePath": "docs/specs/consumer", "overviewPath": "docs/specs/consumer/overview.md",
		"requirementsPath": "docs/specs/consumer/requirements.v1.json",
		"requirements": []any{map[string]any{
			"requirementId": "REQ-CONSUMER-001", "ownerId": "consumer.owner", "invariant": invariant,
			"claimLevel": "blocking", "riskClass": "high",
			"proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "nonClaimRefs": []any{"NC-CONSUMER-001"},
			"nonClaims":    []any{"This requirement does not approve merge."},
			"lifecycle":    map[string]any{"state": "active", "replacementRequirementIds": []any{}, "evidenceRefs": []any{}},
			"deferral":     nil,
			"updatePolicy": map[string]any{"reviewOwnerId": "consumer.owner", "requiresImpactDeclaration": true, "requiresProofBindingReview": true},
		}},
		"nonClaims": []any{"This source does not execute proof witnesses."},
	}
}

func runAppJSON(t *testing.T, args []string, input any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := Run(context.Background(), args, bytes.NewReader(encoded), &stdout, &stderr); exit != 0 {
		t.Fatalf("Run(%v) exit=%d stderr=%s stdout=%s", args, exit, stderr.String(), stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("Run(%v) wrote stderr on success: %s", args, stderr.String())
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), int64(stdout.Len()))
	if err != nil {
		t.Fatalf("Run(%v) emitted invalid JSON: %v", args, err)
	}
	record, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("Run(%v) output is not an object", args)
	}
	return record
}

func writeCLIJSONFixture(t *testing.T, root, path string, value any) {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
