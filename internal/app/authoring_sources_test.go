package app

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestAuthoringInputGuideIsLazy(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"help", "families"}, {"changed-path-set", "--help"}, {"native-evidence-guidance", "--help"}, {"change", "plan", "--help"}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || strings.Contains(output, "Requirement authoring input guide:") {
			t.Fatalf("authoring guide is not demand-loaded for %v", args)
		}
	}
	_, output := receiptHelpTemplate(t, "requirement-authoring-plan")
	if strings.Count(output, "Requirement authoring input guide:") != 1 {
		t.Fatal("targeted authoring help lost its unique guide")
	}
}

func TestAuthoringSourceClassesPreserveProvenanceAndReviewCLI(t *testing.T) {
	input, help := receiptHelpTemplate(t, "requirement-authoring-plan")
	for _, text := range []string{
		"Admitted reference roles:", "external specifications", "test-coverage observations",
		"product intent", "coverage percentage", "not an approval",
	} {
		if !strings.Contains(help, text) {
			t.Fatalf("authoring help omits intake boundary %q", text)
		}
	}
	cases := []struct{ name, kind, path, summary string }{
		{"code", "code_summary", "src/request.go", "Observed code rejects empty input; the owner must decide whether this is required."},
		{"external-spec", "design_doc", "imports/request-spec.md", "An external specification proposes accepting empty input; it is not this repository's authority."},
		{"intent", "clarification_answer", "decisions/intent.md", "The product owner proposes rejection of empty input for review."},
		{"design", "design_doc", "design/request.md", "The design proposes rejection of empty input."},
		{"plan", "implementation_plan", "plans/request.md", "The implementation plan proposes preserving empty-input rejection."},
		{"tests", "test_summary", "tests/request_test.go", "A test asserts empty-input rejection; no execution is asserted."},
		{"coverage", "test_summary", "reports/coverage.json", "Coverage-only observation: the empty-input branch is not exercised; no product requirement is inferred."},
		{"pr-facts", "pr_facts", "reviews/change.md", "A pull request proposes changing empty-input behavior; approval is unresolved."},
	}
	for _, mode := range []string{"code-baseline", "audit-from-code"} {
		for _, item := range cases {
			t.Run(mode+"/"+item.name, func(t *testing.T) {
				root := t.TempDir()
				materialization := adoptionHelpPacket(t, root, mode)
				source := materialization["requirementSources"].([]any)[0].(map[string]any)
				empty := cloneMap(t, source)
				empty["groups"] = []any{}
				packet := cloneMap(t, input)
				packet["currentRequirementSource"] = empty
				packet["candidateRequirementSource"] = source
				update := packet["candidateUpdates"].([]any)[0].(map[string]any)
				questions := []any{"Does the owner accept the proposed behavior?", "Which conflicting observation should be retained or rejected?"}
				update["ownerQuestions"] = questions
				ref := packet["authoringRefs"].([]any)[0].(map[string]any)
				ref["kind"], ref["path"], ref["summary"] = item.kind, item.path, item.summary
				ref["digest"] = "sha256:" + strings.Repeat("a", 64)
				ref["nonClaims"] = []any{"Caller-provided observation; no authenticity, execution or approval is established."}
				for _, authoringMode := range []string{"retrospective_baseline", "pull_request_design"} {
					packet["mode"] = authoringMode
					report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, packet), "requirement-authoring-plan", "--input", "-")
					if report["state"] != "passed" || !reflect.DeepEqual(report["authoringRefs"], packet["authoringRefs"]) {
						t.Fatal("authoring lost an entire admitted reference")
					}
					changes := report["candidateChangeSet"].([]any)
					if len(changes) != 1 || !reflect.DeepEqual(changes[0].(map[string]any)["sourceRefIds"], update["sourceRefIds"]) {
						t.Fatal("candidate lost its provenance relation")
					}
					var ownerAction map[string]any
					for _, raw := range report["ownerReviewPlan"].([]any) {
						action := raw.(map[string]any)
						if action["candidateId"] == update["candidateId"] {
							ownerAction = action
						}
					}
					if ownerAction == nil || !reflect.DeepEqual(ownerAction["ownerQuestions"], questions) || !reflect.DeepEqual(ownerAction["evidenceRefs"], update["sourceRefIds"]) {
						t.Fatal("unresolved owner questions or evidence links disappeared")
					}
					preview := report["nonAuthoritativeAdmissionPreview"].(map[string]any)
					if preview["authority"] != "candidate_only" || preview["candidateOnly"] != true || preview["ownerReviewRequired"] != true {
						t.Fatal("observations or coverage became owner approval")
					}
					for _, field := range []string{"writtenFileCountNonClaim", "executedWitnessCountNonClaim"} {
						if fmt.Sprint(report["summary"].(map[string]any)[field]) != "0" {
							t.Fatal("authoring claimed an unperformed effect")
						}
					}
					if !equalCLIJSON(t, preview["requirementSourcePreview"], source) {
						t.Fatal("reference role changed canonical requirement meaning")
					}
					materialization["requirementSources"] = []any{preview["requirementSourcePreview"]}
					plan := runAdoptionHelpCLI(t, adoptionHelpJSON(t, materialization), "adopt", "materialize", "plan", "--input", "-", "--repo-root", root)
					if plan["state"] != "ready" || plan["sourceIntent"] != mode {
						t.Fatal("actual candidate output cannot enter its declared adoption mode")
					}
				}
				for _, field := range []string{"kind", "sourceRefIds"} {
					invalid := cloneMap(t, packet)
					if field == "kind" {
						invalid["authoringRefs"].([]any)[0].(map[string]any)[field] = "unadmitted_kind"
					} else {
						invalid["candidateUpdates"].([]any)[0].(map[string]any)[field] = []any{"missing.ref"}
					}
					code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"requirement-authoring-plan", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, invalid)), PresentationCapabilities{})
					if code != 1 || output != "" || !strings.Contains(diagnostic, field) {
						t.Fatalf("invalid %s did not fail at the intended boundary: %d %q %q", field, code, output, diagnostic)
					}
				}
			})
		}
	}
}
