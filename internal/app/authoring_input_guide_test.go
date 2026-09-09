package app

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestAuthoringInputGuideBootstrapCLI(t *testing.T) {
	root := t.TempDir()
	materialization := adoptionHelpPacket(t, root, "audit-from-code")
	source := materialization["requirementSources"].([]any)[0].(map[string]any)
	candidate := source["requirements"].([]any)[0]
	empty := decodeCLIJSON(t, string(adoptionHelpJSON(t, source))).(map[string]any)
	empty["requirements"] = []any{}

	var canonical string
	for _, args := range [][]string{
		{"requirement-authoring-plan", "--help"},
		{"requirement-authoring-plan", "-h"},
		{"help", "requirement-authoring-plan"},
	} {
		status, help, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if status != 0 || stderr != "" || len(help) > 10<<10 || !strings.Contains(help, "adopt materialize plan --help") {
			t.Fatalf("authoring help status=%d stderr=%q", status, stderr)
		}
		if canonical != "" && canonical != help {
			t.Fatal("authoring help aliases disagree")
		}
		canonical = help
	}
	if !strings.Contains(canonical, "Order authoringRefs by refId, strictly ascending and without duplicates.") {
		t.Fatal("authoring help omits multi-reference ordering")
	}
	parts := strings.Split(canonical, "```json\n")
	if len(parts) != 2 {
		t.Fatal("authoring help must contain one template, not duplicate source examples")
	}
	input, _, closed := strings.Cut(parts[1], "\n```")
	if !closed {
		t.Fatal("unclosed authoring template")
	}
	packet := decodeCLIJSON(t, input).(map[string]any)
	if packet["mode"] != "retrospective_baseline" {
		t.Fatalf("published authoring mode drifted: %v", packet["mode"])
	}
	commands := guideCommands(t, canonical, "Requirement authoring input guide:", cliexec.PathRenderer())
	if !reflect.DeepEqual(commands, [][]string{{"requirement-authoring-plan", "--input", "<packet>"}}) {
		t.Fatalf("wrong authoring invocation: %v", commands)
	}
	args := fillGuideOperands(t, commands[0], map[string]string{"<packet>": "-"})
	update := packet["candidateUpdates"].([]any)[0].(map[string]any)
	if packet["currentRequirementSource"] != nil || update["candidateRequirement"] != nil {
		t.Fatal("authoring template fabricated its source or candidate")
	}
	packet["currentRequirementSource"], update["candidateRequirement"] = empty, candidate
	firstRef := packet["authoringRefs"].([]any)[0].(map[string]any)
	secondRef := decodeCLIJSON(t, string(adoptionHelpJSON(t, firstRef))).(map[string]any)
	secondRef["refId"] = "example.observation.z"
	secondRef["summary"] = "A second independent observation remains pending owner review."
	refs := []any{firstRef, secondRef}
	refIDs := []any{firstRef["refId"], secondRef["refId"]}
	for _, count := range []int{1, 2} {
		packet["authoringRefs"] = refs[:count]
		update["sourceRefIds"] = refIDs[:count]
		for _, mode := range []string{"retrospective_baseline", "pull_request_design"} {
			packet["mode"] = mode
			report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, packet), args...)
			if report["planKind"] != "proofkit.requirement-authoring-plan" || report["state"] != "passed" || report["mode"] != mode {
				t.Fatalf("wrong authoring report: %v", report)
			}
			if !reflect.DeepEqual(report["authoringRefs"], packet["authoringRefs"]) {
				t.Fatal("authoring projection lost or changed a complete reference record")
			}
			preview := report["nonAuthoritativeAdmissionPreview"].(map[string]any)
			if preview["candidateOnly"] != true || preview["ownerReviewRequired"] != true || preview["authority"] != "candidate_only" {
				t.Fatal("admitted bootstrap became product approval")
			}
			if !reflect.DeepEqual(preview["requirementSourcePreview"], source) {
				t.Fatalf("bootstrap source mismatch:\ngot: %s\nwant: %s", adoptionHelpJSON(t, preview["requirementSourcePreview"]), adoptionHelpJSON(t, source))
			}
			materialization["requirementSources"] = []any{preview["requirementSourcePreview"]}
			plan := runAdoptionHelpCLI(t, adoptionHelpJSON(t, materialization), "adopt", "materialize", "plan", "--input", "-", "--repo-root", root)
			if plan["state"] != "ready" || plan["sourceIntent"] != "audit-from-code" {
				t.Fatal("bootstrap preview cannot feed the existing materialization route")
			}
		}
	}
	for _, mutation := range []string{"unsorted", "duplicate"} {
		t.Run(mutation+" authoring refs", func(t *testing.T) {
			invalid := decodeCLIJSON(t, string(adoptionHelpJSON(t, packet))).(map[string]any)
			refs := invalid["authoringRefs"].([]any)
			if mutation == "unsorted" {
				refs[0], refs[1] = refs[1], refs[0]
			} else {
				refs[1] = refs[0]
			}
			status, stdout, stderr := executeAgentWorkflowCLI(t, args, bytes.NewReader(adoptionHelpJSON(t, invalid)), PresentationCapabilities{})
			if status != 1 || stdout != "" || !strings.Contains(stderr, "authoringRef ids must be sorted and unique") {
				t.Fatalf("invalid ref order: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
		})
	}

	// A source containing the candidate must not be treated as empty bootstrap.
	packet["currentRequirementSource"] = source
	status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"requirement-authoring-plan", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
	if status != 1 || stderr != "" {
		t.Fatalf("duplicate add status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failed := decodeCLIJSON(t, stdout).(map[string]any)
	if failed["state"] != "failed" || failed["nonAuthoritativeAdmissionPreview"] != nil {
		t.Fatal("duplicate add retained a passing candidate preview")
	}
}
