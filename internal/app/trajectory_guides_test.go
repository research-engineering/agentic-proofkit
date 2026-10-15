package app

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestTrajectoryInputGuidesAreLazyAndCarrierBound(t *testing.T) {
	for _, item := range []struct {
		command, marker string
		commands        [][]string
	}{
		{"witness-scheduler-plan", "Witness scheduler input guide:", [][]string{
			{"witness-plan", "--input", "<projection-input>"},
			{"witness-scheduler-plan", "--input", "<scheduler-input>"},
		}},
		{"requirement-context-slice", "Requirement context slice input guide:", [][]string{
			{"requirement-context-slice", "--input", "<slice-input>"},
		}},
		{"requirement-semantic-diff", "Requirement semantic diff input guide:", [][]string{
			{"requirement-semantic-diff", "--input", "<diff-input>"},
		}},
	} {
		t.Run(item.command, func(t *testing.T) {
			packet, help := receiptHelpTemplate(t, item.command)
			if len(help) > 10<<10 {
				t.Fatal("guide exceeds its bounded help surface")
			}
			code, output, diagnostic := executeAgentWorkflowCLI(t, []string{item.command, "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
			if code != 1 || output != "" || diagnostic == "" {
				t.Fatal("unfilled template must not be admissible")
			}
			for _, carrier := range []struct{ profile, python string }{
				{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
			} {
				renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
				if err != nil {
					t.Fatal(err)
				}
				descriptor, _ := commandDescriptorFor(item.command)
				if got := guideCommands(t, commandUsageWithRenderer(descriptor, renderer), item.marker, renderer); !reflect.DeepEqual(got, item.commands) {
					t.Fatalf("guide argv differs: %v", got)
				}
			}
			for _, args := range [][]string{{"help"}, {"help", "families"}, {"native-evidence-guidance"}, {"changed-path-set", "--help"}} {
				_, output, _ := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
				if strings.Contains(output, item.marker) {
					t.Fatalf("guide must stay demand-loaded: %v", args)
				}
			}
		})
	}
}

// The scheduler guide must compose with the materialization guide's binding
// without retyping argv, and its one-parallel-group premise must be real.
func TestSchedulerGuideProjectsTheConnectedBinding(t *testing.T) {
	scheduler, help := receiptHelpTemplate(t, "witness-scheduler-plan")
	binding := adoptionHelpPacket(t, t.TempDir(), "fresh")["requirementProofBinding"].(map[string]any)["record"]
	commands := guideCommands(t, help, "Witness scheduler input guide:", cliexec.PathRenderer())
	projection := map[string]any{"schemaVersion": 1, "projection": "requirement-bindings", "requirementProofBinding": binding, "vocabulary": scheduler["vocabulary"]}
	projected := runAdoptionHelpCLI(t, adoptionHelpJSON(t, projection), fillGuideOperands(t, commands[0], map[string]string{"<projection-input>": "-"})...)
	projectedCommands := projected["commands"].([]any)
	if len(projectedCommands) != 1 || projectedCommands[0].(map[string]any)["id"] != "example.test.requests" {
		t.Fatalf("projection does not carry the binding command: %v", projected)
	}
	scheduler["schedulerPlanId"], scheduler["commands"] = "example.scheduler", projectedCommands
	policy := scheduler["policies"].([]any)[0].(map[string]any)
	policy["commandId"], policy["inputSelectors"] = "example.test.requests", []any{"src"}
	report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, scheduler), fillGuideOperands(t, commands[1], map[string]string{"<scheduler-input>": "-"})...)
	if report["state"] != "passed" || report["reportId"] != "example.scheduler" {
		t.Fatalf("connected scheduler input did not pass: %v", report)
	}
	vocabulary := scheduler["vocabulary"].(map[string]any)
	vocabulary["parallelGroups"] = []any{"example.native", "example.other"}
	code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"witness-plan", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, projection)), PresentationCapabilities{})
	if code != 1 || output != "" || !strings.Contains(diagnostic, "exactly one parallelGroup") {
		t.Fatalf("projection premise is not enforced: %d %q", code, diagnostic)
	}
}

// The slice and diff guides operate on retained compose stdout: a statement
// edit, a scenario-body edit and an unchanged capture have distinct verdicts.
func TestSliceAndDiffGuidesCompareRetainedContexts(t *testing.T) {
	contextPacket, _ := receiptHelpTemplate(t, "requirement-context-compose")
	root := t.TempDir()
	materialize := adoptionHelpPacket(t, root, "fresh")
	source := materialize["requirementSources"].([]any)[0].(map[string]any)
	admitted, err := requirementsourceadmission.Evaluate(source)
	if err != nil || admitted.ExitCode != 0 {
		t.Fatalf("source premise: %v", err)
	}
	binding := materialize["requirementProofBinding"].(map[string]any)
	writeCLIJSONFixture(t, root, admitted.Source.RequirementsPath(), source)
	writeCLIJSONFixture(t, root, binding["path"].(string), binding["record"])
	writeCLIJSONFixture(t, root, contextPacket["catalog"].(map[string]any)["specTree"].(map[string]any)["path"].(string), contextPacket["tree"])
	capture := func() map[string]any {
		return runAdoptionHelpCLI(t, adoptionHelpJSON(t, contextPacket), "requirement-context-compose", "--input", "-", "--input-pointer", "/catalog", "--repo-root", root)
	}
	base := capture()
	slice, sliceHelp := receiptHelpTemplate(t, "requirement-context-slice")
	slice["sliceId"], slice["context"] = "example.slice", base
	slice["query"].(map[string]any)["requirementIds"] = []any{"REQ-EXAMPLE-001"}
	sliceArgs := fillGuideOperands(t, guideCommands(t, sliceHelp, "Requirement context slice input guide:", cliexec.PathRenderer())[0], map[string]string{"<slice-input>": "-"})
	selected := runAdoptionHelpCLI(t, adoptionHelpJSON(t, slice), sliceArgs...)
	bindings := selected["projections"].(map[string]any)["proofBinding"].(map[string]any)["bindings"].([]any)
	if selected["state"] != "selected" || len(bindings) != 1 || bindings[0].(map[string]any)["scenarioId"] != "example.requests.empty" {
		t.Fatalf("proof slice lost the selected route: %v", selected)
	}
	diff, diffHelp := receiptHelpTemplate(t, "requirement-semantic-diff")
	diffArgs := fillGuideOperands(t, guideCommands(t, diffHelp, "Requirement semantic diff input guide:", cliexec.PathRenderer())[0], map[string]string{"<diff-input>": "-"})
	compare := func(current map[string]any) []any {
		diff["diffId"], diff["baseContext"], diff["currentContext"] = "example.diff", base, current
		report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, diff), diffArgs...)
		pointers := []any{}
		for _, change := range report["changes"].([]any) {
			pointers = append(pointers, change.(map[string]any)["jsonPointer"])
		}
		return pointers
	}
	if changes := compare(capture()); len(changes) != 0 {
		t.Fatalf("unchanged capture reported changes: %v", changes)
	}
	member := source["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
	member["statementCompletion"] = "Empty and whitespace-only requests are rejected."
	writeCLIJSONFixture(t, root, admitted.Source.RequirementsPath(), source)
	if changes := compare(capture()); !reflect.DeepEqual(changes, []any{"/requirements/REQ-EXAMPLE-001/invariant"}) {
		t.Fatalf("statement edit changes = %v", changes)
	}
	base = capture()
	source["scenarios"] = scenarioGuideExample(t)
	writeCLIJSONFixture(t, root, admitted.Source.RequirementsPath(), source)
	if changes := compare(capture()); !reflect.DeepEqual(changes, []any{"/requirements/REQ-EXAMPLE-001/sourceReviewDigest"}) {
		t.Fatalf("scenario-body edit changes = %v", changes)
	}
}

func scenarioGuideExample(t *testing.T) []any {
	t.Helper()
	code, help, diagnostic := executeAgentWorkflowCLI(t, []string{"requirement-source-admission", "--help"}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" || strings.Count(help, "Scenario body guide:") != 1 {
		t.Fatal("source help lacks the scenario body guide")
	}
	_, body, _ := strings.Cut(help, "```json\n")
	example, _, closed := strings.Cut(body, "\n```")
	if !closed {
		t.Fatal("scenario example is not closed")
	}
	return decodeCLIJSON(t, example).([]any)
}

func TestScenarioGuideBodyMaterializesWithItsBindingRow(t *testing.T) {
	root := t.TempDir()
	packet := adoptionHelpPacket(t, root, "fresh")
	source := packet["requirementSources"].([]any)[0].(map[string]any)
	source["scenarios"] = scenarioGuideExample(t)
	if report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, source), "requirement-source-admission", "--input", "-"); report["state"] != "passed" {
		t.Fatalf("scenario example is not admissible: %v", report)
	}
	if plan := runAdoptionHelpCLI(t, adoptionHelpJSON(t, packet), "adopt", "materialize", "plan", "--input", "-", "--repo-root", root); plan["state"] != "ready" {
		t.Fatalf("scenario example does not link to the binding row: %v", plan)
	}
	scenario := source["scenarios"].([]any)[0].(map[string]any)
	scenario["parameters"] = []any{"channel", "request"}
	code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"requirement-source-admission", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, source)), PresentationCapabilities{})
	if code != 1 || output != "" || !strings.Contains(diagnostic, "unused_parameter") {
		t.Fatalf("an unreferenced parameter was admitted: %d %q", code, diagnostic)
	}
}

func TestNextActionContinuationIsTotalAndExecutable(t *testing.T) {
	routes := map[string][]string{
		"choose_adoption_mode":        {"adopt", "plan"},
		"rematerialize_project":       {"adopt", "materialize", "plan"},
		"choose_recovery":             {"adopt", "materialize", "recover"},
		"run_repository_verification": {"native-evidence-guidance"},
		"repair_project_records":      nil,
		"repair_control_state":        nil,
	}
	for _, carrier := range []struct{ profile, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"next", "status"} {
			descriptor, _ := commandDescriptorFor(command)
			lines := strings.Split(commandUsageWithRenderer(descriptor, renderer), "\n")
			seen := map[string]bool{}
			for index, line := range lines {
				class, _, ok := strings.Cut(strings.TrimPrefix(line, "  "), ": ")
				route, known := routes[class]
				if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") || !ok || !known {
					continue
				}
				seen[class] = true
				next := lines[index+1]
				if route == nil {
					if strings.Contains(next, renderer.DisplayCommand()) {
						t.Fatalf("%s %s must stop at an owner decision", command, class)
					}
					continue
				}
				if next != "    "+renderer.DisplayCommand(append(append([]string{}, route...), "--help")...) {
					t.Fatalf("%s %s continuation = %q", command, class, next)
				}
			}
			if len(seen) != len(routes) {
				t.Fatalf("%s continuation covers %v, want every action class", command, seen)
			}
		}
	}
	for _, route := range routes {
		if route == nil {
			continue
		}
		if code, output, diagnostic := executeAgentWorkflowCLI(t, append(append([]string{}, route...), "--help"), panicReader{}, PresentationCapabilities{}); code != 0 || output == "" || diagnostic != "" {
			t.Fatalf("continuation help is not executable: %v", route)
		}
	}
	for _, args := range [][]string{{"help"}, {"help", "families"}, {"adopt", "plan", "--help"}} {
		if _, output, _ := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{}); strings.Contains(output, "Next-action continuation:") {
			t.Fatalf("continuation must stay on status/next help: %v", args)
		}
	}
}
