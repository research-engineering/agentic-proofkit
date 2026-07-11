package requirementbinding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestSelfHostingWitnessCommandIdentityMatchesWitnessPlan(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..", "..")
	bindingRaw := readOwnerJSON(t, filepath.Join(repositoryRoot, "proofkit", "requirement-bindings.json"))
	result, err := Build(bindingRaw)
	if err != nil {
		t.Fatalf("Build(requirement-bindings.json) error=%v", err)
	}
	if result.Record.State != "passed" {
		t.Fatalf("requirement-bindings.json state=%s, want passed", result.Record.State)
	}

	witnessPlan := readOwnerJSON(t, filepath.Join(repositoryRoot, "proofkit", "witness-plan.json")).(map[string]any)
	planCommands := map[string]map[string]any{}
	for _, rawCommand := range witnessPlan["commands"].([]any) {
		command := rawCommand.(map[string]any)
		commandID := command["id"].(string)
		if _, exists := planCommands[commandID]; exists {
			t.Fatalf("witness-plan.json repeats command id %s", commandID)
		}
		planCommands[commandID] = command
	}
	if len(planCommands) != len(result.Input.WitnessCommands) {
		t.Fatalf("witness command count binding=%d plan=%d", len(result.Input.WitnessCommands), len(planCommands))
	}
	for _, bindingCommand := range result.Input.WitnessCommands {
		planCommand, ok := planCommands[bindingCommand.CommandID]
		if !ok {
			t.Errorf("binding witness command %s is absent from witness-plan.json", bindingCommand.CommandID)
			continue
		}
		argv, err := displayCommandArgv(bindingCommand.Command)
		if err != nil {
			t.Fatalf("parse binding command %s: %v", bindingCommand.CommandID, err)
		}
		if got := stringValues(planCommand["argv"].([]any)); !reflect.DeepEqual(got, argv) {
			t.Errorf("command %s argv=%q, want %q", bindingCommand.CommandID, got, argv)
		}
		environment := planCommand["environment"].(map[string]any)
		if got := stringValues(environment["classes"].([]any)); !reflect.DeepEqual(got, bindingCommand.EnvironmentClasses) {
			t.Errorf("command %s environment classes=%q, want %q", bindingCommand.CommandID, got, bindingCommand.EnvironmentClasses)
		}
	}
}

func readOwnerJSON(t *testing.T, path string) any {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	value, err := admission.DecodeJSON(file, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestBuildReportFailsUnknownRequirementBinding(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.000376648692213538787264617164821843651034132903736657977168045531003514534050")
	input := validRequirementBindingInput()
	input["bindings"].([]any)[0].(map[string]any)["requirementId"] = "REQ-PROOFKIT-MISSING"

	record, exitCode, err := BuildReport(input)
	if err != nil {
		t.Fatalf("BuildReport() unexpected error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("BuildReport() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnosticContains(t, record.RuleResults, "binding references unknown requirementId=REQ-PROOFKIT-MISSING")
}

func TestBuildReportRejectsBindingThatOmitsMultiEnvironmentCommandClass(t *testing.T) {
	input := validRequirementBindingInput()
	input["witnessCommands"].([]any)[0].(map[string]any)["environmentClasses"] = []any{"local-go", "local-python"}
	delete(input["witnessCommands"].([]any)[0].(map[string]any), "environmentClass")

	record, exitCode, err := BuildReport(input)
	if err != nil {
		t.Fatalf("BuildReport() unexpected error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("BuildReport() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnosticContains(t, record.RuleResults, "binding proofkit.test.scenario.one omits command environmentClass=local-python")
}

func TestBuildReportRejectsBindingWithoutCommandIDs(t *testing.T) {
	input := validRequirementBindingInput()
	input["bindings"].([]any)[0].(map[string]any)["commandIds"] = []any{}

	record, exitCode, err := BuildReport(input)
	if err != nil {
		t.Fatalf("BuildReport() unexpected error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("BuildReport() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnosticContains(t, record.RuleResults, "binding proofkit.test.scenario.one must cite at least one commandId")
}

func TestBuildReportRejectsUnboundWitnessCommand(t *testing.T) {
	input := validRequirementBindingInput()
	input["witnessCommands"] = append(input["witnessCommands"].([]any), map[string]any{
		"command":          "go test ./internal/unbound",
		"commandId":        "proofkit.unbound-command",
		"environmentClass": "local-go",
	})

	record, exitCode, err := BuildReport(input)
	if err != nil {
		t.Fatalf("BuildReport() unexpected error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("BuildReport() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnosticContains(t, record.RuleResults, "witness command is not referenced by any binding commandId: proofkit.unbound-command")

	_, err = BuildWitnessPlanInput(input, map[string]any{
		"schemaVersion": json.Number("1"),
		"parallelGroups": []any{
			map[string]any{"id": "local", "maxParallel": json.Number("1")},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot project witness-plan input from failed requirement proof bindings") {
		t.Fatalf("BuildWitnessPlanInput() error=%v, want failed projection", err)
	}
}

func TestBuildReportRejectsEmptyWitnessCommandEnvironmentClasses(t *testing.T) {
	input := validRequirementBindingInput()
	input["witnessCommands"].([]any)[0].(map[string]any)["environmentClasses"] = []any{}
	delete(input["witnessCommands"].([]any)[0].(map[string]any), "environmentClass")

	_, _, err := BuildReport(input)
	if err == nil || !strings.Contains(err.Error(), "environmentClasses must be non-empty") {
		t.Fatalf("BuildReport() error=%v, want non-empty environmentClasses rejection", err)
	}
}

func TestBuildEvidenceGraphBuildsGraphAndRejectsFailedReport(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.107818454717962585697455608706257308689211271216669906752699392232450827006825")
	graph, exitCode, err := BuildEvidenceGraph(validRequirementBindingInput())
	if err != nil {
		t.Fatalf("BuildEvidenceGraph() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildEvidenceGraph() exit=%d, want 0", exitCode)
	}
	graphRecord := graph.(map[string]any)
	if graphRecord["graphKind"] != "proofkit.requirement-evidence-graph" || graphRecord["requirementCount"] != 2 {
		t.Fatalf("graph=%#v, want graph kind and two requirements", graphRecord)
	}

	input := validRequirementBindingInput()
	input["bindings"].([]any)[0].(map[string]any)["commandIds"] = []any{"proofkit.command.missing"}
	_, exitCode, err = BuildEvidenceGraph(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "cannot build evidence graph from failed requirement proof bindings") {
		t.Fatalf("BuildEvidenceGraph() exit=%d err=%v, want failed binding rejection", exitCode, err)
	}
}

func TestBuildProofSliceSelectsRequirementsAndRejectsFailedReport(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.057814514043290257871128107874680755541616706843803515635545866062242868890363")
	input := validRequirementBindingInput()
	input["selection"] = map[string]any{
		"changedPaths":   []any{},
		"ownerIds":       []any{},
		"requirementIds": []any{"REQ-PROOFKIT-ONE"},
	}

	slice, exitCode, err := BuildProofSlice(input)
	if err != nil {
		t.Fatalf("BuildProofSlice() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildProofSlice() exit=%d, want 0", exitCode)
	}
	sliceRecord := slice.(map[string]any)
	if sliceRecord["sliceKind"] != "proofkit.requirement-proof-slice" ||
		sliceRecord["selectedRequirementCount"] != 1 ||
		sliceRecord["omittedRequirementCount"] != 1 {
		t.Fatalf("slice=%#v, want one selected and one omitted requirement", sliceRecord)
	}

	input = validRequirementBindingInput()
	input["bindings"].([]any)[0].(map[string]any)["commandIds"] = []any{"proofkit.command.missing"}
	_, exitCode, err = BuildProofSlice(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "cannot build proof slice from failed requirement proof bindings") {
		t.Fatalf("BuildProofSlice() exit=%d err=%v, want failed binding rejection", exitCode, err)
	}
}

func validRequirementBindingInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"bindingId":     "proofkit.test.bindings",
		"requirements": []any{
			map[string]any{
				"claimLevel":    "blocking",
				"nonClaims":     []any{"Requirement one test fixture does not execute commands."},
				"ownerId":       "proofkit.test",
				"proofState":    "witness_backed",
				"requirementId": "REQ-PROOFKIT-ONE",
				"specPath":      "docs/specs/proofkit-test/requirements.v1.json",
			},
			map[string]any{
				"claimLevel":    "blocking",
				"nonClaims":     []any{"Requirement two test fixture does not execute commands."},
				"ownerId":       "proofkit.test",
				"proofState":    "witness_backed",
				"requirementId": "REQ-PROOFKIT-TWO",
				"specPath":      "docs/specs/proofkit-test/requirements.v1.json",
			},
		},
		"bindings": []any{
			map[string]any{
				"commandIds":         []any{"proofkit.test.command"},
				"environmentClasses": []any{"local-go"},
				"requirementId":      "REQ-PROOFKIT-ONE",
				"scenarioId":         "proofkit.test.scenario.one",
				"witnessId":          "proofkit.test.witness.one",
				"witnessKind":        "contract",
				"witnessPath":        "internal/test_one.go",
			},
			map[string]any{
				"commandIds":         []any{"proofkit.test.command"},
				"environmentClasses": []any{"local-go"},
				"requirementId":      "REQ-PROOFKIT-TWO",
				"scenarioId":         "proofkit.test.scenario.two",
				"witnessId":          "proofkit.test.witness.two",
				"witnessKind":        "contract",
				"witnessPath":        "internal/test_two.go",
			},
		},
		"witnessCommands": []any{
			map[string]any{
				"command":          "go test ./internal/test",
				"commandId":        "proofkit.test.command",
				"environmentClass": "local-go",
			},
		},
		"selection": map[string]any{
			"changedPaths":   []any{},
			"ownerIds":       []any{},
			"requirementIds": []any{},
		},
		"nonClaims": []any{"Requirement binding test input does not execute witnesses."},
	}
}

func assertRuleDiagnosticContains(t *testing.T, rules []report.RuleResult, want string) {
	t.Helper()
	for _, rule := range rules {
		if strings.Contains(rule.Message, want) {
			return
		}
		for _, diagnostic := range rule.Diagnostics {
			if text, ok := diagnostic.Value.(string); ok && strings.Contains(text, want) {
				return
			}
		}
	}
	t.Fatalf("rule diagnostics do not contain %q: %#v", want, rules)
}
