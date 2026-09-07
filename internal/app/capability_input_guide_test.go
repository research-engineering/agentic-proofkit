package app

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/capabilitymapadmission"
)

func TestCapabilityInputGuideCLI(t *testing.T) {
	var help string
	for _, args := range [][]string{
		{"capability-map-admission", "--help"},
		{"capability-map-admission", "-h"},
		{"help", "capability-map-admission"},
	} {
		status, stdout, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if status != 0 || stderr != "" || strings.Count(stdout, capabilitymapadmission.InputGuide) != 1 {
			t.Fatalf("help %v did not emit the exact owner guide: status=%d stderr=%q", args, status, stderr)
		}
		if help != "" && stdout != help {
			t.Fatal("help aliases emitted different input guides")
		}
		help = stdout
	}
	if len(help) > 12<<10 {
		t.Fatal("bounded command help exceeded 12 KiB")
	}
	for _, args := range [][]string{{"--help"}, {"self-check", "--help"}} {
		status, stdout, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if status != 0 || stderr != "" || strings.Contains(stdout, "Capability input guide:") {
			t.Fatal("on-demand examples leaked into unrelated help")
		}
	}

	examples := capabilityHelpExamples(t, help)
	for index, input := range examples {
		t.Run(fmt.Sprintf("example-%d", index), func(t *testing.T) {
			value := decodeCLIJSON(t, input).(map[string]any)
			status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"capability-map-admission", "--input", "-"}, strings.NewReader(input), PresentationCapabilities{})
			if status != 0 || stderr != "" {
				t.Fatalf("published example failed: status=%d stderr=%q stdout=%s", status, stderr, stdout)
			}
			record := decodeCLIJSON(t, stdout).(map[string]any)
			if record["reportKind"] != "proofkit.capability-map-admission" || record["reportId"] != value["mapId"] || record["state"] != "passed" {
				t.Fatalf("wrong report identity/state: %v", record)
			}
			summary := record["summary"].(map[string]any)
			wantSeeds := json.Number(fmt.Sprint(index))
			for _, key := range []string{"candidateRequirementSeedCount", "candidateProofBindingSeedCount", "scenarioAnchorCount", "verificationCommandCount"} {
				if summary[key] != wantSeeds {
					t.Fatalf("%s=%v, want %v", key, summary[key], wantSeeds)
				}
			}
			if index == 0 && summary["agentActionCount"] != json.Number("2") {
				t.Fatal("missing evidence and owner question must remain actionable")
			}
			if !strings.Contains(stdout, "candidate-only") || !strings.Contains(stdout, "does not scan repositories") {
				t.Fatal("example lost command-owned authority limits")
			}
			for _, raw := range record["diagnostics"].([]any) {
				diagnostic := raw.(map[string]any)
				if diagnostic["key"] != "candidateProofBindingSeeds" {
					continue
				}
				for _, rawSeed := range diagnostic["value"].([]any) {
					seed := rawSeed.(map[string]any)
					if seed["state"] != "candidate" || seed["executableEvidenceState"] != "candidate_executable_anchor" || seed["promotionState"] != "candidate_requires_admission" {
						t.Fatalf("baseline guide promoted evidence: %v", seed)
					}
				}
			}
		})
	}

	for _, mutation := range []struct {
		name       string
		example    int
		change     func(map[string]any)
		diagnostic string
		report     bool
	}{
		{"baseline requires evidence", 0, func(v map[string]any) { v["trustMode"] = "code_baseline" }, "active scenario anchor", true},
		{"baseline requires stable ID", 1, func(v map[string]any) { delete(capabilityHelpScenario(v), "candidateRequirementId") }, "candidateRequirementId", true},
		{"command reference must resolve", 1, func(v map[string]any) { v["requiredVerification"] = []any{} }, "reference requiredVerification", true},
		{"missing nested field", 0, func(v map[string]any) { delete(v["repository"].(map[string]any), "repositoryId") }, "repositoryId", false},
		{"nested object is not a string", 0, func(v map[string]any) { v["proofScope"] = "unknown" }, "proofScope must be an object", false},
		{"unknown nested field", 0, func(v map[string]any) { capabilityHelpScenario(v)["unrecognized"] = true }, "unsupported", false},
		{"secret-shaped text", 0, func(v map[string]any) { capabilityHelpScenario(v)["summary"] = "api_key=example-private-value" }, "secret", false},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			value := decodeCLIJSON(t, examples[mutation.example]).(map[string]any)
			mutation.change(value)
			input, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"capability-map-admission", "--input", "-"}, strings.NewReader(string(input)), PresentationCapabilities{})
			if status != 1 || !strings.Contains(stdout+stderr, mutation.diagnostic) {
				t.Fatalf("mutation not rejected by its owner: status=%d stdout=%s stderr=%s", status, stdout, stderr)
			}
			if strings.Contains(stdout+stderr, "example-private-value") {
				t.Fatal("rejected input leaked caller text")
			}
			if mutation.report {
				if stderr != "" || decodeCLIJSON(t, stdout).(map[string]any)["state"] != "failed" {
					t.Fatal("semantic failure must remain a failed report")
				}
			} else if stdout != "" || stderr == "" {
				t.Fatal("malformed input must fail without a report")
			}
		})
	}
}

func TestCapabilityInputGuideWitnessKindsCLI(t *testing.T) {
	status, help, stderr := executeAgentWorkflowCLI(t, []string{"capability-map-admission", "--help"}, panicReader{}, PresentationCapabilities{})
	if status != 0 || stderr != "" {
		t.Fatalf("command help failed: status=%d stderr=%q", status, stderr)
	}
	baseline := capabilityHelpExamples(t, help)[1]
	type witnessKinds struct {
		positive      bool
		falsification bool
	}
	for _, test := range []struct {
		name       string
		required   []any
		anchors    []witnessKinds
		diagnostic string
		wantSeeds  int
	}{
		{"non-executable anchor", []any{"negative_test"}, []witnessKinds{{}}, "requires an executable falsification witness anchor", 0},
		{"negative requires falsification", []any{"negative_test"}, []witnessKinds{{positive: true}}, "requires an executable falsification witness anchor", 0},
		{"positive requires positive", []any{"positive_test"}, []witnessKinds{{falsification: true}}, "requires an executable positive witness anchor", 0},
		{"one anchor satisfies both kinds", []any{"negative_test", "positive_test"}, []witnessKinds{{positive: true, falsification: true}}, "", 1},
		{"complementary anchors are insufficient", []any{"negative_test", "positive_test"}, []witnessKinds{{positive: true}, {falsification: true}}, "must declare an executable anchor satisfying requiredEvidence", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := decodeCLIJSON(t, baseline).(map[string]any)
			capabilityHelpScenario(value)["requiredEvidence"] = test.required
			originalAnchor := value["scenarioAnchors"].([]any)[0].(map[string]any)
			anchors := make([]any, 0, len(test.anchors))
			for index, kinds := range test.anchors {
				anchor := maps.Clone(originalAnchor)
				anchor["selector"] = fmt.Sprintf("%s::TestWitness%d", anchor["sourcePath"], index)
				anchor["positiveWitness"] = kinds.positive
				anchor["falsificationWitness"] = kinds.falsification
				anchors = append(anchors, anchor)
			}
			value["scenarioAnchors"] = anchors
			input, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"capability-map-admission", "--input", "-"}, strings.NewReader(string(input)), PresentationCapabilities{})
			wantStatus, wantState := 0, "passed"
			if test.diagnostic != "" {
				wantStatus, wantState = 1, "failed"
			}
			if status != wantStatus || stderr != "" || !strings.Contains(stdout, test.diagnostic) {
				t.Fatalf("wrong witness-kind outcome: status=%d stdout=%s stderr=%s", status, stdout, stderr)
			}
			record := decodeCLIJSON(t, stdout).(map[string]any)
			if record["reportKind"] != "proofkit.capability-map-admission" || record["reportId"] != value["mapId"] || record["state"] != wantState {
				t.Fatalf("wrong report identity/state: %v", record)
			}
			if record["summary"].(map[string]any)["candidateProofBindingSeedCount"] != json.Number(fmt.Sprint(test.wantSeeds)) {
				t.Fatal("binding count includes an ineligible anchor or omits an eligible one")
			}
			foundSeeds := false
			for _, raw := range record["diagnostics"].([]any) {
				diagnostic := raw.(map[string]any)
				if diagnostic["key"] != "candidateProofBindingSeeds" {
					continue
				}
				if foundSeeds {
					t.Fatal("binding seeds diagnostic is duplicated")
				}
				foundSeeds = true
				seeds := diagnostic["value"].([]any)
				if len(seeds) != test.wantSeeds {
					t.Fatalf("emitted %d binding seeds, want %d", len(seeds), test.wantSeeds)
				}
				if test.wantSeeds == 1 && !slices.Equal(seeds[0].(map[string]any)["witnessKinds"].([]any), []any{"positive", "falsification"}) {
					t.Fatal("eligible binding lost a required witness kind")
				}
			}
			if !foundSeeds {
				t.Fatal("binding seeds diagnostic is missing")
			}
		})
	}
}

func capabilityHelpExamples(t *testing.T, help string) []string {
	t.Helper()
	sections := strings.Split(help, "```json\n")
	if len(sections) != 3 {
		t.Fatal("help must contain two complete JSON examples")
	}
	result := make([]string, 0, 2)
	for _, section := range sections[1:] {
		input, _, ok := strings.Cut(section, "\n```")
		if !ok {
			t.Fatal("help example is not closed")
		}
		result = append(result, input)
	}
	return result
}

func capabilityHelpScenario(value map[string]any) map[string]any {
	return value["capabilities"].([]any)[0].(map[string]any)["scenarioShapes"].([]any)[0].(map[string]any)
}
