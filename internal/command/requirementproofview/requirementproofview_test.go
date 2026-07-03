package requirementproofview

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestBuildHTMLIncludesStructuredScenarioWitnessDetails(t *testing.T) {
	output, exitCode, err := BuildHTML(validStructuredBindingInput(), Options{Scope: "graph"})
	if err != nil {
		t.Fatalf("BuildHTML() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildHTML() exitCode=%d, want 0", exitCode)
	}
	for _, want := range []string{
		"Scenarios and test witnesses",
		"proofkit.test.scenario.one",
		"proofkit.test.witness.one",
		"contract",
		"internal/test_one.go",
		"proofkit.test.command",
		"local-go",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("BuildHTML() output missing structured proof detail %q:\n%s", want, output)
		}
	}
}

func TestBuildHTMLIncludesCompactScenarioWitnessDetails(t *testing.T) {
	input := validCompactContract()
	view, exitCode, err := BuildJSON(input, Options{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildJSON() exitCode=%d, want 0", exitCode)
	}
	requirement := view.(map[string]any)["requirements"].([]any)[0].(map[string]any)
	positive := requirement["positiveWitness"].(map[string]any)
	falsification := requirement["falsificationWitness"].(map[string]any)
	if positive["selector"] != "tests/positive_proof_test.go::TestPositiveProof" {
		t.Fatalf("positive selector=%v", positive["selector"])
	}
	if falsification["selector"] != "tests/falsification_proof_test.go::TestFalsificationProof" {
		t.Fatalf("falsification selector=%v", falsification["selector"])
	}
	if strings.Join(stringArray(positive["verifyCommands"]), "\n") == strings.Join(stringArray(falsification["verifyCommands"]), "\n") {
		t.Fatalf("positive and falsification commands should be distinct: %#v", requirement)
	}

	output, exitCode, err := BuildHTML(input, Options{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("BuildHTML() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildHTML() exitCode=%d, want 0", exitCode)
	}
	for _, want := range []string{
		"Scenario and test witnesses",
		"proofkit.surface::scenario.compact",
		"Positive witness",
		"Falsification witness",
		"tests/positive_proof_test.go::TestPositiveProof",
		"tests/falsification_proof_test.go::TestFalsificationProof",
		"go test ./... -run TestPositiveProof",
		"go test ./... -run TestFalsificationProof",
		"local-go",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("BuildHTML() output missing compact proof detail %q:\n%s", want, output)
		}
	}
}

func TestBuildHTMLEscapesCallerControlledStructuredFields(t *testing.T) {
	input := validStructuredBindingInput()
	input["requirements"].([]any)[0].(map[string]any)["nonClaims"] = []any{"<script>alert(1)</script><img src=x>"}

	output, exitCode, err := BuildHTML(input, Options{Scope: "graph"})
	if err != nil {
		t.Fatalf("BuildHTML() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildHTML() exitCode=%d, want 0", exitCode)
	}
	for _, forbidden := range []string{"<script>alert(1)</script>", "<img src=x"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("BuildHTML() output contains raw HTML payload %q:\n%s", forbidden, output)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x&gt;"} {
		if !strings.Contains(output, want) {
			t.Fatalf("BuildHTML() output missing escaped payload %q:\n%s", want, output)
		}
	}
}

func TestBuildHTMLEscapesCallerControlledCompactFields(t *testing.T) {
	output, exitCode, err := BuildHTML(maliciousCompactContract(), Options{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("BuildHTML() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildHTML() exitCode=%d, want 0", exitCode)
	}
	for _, forbidden := range []string{"<script>alert(1)</script>", "<img src=x"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("BuildHTML() output contains raw HTML payload %q:\n%s", forbidden, output)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;"} {
		if !strings.Contains(output, want) {
			t.Fatalf("BuildHTML() output missing escaped payload %q:\n%s", want, output)
		}
	}
}

func TestBuildMarkdownEscapesCallerControlledCompactFields(t *testing.T) {
	output, exitCode, err := BuildMarkdown(maliciousCompactContract(), Options{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("BuildMarkdown() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildMarkdown() exitCode=%d, want 0", exitCode)
	}
	for _, forbidden := range []string{"<script>", "<img", "`docs/\\`evil\\`.go`", "\n# forged heading", "![x](", "| a | b |"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("BuildMarkdown() output contains unescaped payload %q:\n%s", forbidden, output)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert\\(1\\)&lt;/script&gt;", "``docs/`evil`.go::TestEvil``", "\\# forged heading", "\\!\\[x\\]", "\\| a \\| b \\|"} {
		if !strings.Contains(output, want) {
			t.Fatalf("BuildMarkdown() output missing escaped payload %q:\n%s", want, output)
		}
	}
}

func validStructuredBindingInput() map[string]any {
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

func validCompactContract() map[string]any {
	return map[string]any{
		"schema_version":        json.Number("1"),
		"authority_state":       "canonical",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_binding",
		"normalization_profile": "proofkit.compact.v1",
		"non_claims":            []any{"Compact test input does not execute witnesses."},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.surface", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "proof_contract_state", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "mutation_resistance_state"},
		"bindings": []any{
			[]any{
				"REQ-PROOFKIT-COMPACT-001",
				"proofkit.surface",
				"proofkit.surface::scenario.compact",
				"contract",
				"proofkit.compact",
				"witness_backed",
				"blocking",
				[]any{"local-go"},
				validCompactWitnessRow("tests/positive_proof_test.go::TestPositiveProof", "go test ./... -run TestPositiveProof", 0),
				validCompactWitnessRow("tests/falsification_proof_test.go::TestFalsificationProof", "go test ./... -run TestFalsificationProof", 1),
				[]any{"go test ./... -run TestPositiveProof", "go test ./... -run TestFalsificationProof"},
				"no_known_advisory_gap",
			},
		},
	}
}

func validCompactWitnessRow(selector string, command string, order int) []any {
	return []any{selector, []any{"local-go"}, []any{command}, json.Number(strconv.Itoa(order))}
}

func maliciousCompactContract() map[string]any {
	return map[string]any{
		"schema_version":        json.Number("1"),
		"authority_state":       "canonical",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_binding",
		"normalization_profile": "proofkit.compact.v1",
		"non_claims":            []any{"<script>alert(1)</script><img src=x onerror=alert(1)>\n# forged heading\n![x](https://example.test/x)\n| a | b |"},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.surface", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "proof_contract_state", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "mutation_resistance_state"},
		"bindings": []any{
			[]any{
				"REQ-PROOFKIT-COMPACT-001",
				"proofkit.surface",
				"proofkit.surface::scenario.escape",
				"contract",
				"proofkit.compact",
				"witness_backed",
				"blocking",
				[]any{"local-go"},
				[]any{"docs/`evil`.go::TestEvil", []any{"local-go"}, []any{"go test ./..."}, json.Number("0")},
				[]any{"docs/`evil`.go::TestEvil", []any{"local-go"}, []any{"go test ./..."}, json.Number("1")},
				[]any{"go test ./..."},
				"no_known_advisory_gap",
			},
		},
	}
}
