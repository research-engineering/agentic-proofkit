package requirementbinding

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildResolverPreservesCompactMutationResistanceState(t *testing.T) {
	output, exitCode, err := BuildResolver(validCompactContract(), ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("BuildResolver() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildResolver() exitCode=%d, want 0", exitCode)
	}
	requirements := output.(map[string]any)["requirements"].([]any)
	context := requirements[0].(map[string]any)["mutationResistanceContext"].(map[string]any)
	if context["mutationResistanceState"] != "no_known_advisory_gap" {
		t.Fatalf("mutationResistanceState=%v", context["mutationResistanceState"])
	}
}

func TestBuildResolverEmitsNamedLookupFacts(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.079097784231569243123760864431497247802974951490040482853947549382894609207552")
	output, exitCode, err := BuildResolver(validCompactContract(), ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("BuildResolver() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildResolver() exitCode=%d, want 0", exitCode)
	}
	record := output.(map[string]any)
	commands := record["commands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("commands=%#v, want one command fact", commands)
	}
	command := commands[0].(map[string]any)
	if command["verifyCommandRef"] != "go test ./..." {
		t.Fatalf("verifyCommandRef=%v", command["verifyCommandRef"])
	}
	if values := strings.Join(stringValues(command["requirementIds"].([]any)), ","); values != "REQ-PROOFKIT-COMPACT-001" {
		t.Fatalf("command requirementIds=%s", values)
	}
	environmentClasses := record["environmentClasses"].([]any)
	if len(environmentClasses) != 1 {
		t.Fatalf("environmentClasses=%#v, want one class fact", environmentClasses)
	}
	environment := environmentClasses[0].(map[string]any)
	if environment["environmentClass"] != "local-go" {
		t.Fatalf("environmentClass=%v", environment["environmentClass"])
	}
	if selectors := strings.Join(stringValues(environment["witnessSelectors"].([]any)), ","); selectors != "tests/proofkit_test.go::TestCompact" {
		t.Fatalf("environment witnessSelectors=%s", selectors)
	}
	conformance := record["conformanceProofContract"].(map[string]any)
	if conformance["contractId"] != "proofkit.test.compact" {
		t.Fatalf("conformance contractId=%v", conformance["contractId"])
	}
	conformanceSurfaces := conformance["surfaces"].([]any)
	if len(conformanceSurfaces) != 1 {
		t.Fatalf("conformance surfaces=%#v, want one surface", conformanceSurfaces)
	}
	conformanceSurface := conformanceSurfaces[0].(map[string]any)
	if conformanceSurface["surfaceId"] != "proofkit.surface" {
		t.Fatalf("conformance surfaceId=%v", conformanceSurface["surfaceId"])
	}
	conformanceBindings := conformance["bindings"].([]any)
	if len(conformanceBindings) != 1 {
		t.Fatalf("conformance bindings=%#v, want one binding", conformanceBindings)
	}
	witnessRefs := conformanceBindings[0].(map[string]any)["witnessRefs"].([]any)
	if got := len(witnessRefs); got != 2 {
		t.Fatalf("conformance witnessRefs=%d, want 2", got)
	}
}

func TestBuildResolverRejectsCompactBindingWithoutMutationResistanceColumn(t *testing.T) {
	input := validCompactContract()
	input["binding_columns"] = []any{
		"requirement_id",
		"surface_id",
		"scenario_id",
		"invariant_role",
		"owned_invariant",
		"proof_contract_state",
		"blocking_status",
		"required_environment_classes",
		"positive_witness",
		"falsification_witness",
		"verify_commands",
	}
	input["bindings"] = []any{
		[]any{
			"REQ-PROOFKIT-COMPACT-001",
			"proofkit.surface",
			"scenario.compact",
			"contract",
			"proofkit.compact",
			"witness_backed",
			"blocking",
			[]any{"local-go"},
			compactWitnessRow(),
			compactWitnessRow(),
			[]any{"go test ./..."},
		},
	}

	_, exitCode, err := BuildResolver(input, ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "mutation_resistance_state") {
		t.Fatalf("BuildResolver() exitCode=%d err=%v, want missing mutation_resistance_state", exitCode, err)
	}
}

func TestBuildResolverRejectsCompactDiscriminatorDrift(t *testing.T) {
	cases := []struct {
		field string
		value string
		want  string
	}{
		{field: "authority_state", value: "advisory", want: "authority_state"},
		{field: "contract_kind", value: "other_contract", want: "contract_kind"},
		{field: "normalization_profile", value: "other.profile", want: "normalization_profile"},
	}
	for _, item := range cases {
		t.Run(item.field, func(t *testing.T) {
			input := validCompactContract()
			input[item.field] = item.value
			_, exitCode, err := BuildResolver(input, ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
			if exitCode != 1 || err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("BuildResolver() exitCode=%d err=%v, want %s discriminator rejection", exitCode, err, item.want)
			}
		})
	}
}

func TestBuildResolverRejectsCompactSecretLikeText(t *testing.T) {
	input := validCompactContract()
	input["non_claims"] = []any{"Authorization: Bearer abcdefghijklmnop"}

	_, exitCode, err := BuildResolver(input, ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "secret-like") {
		t.Fatalf("BuildResolver() exitCode=%d err=%v, want secret-like rejection", exitCode, err)
	}
}

func TestBuildResolverRejectsCompactShellControlCommandText(t *testing.T) {
	input := validCompactContract()
	binding := input["bindings"].([]any)[0].([]any)
	binding[10] = []any{"go test ./... && curl https://example.invalid"}

	_, exitCode, err := BuildResolver(input, ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("BuildResolver() exitCode=%d err=%v, want display-only command rejection", exitCode, err)
	}
}

func TestBuildResolverRejectsUnscopedCompactIdentity(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.069762921155265534833897611463817586909954409189497461749409846690639299144534")
	type selectorCase struct {
		name   string
		mutate func(map[string]any)
		want   string
	}
	cases := []selectorCase{
		{
			name: "scenario not scoped to surface",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[2] = "scenario.compact"
			},
			want: "surface_id::stable_anchor",
		},
		{
			name: "scenario scoped to another surface",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[2] = "other.surface::scenario.compact"
			},
			want: "scoped under surface_id",
		},
	}
	for _, witness := range []struct {
		index int
		role  string
	}{{index: 8, role: "positive"}, {index: 9, role: "falsification"}} {
		cases = append(cases,
			selectorCase{
				name: witness.role + " selector without anchor",
				mutate: func(input map[string]any) {
					mutateWitnessSelector(input, witness.index, "tests/proofkit_test.go")
				},
				want: "repo/path::stable_anchor",
			},
			selectorCase{
				name: witness.role + " unsafe selector path",
				mutate: func(input map[string]any) {
					mutateWitnessSelector(input, witness.index, "../proofkit_test.go::TestCompact")
				},
				want: "escape the repository root",
			},
			selectorCase{
				name: witness.role + " invalid selector anchor",
				mutate: func(input map[string]any) {
					mutateWitnessSelector(input, witness.index, "tests/proofkit_test.go::bad anchor")
				},
				want: "stable rule identifier",
			},
		)
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validCompactContract()
			item.mutate(input)
			_, exitCode, err := BuildResolver(input, ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
			if exitCode != 1 || err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("BuildResolver() exitCode=%d err=%v, want %q", exitCode, err, item.want)
			}
		})
	}
}

func mutateWitnessSelector(input map[string]any, witnessIndex int, selector string) {
	binding := input["bindings"].([]any)[0].([]any)
	witness := binding[witnessIndex].([]any)
	witness[0] = selector
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
				compactWitnessRow(),
				compactWitnessRow(),
				[]any{"go test ./..."},
				"no_known_advisory_gap",
			},
		},
	}
}

func compactWitnessRow() []any {
	return []any{"tests/proofkit_test.go::TestCompact", []any{"local-go"}, []any{"go test ./..."}, json.Number("0")}
}

func stringValues(values []any) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.(string)
	}
	return result
}
