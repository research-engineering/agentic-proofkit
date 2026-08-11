package requirementbinding

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildResolverPreservesDeclaredMutationResistanceClaim(t *testing.T) {
	output, exitCode, err := BuildResolver(validCompactContract(), ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("BuildResolver() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildResolver() exitCode=%d, want 0", exitCode)
	}
	binding := output.(map[string]any)["bindings"].([]any)[0].(map[string]any)
	if binding["declaredMutationResistanceClaimId"] != "claim.no_known_advisory_gap" {
		t.Fatalf("declaredMutationResistanceClaimId=%v", binding["declaredMutationResistanceClaimId"])
	}
	if _, exists := binding["mutationResistanceContext"]; exists {
		t.Fatalf("binding must not project assurance-shaped mutationResistanceContext: %#v", binding)
	}
}

func TestBuildResolverEmitsNamedLookupFacts(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.111196201832829118735064910982698751650497890612272762431668463661114699885279")
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
	binding := record["bindings"].([]any)[0].(map[string]any)
	if values := strings.Join(stringValues(command["bindingRecordIds"].([]any)), ","); values != binding["bindingRecordId"] {
		t.Fatalf("command bindingRecordIds=%s", values)
	}
	environmentClasses := record["environmentClasses"].([]any)
	if len(environmentClasses) != 1 {
		t.Fatalf("environmentClasses=%#v, want one class fact", environmentClasses)
	}
	environment := environmentClasses[0].(map[string]any)
	if environment["environmentClass"] != "local-go" {
		t.Fatalf("environmentClass=%v", environment["environmentClass"])
	}
	if routeIDs := stringValues(environment["witnessRouteIds"].([]any)); len(routeIDs) != 2 || routeIDs[0] == routeIDs[1] {
		t.Fatalf("environment witnessRouteIds=%#v, want two role-distinct routes", routeIDs)
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

func TestBuildResolverRejectsCompactBindingWithoutDeclaredMutationClaimColumn(t *testing.T) {
	input := validCompactContract()
	input["binding_columns"] = []any{
		"requirement_id",
		"surface_id",
		"scenario_id",
		"invariant_role",
		"owned_invariant",
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
			"blocking",
			[]any{"local-go"},
			compactWitnessRow(),
			compactWitnessRow(),
			[]any{"go test ./..."},
		},
	}

	_, exitCode, err := BuildResolver(input, ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "declared_mutation_resistance_claim_id") {
		t.Fatalf("BuildResolver() exitCode=%d err=%v, want missing declared_mutation_resistance_claim_id", exitCode, err)
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
	binding[9] = []any{"go test ./... && curl https://example.invalid"}

	_, exitCode, err := BuildResolver(input, ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("BuildResolver() exitCode=%d err=%v, want display-only command rejection", exitCode, err)
	}
}

func TestBuildResolverRejectsUnscopedCompactIdentity(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.076041686007458666270617161270722640013102244122307015251002781061987907765701")
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
	}{{index: 7, role: "positive"}, {index: 8, role: "falsification"}} {
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
		"schema_version":        json.Number("2"),
		"authority_state":       "caller_owned_declaration",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_route_declaration",
		"normalization_profile": "proofkit.compact.declaration.v2",
		"non_claims":            []any{"Compact test input does not execute witnesses."},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.surface", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"},
		"bindings": []any{
			[]any{
				"REQ-PROOFKIT-COMPACT-001",
				"proofkit.surface",
				"proofkit.surface::scenario.compact",
				"contract",
				"proofkit.compact",
				"blocking",
				[]any{"local-go"},
				compactWitnessRow(),
				compactWitnessRow(),
				[]any{"go test ./..."},
				"claim.no_known_advisory_gap",
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
