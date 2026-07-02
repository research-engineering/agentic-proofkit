package compactproofcontract

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestResolverProjectionIsColumnOrderIndependent(t *testing.T) {
	base, err := Admit(validCompactContract())
	if err != nil {
		t.Fatalf("Admit(base) error = %v", err)
	}
	shuffled, err := Admit(shuffledCompactContract())
	if err != nil {
		t.Fatalf("Admit(shuffled) error = %v", err)
	}
	baseProjection, err := base.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("ResolverProjection(base) error = %v", err)
	}
	shuffledProjection, err := shuffled.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("ResolverProjection(shuffled) error = %v", err)
	}
	if !reflect.DeepEqual(baseProjection, shuffledProjection) {
		t.Fatalf("shuffled column projection drift:\nbase=%#v\nshuffled=%#v", baseProjection, shuffledProjection)
	}
}

func TestAdmitRejectsUnknownCompactColumn(t *testing.T) {
	input := validCompactContract()
	input["binding_columns"] = append(input["binding_columns"].([]any), "unexpected_column")
	binding := input["bindings"].([]any)[0].([]any)
	input["bindings"] = []any{append(binding, "unexpected")}

	_, err := Admit(input)
	if err == nil || !strings.Contains(err.Error(), "unknown projection column") {
		t.Fatalf("Admit() error=%v, want unknown column rejection", err)
	}
}

func TestAdmittedContractIsIndependentFromRawMutation(t *testing.T) {
	input := validCompactContract()
	contract, err := Admit(input)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	input["non_claims"].([]any)[0] = "Mutated non-claim."
	input["bindings"].([]any)[0].([]any)[10] = []any{"go test ./mutated"}

	projection, err := contract.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("ResolverProjection() error = %v", err)
	}
	requirement := projection["requirements"].([]any)[0].(map[string]any)
	commands := requirement["verifyCommands"].([]any)
	if len(commands) != 1 || commands[0] != "go test ./..." {
		t.Fatalf("admitted contract changed after raw mutation: %v", commands)
	}
	nonClaims := projection["nonClaims"].([]any)
	for _, value := range nonClaims {
		if value == "Mutated non-claim." {
			t.Fatalf("admitted nonClaims changed after raw mutation: %v", nonClaims)
		}
	}
}

func TestConformanceProjectionUsesAdmittedCompactFacts(t *testing.T) {
	contract, err := Admit(validCompactContract())
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	projection := contract.ConformanceProjection()
	bindings := projection["bindings"].([]any)
	if len(bindings) != 1 {
		t.Fatalf("binding count=%d, want 1", len(bindings))
	}
	binding := bindings[0].(map[string]any)
	if binding["requirementId"] != "REQ-PROOFKIT-COMPACT-001" || binding["surfaceId"] != "proofkit.surface" {
		t.Fatalf("binding identity drift: %#v", binding)
	}
	witnessRefs := binding["witnessRefs"].([]any)
	if len(witnessRefs) != 2 {
		t.Fatalf("witnessRefs=%#v, want positive and falsification", witnessRefs)
	}
	if witnessRefs[0].(map[string]any)["role"] != "falsification" || witnessRefs[1].(map[string]any)["role"] != "positive" {
		t.Fatalf("witnessRef role order drift: %#v", witnessRefs)
	}
}

func TestFalsificationRoutesUseFalsificationWitnessCommands(t *testing.T) {
	input := validCompactContract()
	binding := input["bindings"].([]any)[0].([]any)
	binding[10] = []any{"go test ./binding"}
	binding[9] = witnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("1"), "go test ./negative")

	contract, err := Admit(input)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	routes := contract.FalsificationRoutes()
	if len(routes) != 1 {
		t.Fatalf("route count=%d, want 1", len(routes))
	}
	if !reflect.DeepEqual(routes[0].VerifyCommands, []string{"go test ./negative"}) {
		t.Fatalf("VerifyCommands=%v, want falsification witness commands", routes[0].VerifyCommands)
	}
}

func TestResolverProjectionPreservesWitnessCommandsAndSurfaceOnlyEnvironments(t *testing.T) {
	input := validCompactContract()
	input["surfaces"] = []any{[]any{"proofkit.surface", []any{"local-go"}, []any{"live-db"}}}
	binding := input["bindings"].([]any)[0].([]any)
	binding[10] = []any{"go test ./binding"}
	binding[8] = witnessRow("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("0"), "go test ./positive")
	binding[9] = witnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("1"), "go test ./negative")

	contract, err := Admit(input)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	projection, err := contract.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("ResolverProjection() error = %v", err)
	}
	commands := projection["commands"].([]any)
	if got := commandRefs(commands); !reflect.DeepEqual(got, []string{"go test ./binding", "go test ./negative", "go test ./positive"}) {
		t.Fatalf("command refs=%v", got)
	}
	negative := commandByRef(commands, "go test ./negative")
	if selectors := stringValues(negative["witnessSelectors"].([]any)); !reflect.DeepEqual(selectors, []string{"tests/proofkit_falsification_test.go::TestRejectsCompactRegression"}) {
		t.Fatalf("negative witnessSelectors=%v", selectors)
	}
	environments := projection["environmentClasses"].([]any)
	live := environmentByClass(environments, "live-db")
	if !reflect.DeepEqual(stringValues(live["surfaceIds"].([]any)), []string{"proofkit.surface"}) {
		t.Fatalf("live-db surfaceIds=%v", live["surfaceIds"])
	}
	if len(live["requirementIds"].([]any)) != 0 || len(live["witnessSelectors"].([]any)) != 0 {
		t.Fatalf("surface-only live-db should not invent requirement/witness refs: %#v", live)
	}
}

func TestAdmitRejectsDuplicateCompactIdentities(t *testing.T) {
	input := validCompactContract()
	binding := append([]any{}, input["bindings"].([]any)[0].([]any)...)
	input["bindings"] = []any{input["bindings"].([]any)[0], binding}

	_, err := Admit(input)
	if err == nil || !strings.Contains(err.Error(), "binding identity") {
		t.Fatalf("Admit() error=%v, want duplicate binding identity rejection", err)
	}
}

func TestAdmitRejectsNumericDriftOnContractFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "float schema version",
			mutate: func(input map[string]any) {
				input["schema_version"] = float64(1)
			},
			want: "schema_version",
		},
		{
			name: "float witness order",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[8] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", float64(1))
			},
			want: "resolution_order_index",
		},
		{
			name: "fractional witness order",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[8] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("1.5"))
			},
			want: "resolution_order_index",
		},
		{
			name: "overflow witness order",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[8] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("90071992547409931234567890"))
			},
			want: "resolution_order_index",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validCompactContract()
			item.mutate(input)
			_, err := Admit(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Admit() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestAdmitRejectsUnsafeWitnessSelectorSourcePaths(t *testing.T) {
	for _, selector := range []string{
		"../tests/proofkit_positive_test.go::TestAcceptsCompactContract",
		"/abs/tests/proofkit_positive_test.go::TestAcceptsCompactContract",
		"file:tests/proofkit_positive_test.go::TestAcceptsCompactContract",
	} {
		t.Run(selector, func(t *testing.T) {
			input := validCompactContract()
			binding := input["bindings"].([]any)[0].([]any)
			binding[8] = witnessRow(selector, json.Number("0"))
			_, err := Admit(input)
			if err == nil || !strings.Contains(err.Error(), "source path") {
				t.Fatalf("Admit() error=%v, want source path rejection", err)
			}
		})
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
				witnessRow("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("0")),
				witnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("1")),
				[]any{"go test ./..."},
				"no_known_advisory_gap",
			},
		},
	}
}

func shuffledCompactContract() map[string]any {
	return map[string]any{
		"schema_version":        json.Number("1"),
		"authority_state":       "canonical",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_binding",
		"normalization_profile": "proofkit.compact.v1",
		"non_claims":            []any{"Compact test input does not execute witnesses."},
		"surface_columns":       []any{"preconditioned_environment_classes", "surface_id", "required_environment_classes"},
		"surfaces":              []any{[]any{[]any{}, "proofkit.surface", []any{"local-go"}}},
		"witness_columns":       []any{"resolution_order_index", "verify_commands", "selector", "environment_classes"},
		"binding_columns":       []any{"mutation_resistance_state", "verify_commands", "falsification_witness", "positive_witness", "required_environment_classes", "blocking_status", "proof_contract_state", "owned_invariant", "invariant_role", "scenario_id", "surface_id", "requirement_id"},
		"bindings": []any{
			[]any{
				"no_known_advisory_gap",
				[]any{"go test ./..."},
				shuffledWitnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("1")),
				shuffledWitnessRow("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("0")),
				[]any{"local-go"},
				"blocking",
				"witness_backed",
				"proofkit.compact",
				"contract",
				"proofkit.surface::scenario.compact",
				"proofkit.surface",
				"REQ-PROOFKIT-COMPACT-001",
			},
		},
	}
}

func witnessRow(selector string, order json.Number, commands ...string) []any {
	return witnessRowWithRawOrder(selector, order, commands...)
}

func witnessRowWithRawOrder(selector string, order any, commands ...string) []any {
	if len(commands) == 0 {
		commands = []string{"go test ./..."}
	}
	values := make([]any, len(commands))
	for index, command := range commands {
		values[index] = command
	}
	return []any{selector, []any{"local-go"}, values, order}
}

func shuffledWitnessRow(selector string, order json.Number, commands ...string) []any {
	if len(commands) == 0 {
		commands = []string{"go test ./..."}
	}
	values := make([]any, len(commands))
	for index, command := range commands {
		values[index] = command
	}
	return []any{order, values, selector, []any{"local-go"}}
}

func commandRefs(commands []any) []string {
	result := make([]string, 0, len(commands))
	for _, value := range commands {
		result = append(result, value.(map[string]any)["verifyCommandRef"].(string))
	}
	return result
}

func stringValues(values []any) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.(string)
	}
	return result
}

func commandByRef(commands []any, ref string) map[string]any {
	for _, value := range commands {
		command := value.(map[string]any)
		if command["verifyCommandRef"] == ref {
			return command
		}
	}
	return nil
}

func environmentByClass(environments []any, class string) map[string]any {
	for _, value := range environments {
		environment := value.(map[string]any)
		if environment["environmentClass"] == class {
			return environment
		}
	}
	return nil
}
