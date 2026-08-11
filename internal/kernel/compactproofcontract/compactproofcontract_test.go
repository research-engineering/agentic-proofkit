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

func TestResolverProjectionRejectsSecretLikeLocalEnvironmentClass(t *testing.T) {
	contract, err := Admit(validCompactContract())
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	secret := "api_key=environment-secret-sentinel"
	_, err = contract.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{secret}})
	if err == nil || !strings.Contains(err.Error(), "must not contain secret-like values") {
		t.Fatalf("ResolverProjection() error=%v, want secret-like environment rejection", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "environment-secret-sentinel") {
		t.Fatalf("ResolverProjection() leaked local environment value: %v", err)
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

func TestAdmitRejectsLegacyProofStateColumn(t *testing.T) {
	input := validCompactContract()
	input["binding_columns"] = append(input["binding_columns"].([]any), "proof_contract_state")
	input["bindings"].([]any)[0] = append(input["bindings"].([]any)[0].([]any), "witness_backed")

	_, err := Admit(input)
	if err == nil || !strings.Contains(err.Error(), "unknown projection column") {
		t.Fatalf("Admit() error=%v, want legacy proof-state column rejection", err)
	}
}

func TestAdmitRejectsCompactV1(t *testing.T) {
	input := validCompactContract()
	input["schema_version"] = json.Number("1")
	input["authority_state"] = "canonical"
	input["contract_kind"] = "requirement_proof_binding"
	input["normalization_profile"] = "proofkit.compact.v1"

	_, err := Admit(input)
	if err == nil || !strings.Contains(err.Error(), "schema_version must be 2") {
		t.Fatalf("Admit() error=%v, want compact v1 rejection", err)
	}
}

func TestAdmitScenarioIDOwnsScopedIdentityGrammar(t *testing.T) {
	scenarioID, surfaceID, err := AdmitScenarioID("proofkit.coverage::scenario", "scenarioId")
	if err != nil {
		t.Fatalf("AdmitScenarioID() error=%v", err)
	}
	if scenarioID != "proofkit.coverage::scenario" || surfaceID != "proofkit.coverage" {
		t.Fatalf("AdmitScenarioID()=(%q,%q), want exact scoped identity", scenarioID, surfaceID)
	}
	if _, _, err := AdmitScenarioID("unscoped-scenario", "scenarioId"); err == nil {
		t.Fatal("AdmitScenarioID() admitted an unscoped identity")
	}
}

func TestAdmittedContractIsIndependentFromRawMutation(t *testing.T) {
	input := validCompactContract()
	contract, err := Admit(input)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	input["non_claims"].([]any)[0] = "Mutated non-claim."
	input["bindings"].([]any)[0].([]any)[9] = []any{"go test ./mutated"}

	projection, err := contract.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("ResolverProjection() error = %v", err)
	}
	binding := projection["bindings"].([]any)[0].(map[string]any)
	commands := binding["verifyCommands"].([]any)
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

func TestAdmittedContractAccessorsReturnIndependentCopies(t *testing.T) {
	contract, err := Admit(validCompactContract())
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	bindings := contract.Bindings()
	bindings[0].scenarioID = "proofkit.surface::mutated"
	bindings[0].positiveWitness.selector = "tests/mutated.go::TestMutated"
	bindings[0].verifyCommands[0] = "go test ./mutated"
	surfaces := contract.Surfaces()
	surfaces[0].requiredEnvironmentClasses[0] = "mutated-environment"
	nonClaims := contract.NonClaims()
	nonClaims[0] = "Mutated non-claim."

	projection, err := contract.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("ResolverProjection() error = %v", err)
	}
	binding := projection["bindings"].([]any)[0].(map[string]any)
	if binding["scenarioId"] == "proofkit.surface::mutated" {
		t.Fatal("accessor mutation changed admitted scenario identity")
	}
	if binding["verifyCommands"].([]any)[0] != "go test ./..." {
		t.Fatalf("accessor mutation changed admitted commands: %#v", binding["verifyCommands"])
	}
	if contract.ContractID() != "proofkit.test.compact" {
		t.Fatalf("ContractID()=%q, want admitted id", contract.ContractID())
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
	if witnessRefs[0].(map[string]any)["resolutionOrderIndex"] != 1 || witnessRefs[1].(map[string]any)["resolutionOrderIndex"] != 0 {
		t.Fatalf("witnessRef resolution order drift: %#v", witnessRefs)
	}
}

func TestConformanceProjectionChangesWithWitnessResolutionOrder(t *testing.T) {
	baseline, err := Admit(validCompactContract())
	if err != nil {
		t.Fatalf("Admit(baseline) error=%v", err)
	}
	changedInput := validCompactContract()
	binding := changedInput["bindings"].([]any)[0].([]any)
	binding[7] = witnessRow("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("8"))
	binding[8] = witnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("9"))
	changed, err := Admit(changedInput)
	if err != nil {
		t.Fatalf("Admit(changed) error=%v", err)
	}

	if reflect.DeepEqual(baseline.ConformanceProjection(), changed.ConformanceProjection()) {
		t.Fatal("order-only witness mutation did not change conformance projection")
	}
}

func TestFalsificationRoutesUseFalsificationWitnessCommands(t *testing.T) {
	input := validCompactContract()
	binding := input["bindings"].([]any)[0].([]any)
	binding[9] = []any{"go test ./binding"}
	binding[8] = witnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("1"), "go test ./negative")

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
	if routes[0].ResolutionOrderIndex != 1 {
		t.Fatalf("ResolutionOrderIndex=%d, want 1", routes[0].ResolutionOrderIndex)
	}
}

func TestResolverProjectionPreservesWitnessCommandsAndSurfaceOnlyEnvironments(t *testing.T) {
	input := validCompactContract()
	input["surfaces"] = []any{[]any{"proofkit.surface", []any{"local-go"}, []any{"live-db"}}}
	binding := input["bindings"].([]any)[0].([]any)
	binding[9] = []any{"go test ./binding"}
	binding[7] = witnessRow("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("0"), "go test ./positive")
	binding[8] = witnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("1"), "go test ./negative")

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
	routeIDs := stringValues(negative["witnessRouteIds"].([]any))
	if len(routeIDs) != 1 {
		t.Fatalf("negative witnessRouteIds=%v", routeIDs)
	}
	route := witnessRouteByID(projection["witnessRoutes"].([]any), routeIDs[0])
	if route["role"] != FalsificationWitnessRole || route["selector"] != "tests/proofkit_falsification_test.go::TestRejectsCompactRegression" {
		t.Fatalf("negative witness route drift: %#v", route)
	}
	environments := projection["environmentClasses"].([]any)
	live := environmentByClass(environments, "live-db")
	if !reflect.DeepEqual(stringValues(live["surfaceIds"].([]any)), []string{"proofkit.surface"}) {
		t.Fatalf("live-db surfaceIds=%v", live["surfaceIds"])
	}
	if len(live["bindingRecordIds"].([]any)) != 0 || len(live["witnessRouteIds"].([]any)) != 0 {
		t.Fatalf("surface-only live-db should not invent requirement/witness refs: %#v", live)
	}
}

func TestStableIdentityKnownAnswerAndSameSelectorRoles(t *testing.T) {
	input := validCompactContract()
	binding := input["bindings"].([]any)[0].([]any)
	sharedSelector := "tests/proofkit_routes_test.go::TestProofRouteTable"
	binding[7] = witnessRow(sharedSelector, json.Number("0"), "go test ./positive")
	binding[8] = witnessRow(sharedSelector, json.Number("1"), "go test ./negative")

	contract, err := Admit(input)
	if err != nil {
		t.Fatalf("Admit() error=%v", err)
	}
	bindings := contract.Bindings()
	if got := bindings[0].RecordID(); got != "sha256:3e12335736f4aae18fc88fa1b7d704a77dbdbb7889ab6584f792adf43eb3e803" {
		t.Fatalf("binding record id=%s", got)
	}
	routes, err := bindings[0].WitnessRoutes()
	if err != nil {
		t.Fatalf("WitnessRoutes() error=%v", err)
	}
	if len(routes) != 2 || routes[0].Role != FalsificationWitnessRole || routes[1].Role != PositiveWitnessRole {
		t.Fatalf("witness routes=%#v", routes)
	}
	if routes[0].Selector != sharedSelector || routes[1].Selector != sharedSelector || routes[0].RouteID == routes[1].RouteID {
		t.Fatalf("same-selector role identity collapsed: %#v", routes)
	}

	knownRouteID, err := WitnessRouteID(bindings[0].RecordID(), PositiveWitnessRole, "tests/proofkit_positive_test.go::TestAcceptsCompactContract")
	if err != nil {
		t.Fatalf("WitnessRouteID() error=%v", err)
	}
	if knownRouteID != "sha256:23e2c5c66d485bd4bc3fe051283f2fbd752d55e827e26f7564e3903a49d8753a" {
		t.Fatalf("positive witness route id=%s", knownRouteID)
	}
}

func TestColumnAccessorsDoNotMutateOwnerGrammar(t *testing.T) {
	surfaceColumns := SurfaceColumns()
	bindingColumns := BindingColumns()
	witnessColumns := WitnessColumns()
	surfaceColumns[0] = "mutated_surface"
	bindingColumns[0] = "mutated_binding"
	witnessColumns[0] = "mutated_witness"

	if _, err := Admit(validCompactContract()); err != nil {
		t.Fatalf("Admit() changed after accessor mutation: %v", err)
	}
	if SurfaceColumns()[0] != "surface_id" || BindingColumns()[0] != "requirement_id" || WitnessColumns()[0] != "selector" {
		t.Fatal("column accessor mutation changed owner grammar")
	}
}

func TestIdentityHelpersRejectMalformedCoordinates(t *testing.T) {
	for _, identity := range []BindingIdentity{
		{},
		{RequirementID: "REQ-VALID", SurfaceID: "proofkit.surface", ScenarioID: "other.surface::scenario"},
	} {
		if _, err := BindingRecordID(identity); err == nil {
			t.Fatalf("BindingRecordID(%#v) accepted malformed identity", identity)
		}
	}
	if _, err := WitnessRouteID("not-a-digest", PositiveWitnessRole, "tests/example_test.go::TestExample"); err == nil {
		t.Fatal("WitnessRouteID() accepted malformed binding record id")
	}
	if _, err := WitnessRouteID("sha256:"+strings.Repeat("0", 64), PositiveWitnessRole, "not-a-selector"); err == nil {
		t.Fatal("WitnessRouteID() accepted malformed selector")
	}
}

func TestResolverPreservesTwoScenariosForOneRequirement(t *testing.T) {
	input := validCompactContract()
	second := append([]any{}, input["bindings"].([]any)[0].([]any)...)
	second[2] = "proofkit.surface::scenario.second"
	second[4] = "proofkit.compact.second"
	second[7] = witnessRow("tests/proofkit_second_test.go::TestPositive", json.Number("2"))
	second[8] = witnessRow("tests/proofkit_second_test.go::TestFalsification", json.Number("3"))
	input["bindings"] = append(input["bindings"].([]any), second)

	contract, err := Admit(input)
	if err != nil {
		t.Fatalf("Admit() error=%v", err)
	}
	projection, err := contract.ResolverProjection(ResolverOptions{})
	if err != nil {
		t.Fatalf("ResolverProjection() error=%v", err)
	}
	bindings := projection["bindings"].([]any)
	routes := projection["witnessRoutes"].([]any)
	if len(bindings) != 2 || len(routes) != 4 {
		t.Fatalf("binding/route cardinality drift: bindings=%d routes=%d", len(bindings), len(routes))
	}
	if bindings[0].(map[string]any)["bindingRecordId"] == bindings[1].(map[string]any)["bindingRecordId"] {
		t.Fatalf("two scenarios collapsed to one binding identity: %#v", bindings)
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

func TestAdmitProjectedResolutionOrderIndexPreservesWireOwner(t *testing.T) {
	got, err := AdmitProjectedResolutionOrderIndex(json.Number("9007199254740991"), "projected order")
	if err != nil || int64(got) != maxJSONSafeInteger {
		t.Fatalf("AdmitProjectedResolutionOrderIndex(json.Number)=%d, %v", got, err)
	}
	got, err = AdmitProjectedResolutionOrderIndex(int(7), "projected order")
	if err != nil || got != 7 {
		t.Fatalf("AdmitProjectedResolutionOrderIndex(int)=%d, %v", got, err)
	}
	for _, value := range []any{json.Number("9007199254740992"), int64(1), float64(1)} {
		if _, err := AdmitProjectedResolutionOrderIndex(value, "projected order"); err == nil {
			t.Fatalf("AdmitProjectedResolutionOrderIndex(%T) accepted %v", value, value)
		}
	}
}

func TestAdmitRejectsNonCanonicalJSONIntegerLexemes(t *testing.T) {
	for _, value := range []json.Number{"+1", "01", "-0"} {
		if _, err := AdmitResolutionOrderIndex(value, "resolution order"); err == nil {
			t.Fatalf("AdmitResolutionOrderIndex(%q) accepted non-canonical JSON integer", value)
		}
	}
	for _, value := range []json.Number{"0", "1", "9007199254740991"} {
		if _, err := AdmitResolutionOrderIndex(value, "resolution order"); err != nil {
			t.Fatalf("AdmitResolutionOrderIndex(%q) error=%v", value, err)
		}
	}
}

func TestResolverPreconditionedIncludesWitnessEnvironments(t *testing.T) {
	input := validCompactContract()
	binding := input["bindings"].([]any)[0].([]any)
	positive := binding[7].([]any)
	positive[1] = []any{"remote-ci"}

	contract, err := Admit(input)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := contract.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatal(err)
	}
	projected := projection["bindings"].([]any)[0].(map[string]any)
	if projected["preconditioned"] != true {
		t.Fatalf("route-only remote environment preconditioned=%v, want true", projected["preconditioned"])
	}

	projection, err = contract.ResolverProjection(ResolverOptions{LocalEnvironmentClasses: []string{"local-go", "remote-ci"}})
	if err != nil {
		t.Fatal(err)
	}
	projected = projection["bindings"].([]any)[0].(map[string]any)
	if projected["preconditioned"] != false {
		t.Fatalf("fully local route environment preconditioned=%v, want false", projected["preconditioned"])
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
				input["schema_version"] = float64(2)
			},
			want: "schema_version",
		},
		{
			name: "float witness order",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[7] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", float64(1))
			},
			want: "resolution_order_index",
		},
		{
			name: "fractional witness order",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[7] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("1.5"))
			},
			want: "resolution_order_index",
		},
		{
			name: "JSON-unsafe witness order",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[7] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("9007199254740992"))
			},
			want: "resolution_order_index",
		},
		{
			name: "overflow witness order",
			mutate: func(input map[string]any) {
				binding := input["bindings"].([]any)[0].([]any)
				binding[7] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("90071992547409931234567890"))
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

func TestAdmitAcceptsMaximumJSONSafeWitnessOrder(t *testing.T) {
	input := validCompactContract()
	binding := input["bindings"].([]any)[0].([]any)
	binding[7] = witnessRowWithRawOrder("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("9007199254740991"))

	contract, err := Admit(input)
	if err != nil {
		t.Fatalf("Admit() error=%v", err)
	}
	if got := contract.Bindings()[0].PositiveWitness().ResolutionOrderIndex(); int64(got) != maxJSONSafeInteger {
		t.Fatalf("ResolutionOrderIndex()=%d, want 9007199254740991", got)
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
			binding[7] = witnessRow(selector, json.Number("0"))
			_, err := Admit(input)
			if err == nil || !strings.Contains(err.Error(), "source path") {
				t.Fatalf("Admit() error=%v, want source path rejection", err)
			}
		})
	}
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
		"schema_version":        json.Number("2"),
		"authority_state":       "caller_owned_declaration",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_route_declaration",
		"normalization_profile": "proofkit.compact.declaration.v2",
		"non_claims":            []any{"Compact test input does not execute witnesses."},
		"surface_columns":       []any{"preconditioned_environment_classes", "surface_id", "required_environment_classes"},
		"surfaces":              []any{[]any{[]any{}, "proofkit.surface", []any{"local-go"}}},
		"witness_columns":       []any{"resolution_order_index", "verify_commands", "selector", "environment_classes"},
		"binding_columns":       []any{"declared_mutation_resistance_claim_id", "verify_commands", "falsification_witness", "positive_witness", "required_environment_classes", "blocking_status", "owned_invariant", "invariant_role", "scenario_id", "surface_id", "requirement_id"},
		"bindings": []any{
			[]any{
				"no_known_advisory_gap",
				[]any{"go test ./..."},
				shuffledWitnessRow("tests/proofkit_falsification_test.go::TestRejectsCompactRegression", json.Number("1")),
				shuffledWitnessRow("tests/proofkit_positive_test.go::TestAcceptsCompactContract", json.Number("0")),
				[]any{"local-go"},
				"blocking",
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

func witnessRouteByID(routes []any, id string) map[string]any {
	for _, value := range routes {
		route := value.(map[string]any)
		if route["witnessRouteId"] == id {
			return route
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
