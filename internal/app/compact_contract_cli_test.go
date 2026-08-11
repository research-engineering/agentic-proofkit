package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestCompactV2PublicCLIResolverAndBrowserRoutes(t *testing.T) {
	compactInput := compactCLIInput(t)

	resolver := runCLIForJSON(t, []string{
		"requirement-proof-resolver", "--input", "-", "--local-environment-class", "local-go",
	}, compactInput)
	if resolver["schemaVersion"] != json.Number("2") || resolver["contractId"] != "proofkit.cli.compact" {
		t.Fatalf("resolver identity=%#v, want compact v2", resolver)
	}
	policy := resolver["localEnvironmentPolicy"].(map[string]any)
	if got := policy["localEnvironmentClasses"].([]any); len(got) != 1 || got[0] != "local-go" {
		t.Fatalf("resolver local environment policy=%#v", policy)
	}
	routes := resolver["witnessRoutes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("resolver witnessRoutes=%#v, want two", routes)
	}
	for _, raw := range routes {
		route := raw.(map[string]any)
		expected, err := compactproofcontract.WitnessRouteID(
			route["bindingRecordId"].(string), route["role"].(string), route["selector"].(string),
		)
		if err != nil {
			t.Fatalf("derive route id: %v", err)
		}
		if route["witnessRouteId"] != expected {
			t.Fatalf("resolver route identity drift: %#v", route)
		}
	}

	proofPlan := runCLIForJSON(t, []string{
		"requirement-browser-server", "--input", "-", "--view", "proof", "--local-environment-class", "local-go",
	}, compactInput)
	if proofPlan["view"] != "proof" || proofPlan["renderedViewKind"] != "proofkit.compact-requirement-proof-view" {
		t.Fatalf("proof browser plan routed incorrectly: %#v", proofPlan)
	}

	coverageInput := runCLIForJSON(t, []string{"requirement-coverage-input-compose", "--input", "-"}, cliCoverageInputComposeInput())
	coveragePlan := runCLIForJSON(t, []string{"requirement-browser-server", "--input", "-", "--view", "coverage"}, cliJSON(coverageInput))
	if coveragePlan["view"] != "coverage" || coveragePlan["renderedViewKind"] != "proofkit.requirement-coverage-view" {
		t.Fatalf("coverage browser plan routed incorrectly: %#v", coveragePlan)
	}
}

func TestRequirementProofSourceSetCLIRejectsLegacyWrapper(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"requirement-proof-source-set", "--input", "-"}, strings.NewReader(`{"schemaVersion":1}`), &stdout, &stderr)
	if status == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "schemaVersion must be 2") {
		t.Fatalf("legacy source-set CLI status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestImpactCLIRejectsUnsafeResolutionOrderWithoutStdout(t *testing.T) {
	fixture := strings.Replace(
		cliImpactInputComposeInput(),
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json"]`,
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json","internal/app/cli_abi_test.go"]`,
		1,
	)
	composed := runCLIForJSON(t, []string{"requirement-impact-input-compose", "--input", "-"}, fixture)
	coverage := composed["changedWitnessPathCoverage"].([]any)
	if len(coverage) == 0 {
		t.Fatal("impact compose fixture has no witness coverage")
	}
	routes := coverage[0].(map[string]any)["routes"].([]any)
	if len(routes) == 0 {
		t.Fatal("impact compose fixture has no witness routes")
	}
	routes[0].(map[string]any)["resolutionOrderIndex"] = json.Number("9007199254740992")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"impact", "--input", "-"}, strings.NewReader(cliJSON(composed)), &stdout, &stderr)
	if status == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "JSON-safe non-negative integer") {
		t.Fatalf("unsafe impact order status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestCompactV2ComposeImpactPilotRoundTrip(t *testing.T) {
	fixture := strings.Replace(
		cliImpactInputComposeInput(),
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json"]`,
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json","internal/app/cli_abi_test.go"]`,
		1,
	)
	composed := runCLIForJSON(t, []string{"requirement-impact-input-compose", "--input", "-"}, fixture)
	coverage := composed["changedWitnessPathCoverage"].([]any)
	if len(coverage) != 1 || len(coverage[0].(map[string]any)["routes"].([]any)) != 2 {
		t.Fatalf("composed impact witness routes=%#v want two role-qualified routes", coverage)
	}
	pilot := cliPilotInput("proofkit.cli.compact-round-trip", false)
	demo := pilot["impactDemos"].([]any)[0].(map[string]any)
	demo["impactInput"] = composed
	demo["sourceOwnedChangedPaths"] = []any{"docs/specs/proofkit-cli-impact/requirements.v1.json"}
	report := runCLIForJSON(t, []string{"pilot-admission", "--input", "-"}, cliJSON(pilot))
	if report["state"] != "passed" {
		t.Fatalf("pilot report=%#v want passed compose -> impact -> pilot route", report)
	}
}

func TestCompactV2PublicCLIRejectsParentLegacyAndNestedShapeMutants(t *testing.T) {
	compact := strictJSONObjectFromText(t, compactCLIInput(t), "compact CLI input")
	impactCompose := strictJSONObjectFromText(t, cliImpactInputComposeInput(), "impact compose CLI input")
	impactDirect := runCLIForJSON(t, []string{"requirement-impact-input-compose", "--input", "-"}, cliJSON(impactCompose))
	coverageCompose := strictJSONObjectFromText(t, cliCoverageInputComposeInput(), "coverage compose CLI input")
	coverageView := runCLIForJSON(t, []string{"requirement-coverage-input-compose", "--input", "-"}, cliJSON(coverageCompose))

	type ingressCase struct {
		args        []string
		input       map[string]any
		legacy      func(map[string]any)
		name        string
		requiredKey string
		target      func(*testing.T, map[string]any) map[string]any
	}
	schemaV1 := func(input map[string]any) { input["schemaVersion"] = json.Number("1") }
	compactV1 := func(input map[string]any) { input["schema_version"] = json.Number("1") }
	cases := []ingressCase{
		{
			name: "adoption aggregate", args: []string{"adoption-contract-envelope", "--input", "-", "--mode", "pilot", "--pilot", "all"},
			input:  strictJSONObjectFromText(t, cliAdoptionContractEnvelopeInput(), "adoption aggregate CLI input"),
			legacy: func(input map[string]any) { input["schema"] = "proofkit.adoption-contract-envelope.v1" },
			target: func(t *testing.T, input map[string]any) map[string]any { return jsonObjectField(t, input, "pilot") }, requiredKey: "schema",
		},
		{
			name: "conformance profile", args: []string{"conformance-profile", "--input", "-", "--profile", "local"},
			input: strictJSONObjectFromText(t, cliConformanceProfileInput(), "conformance profile CLI input"), legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any {
				return jsonObjectField(t, input, "proofContract")
			}, requiredKey: "declarationKind",
		},
		{
			name: "impact", args: []string{"impact", "--input", "-"}, input: impactDirect, legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any {
				return firstObjectField(t, input, "obligationCatalog")
			}, requiredKey: "bindingRecordId",
		},
		{
			name: "pilot direct", args: []string{"pilot-admission", "--input", "-"},
			input: cliPilotInput("proofkit.cli.compact-negative.direct", false), legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any {
				return jsonObjectField(t, firstObjectField(t, input, "impactDemos"), "impactInput")
			}, requiredKey: "schemaVersion",
		},
		{
			name: "pilot envelope", args: []string{"pilot-admission", "--input", "-", "--contract-envelope", "--pilot", "all"},
			input:  strictJSONObjectFromText(t, cliPilotContractEnvelopeInput("all"), "pilot envelope CLI input"),
			legacy: func(input map[string]any) { input["schema"] = "proofkit.pilot-admission.v1" },
			target: func(t *testing.T, input map[string]any) map[string]any { return jsonObjectField(t, input, "input") }, requiredKey: "schemaVersion",
		},
		{
			name: "coverage compose", args: []string{"requirement-coverage-input-compose", "--input", "-"}, input: coverageCompose, legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any {
				return jsonObjectField(t, input, "compactProofContract")
			}, requiredKey: "contract_kind",
		},
		{
			name: "coverage view", args: []string{"requirement-coverage-view", "--input", "-", "--format", "json"}, input: coverageView, legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any {
				return jsonObjectField(t, input, "compactProofContract")
			}, requiredKey: "contract_kind",
		},
		{
			name: "impact compose", args: []string{"requirement-impact-input-compose", "--input", "-"}, input: impactCompose, legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any {
				return jsonObjectField(t, input, "baseCompactProofContract")
			}, requiredKey: "contract_kind",
		},
		{
			name: "proof resolver", args: []string{"requirement-proof-resolver", "--input", "-", "--local-environment-class", "local-go"}, input: compact, legacy: compactV1,
			target: func(_ *testing.T, input map[string]any) map[string]any { return input }, requiredKey: "contract_kind",
		},
		{
			name: "proof source set", args: []string{"requirement-proof-source-set", "--input", "-"}, input: cliProofSourceSetInput(t, "canonical_contract"), legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any { return jsonObjectField(t, input, "sourceSet") }, requiredKey: "contract_id",
		},
		{
			name: "proof view", args: []string{"requirement-proof-view", "--input", "-", "--format", "json", "--local-environment-class", "local-go"}, input: compact, legacy: compactV1,
			target: func(_ *testing.T, input map[string]any) map[string]any { return input }, requiredKey: "contract_kind",
		},
		{
			name: "browser proof view", args: []string{"requirement-browser-server", "--input", "-", "--view", "proof", "--local-environment-class", "local-go"}, input: compact, legacy: compactV1,
			target: func(_ *testing.T, input map[string]any) map[string]any { return input }, requiredKey: "contract_kind",
		},
		{
			name: "proof-binding inventory", args: []string{"test-evidence-inventory", "--input", "-", "--projection", "proof-binding-derived", "--normalized-inventory"},
			input: strictJSONObjectFromText(t, cliProofBindingDerivedInventoryInput(), "proof-binding inventory CLI input"), legacy: schemaV1,
			target: func(t *testing.T, input map[string]any) map[string]any {
				return jsonObjectField(t, input, "compactProofContract")
			}, requiredKey: "contract_kind",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assertCLIInputAdmitted(t, test.args, test.input)
			mutations := []struct {
				apply func(map[string]any)
				name  string
			}{
				{name: "legacy-v1", apply: test.legacy},
				{name: "missing-nested-key", apply: func(input map[string]any) {
					delete(test.target(t, input), test.requiredKey)
				}},
				{name: "surplus-nested-key", apply: func(input map[string]any) {
					test.target(t, input)["unexpectedCompactField"] = "not admitted"
				}},
				{name: "renamed-nested-key", apply: func(input map[string]any) {
					target := test.target(t, input)
					target[test.requiredKey+"Renamed"] = target[test.requiredKey]
					delete(target, test.requiredKey)
				}},
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					mutant := strictJSONObjectFromText(t, cliJSON(test.input), test.name+" mutant source")
					mutation.apply(mutant)
					assertCLIInputRejected(t, test.args, mutant)
				})
			}
		})
	}
}

func TestCompactV2PublicCLIRejectsFullLegacyNestedPayloads(t *testing.T) {
	old := readCompactV1WireObservations(t)
	compactV1 := jsonObject(t, old[compactWireObservationKey("compact-contract", "input", "direct")])
	impactV1 := jsonObject(t, old[compactWireObservationKey("impact", "input", "direct")])
	conformanceV1 := jsonObjectField(t, jsonObject(t, old[compactWireObservationKey("conformance-profile", "input", "direct")]), "proofContract")
	sourceV1 := jsonObject(t, old[compactWireObservationKey("requirement-proof-source-set", "input", "wrapper")])
	coverageCompose := strictJSONObjectFromText(t, cliCoverageInputComposeInput(), "current coverage compose input")
	coverageView := runCLIForJSON(t, []string{"requirement-coverage-input-compose", "--input", "-"}, cliJSON(coverageCompose))
	impactCompose := strictJSONObjectFromText(t, cliImpactInputComposeInput(), "current impact compose input")

	tests := []struct {
		args   []string
		input  map[string]any
		mutate func(*testing.T, map[string]any)
		name   string
		want   string
	}{
		{
			name: "coverage compose compact child", args: []string{"requirement-coverage-input-compose", "--input", "-"}, input: coverageCompose,
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, input, "compactProofContract"), compactV1)
			},
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "coverage view compact child", args: []string{"requirement-coverage-view", "--input", "-", "--format", "json"}, input: coverageView,
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, input, "compactProofContract"), compactV1)
			},
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "impact compose base compact child", args: []string{"requirement-impact-input-compose", "--input", "-"}, input: impactCompose,
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, input, "baseCompactProofContract"), compactV1)
			},
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "impact compose current compact child", args: []string{"requirement-impact-input-compose", "--input", "-"}, input: impactCompose,
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, input, "currentCompactProofContract"), compactV1)
			},
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "proof resolver compact root", args: []string{"requirement-proof-resolver", "--input", "-", "--local-environment-class", "local-go"},
			input: compactV2WireContract(), mutate: func(_ *testing.T, input map[string]any) { replaceJSONObject(input, compactV1) },
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "proof view compact root", args: []string{"requirement-proof-view", "--input", "-", "--format", "json", "--local-environment-class", "local-go"},
			input: compactV2WireContract(), mutate: func(_ *testing.T, input map[string]any) { replaceJSONObject(input, compactV1) },
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "browser proof compact root", args: []string{"requirement-browser-server", "--input", "-", "--view", "proof", "--local-environment-class", "local-go"},
			input: compactV2WireContract(), mutate: func(_ *testing.T, input map[string]any) { replaceJSONObject(input, compactV1) },
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "inventory compact child", args: []string{"test-evidence-inventory", "--input", "-", "--projection", "proof-binding-derived", "--normalized-inventory"},
			input: strictJSONObjectFromText(t, cliProofBindingDerivedInventoryInput(), "current proof-binding inventory input"),
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, input, "compactProofContract"), compactV1)
			},
			want: "compact requirement proof contract schema_version must be 2",
		},
		{
			name: "conformance proof child", args: []string{"conformance-profile", "--input", "-", "--profile", "local"},
			input: strictJSONObjectFromText(t, cliConformanceProfileInput(), "current conformance input"),
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, input, "proofContract"), conformanceV1)
			},
			want: "conformance proof contract schemaVersion must be 2",
		},
		{
			name: "source set canonical child", args: []string{"requirement-proof-source-set", "--input", "-"}, input: cliProofSourceSetInput(t, "canonical_contract"),
			mutate: func(t *testing.T, input map[string]any) {
				input["canonicalEnvelope"] = cloneJSONForCLI(t, sourceV1["canonicalEnvelope"])
				input["sourceSet"] = cloneJSONForCLI(t, sourceV1["sourceSet"])
				input["sources"] = cloneJSONForCLI(t, sourceV1["sources"])
			},
			want: "requirement proof route declaration canonical envelope schemaVersion must be 2",
		},
		{
			name: "pilot direct impact child", args: []string{"pilot-admission", "--input", "-"}, input: cliPilotInput("proofkit.cli.compact-negative.direct-child", false),
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, firstObjectField(t, input, "impactDemos"), "impactInput"), impactV1)
			},
			want: "proof impact report input has unsupported field(s): changedRecordIds",
		},
		{
			name: "pilot envelope impact child", args: []string{"pilot-admission", "--input", "-", "--contract-envelope", "--pilot", "all"},
			input: strictJSONObjectFromText(t, cliPilotContractEnvelopeInput("all"), "current pilot envelope input"),
			mutate: func(t *testing.T, input map[string]any) {
				replaceJSONObject(jsonObjectField(t, firstObjectField(t, jsonObjectField(t, input, "input"), "impactDemos"), "impactInput"), impactV1)
			},
			want: "proof impact report input has unsupported field(s): changedRecordIds",
		},
		{
			name: "adoption aggregate impact child", args: []string{"adoption-contract-envelope", "--input", "-", "--mode", "pilot", "--pilot", "all"},
			input: strictJSONObjectFromText(t, cliAdoptionContractEnvelopeInput(), "current adoption aggregate input"),
			mutate: func(t *testing.T, input map[string]any) {
				pilot := jsonObjectField(t, input, "pilot")
				replaceJSONObject(jsonObjectField(t, firstObjectField(t, jsonObjectField(t, pilot, "input"), "impactDemos"), "impactInput"), impactV1)
			},
			want: "proof impact report input has unsupported field(s): changedRecordIds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCLIInputAdmitted(t, test.args, test.input)
			mutant := jsonObject(t, cloneJSONForCLI(t, test.input))
			test.mutate(t, mutant)
			assertCLIInputRejectedWith(t, test.args, mutant, test.want)
		})
	}
}

func firstObjectField(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	values := jsonArrayField(t, object, key)
	if len(values) == 0 {
		t.Fatalf("%s must contain at least one object", key)
	}
	return jsonObject(t, values[0])
}

func assertCLIInputAdmitted(t *testing.T, args []string, input map[string]any) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), args, strings.NewReader(cliJSON(input)), &stdout, &stderr)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("valid Run(%v) status=%d stderr=%q stdout=%q", args, status, stderr.String(), stdout.String())
	}
	if _, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), int64(stdout.Len())); err != nil {
		t.Fatalf("valid Run(%v) did not emit an admitted JSON result: %v; stdout=%q", args, err, stdout.String())
	}
}

func assertCLIInputRejected(t *testing.T, args []string, input map[string]any) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), args, strings.NewReader(cliJSON(input)), &stdout, &stderr)
	if status == 0 || stderr.Len() == 0 || stdout.Len() != 0 {
		t.Fatalf("mutant Run(%v) status=%d stderr=%q stdout=%q", args, status, stderr.String(), stdout.String())
	}
}

func assertCLIInputRejectedWith(t *testing.T, args []string, input map[string]any, want string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), args, strings.NewReader(cliJSON(input)), &stdout, &stderr)
	if status == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), want) {
		t.Fatalf("mutant Run(%v) status=%d stderr=%q stdout=%q; want diagnostic %q", args, status, stderr.String(), stdout.String(), want)
	}
}

func replaceJSONObject(target, source map[string]any) {
	for key := range target {
		delete(target, key)
	}
	for key, value := range source {
		target[key] = value
	}
}

func cloneJSONForCLI(t *testing.T, value any) any {
	t.Helper()
	content, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatalf("encode CLI clone: %v", err)
	}
	cloned, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("decode CLI clone: %v", err)
	}
	return cloned
}

func compactCLIInput(t *testing.T) string {
	t.Helper()
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cliProofBindingDerivedInventoryInput()), &wrapper); err != nil {
		t.Fatalf("decode compact CLI wrapper: %v", err)
	}
	value, ok := wrapper["compactProofContract"]
	if !ok {
		t.Fatal("compact CLI wrapper lacks compactProofContract")
	}
	return string(value)
}

func runCLIForJSON(t *testing.T, args []string, input string) map[string]any {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), args, strings.NewReader(input), &stdout, &stderr)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("Run(%v) status=%d stderr=%q stdout=%q", args, status, stderr.String(), stdout.String())
	}
	value, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), int64(stdout.Len()))
	if err != nil {
		t.Fatalf("decode Run(%v) output: %v", args, err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("Run(%v) output=%T, want object", args, value)
	}
	return record
}
