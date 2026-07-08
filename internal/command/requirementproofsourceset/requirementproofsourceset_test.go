package requirementproofsourceset

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestParseJSONObjectRejectsAmbiguousSourceText(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "duplicate key", input: `{"contract_id":"one","contract_id":"two"}`, want: "duplicate object key"},
		{name: "trailing value", input: `{"contract_id":"one"} {"contract_id":"two"}`, want: "multiple JSON values"},
		{name: "array", input: `[]`, want: "must be a JSON object"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := parseJSONObject(item.input, "source text")
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("parseJSONObject() error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildCombinesCanonicalSourceAndRejectsSHADrift(t *testing.T) {
	input := validSourceSetInput(t)

	combined, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit=%d, want 0", exitCode)
	}
	output := combined.(map[string]any)
	if output["sourceCount"] != 1 {
		t.Fatalf("sourceCount=%v, want 1", output["sourceCount"])
	}

	drifted := validSourceSetInput(t)
	drifted["sourceSet"].(map[string]any)["sources"].([]any)[0].([]any)[2] = strings.Repeat("0", 64)
	_, _, err = Build(drifted)
	if err == nil || !strings.Contains(err.Error(), "sha256 drift") {
		t.Fatalf("Build() error=%v, want sha256 drift", err)
	}
}

func TestBuildSelectsSourceSetRowsAndEmitsResolverInput(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.103606270231233266473620303120670087653439368563763197580781857201403855835422")
	input := validFragmentSourceSetInput(t)
	input["projection"] = map[string]any{
		"kind":              "resolver_input",
		"selectedSourceIds": []any{"source.beta", "source.alpha"},
	}

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit=%d, want 0", exitCode)
	}
	record := output.(map[string]any)
	if _, ok := record["contract"]; ok {
		t.Fatalf("resolver projection must not duplicate canonical contract payload")
	}
	if record["projectionKind"] != "proofkit.requirement-proof-source-set.resolver_input" {
		t.Fatalf("projectionKind=%v, want resolver input", record["projectionKind"])
	}
	if record["sourceCount"] != 2 || record["sourceSetCount"] != 2 {
		t.Fatalf("source counts=%v/%v, want 2/2", record["sourceCount"], record["sourceSetCount"])
	}
	if got := record["selectedSourceIds"]; !equalAnyStringSlice(got, []string{"source.alpha", "source.beta"}) {
		t.Fatalf("selectedSourceIds=%v, want source-set order alpha,beta", got)
	}
	resolverInput := record["resolverInput"].(map[string]any)
	if resolverInput["contract_kind"] != "requirement_proof_binding" {
		t.Fatalf("resolverInput contract_kind=%v, want requirement_proof_binding", resolverInput["contract_kind"])
	}
	if got := resolverInput["surface_columns"]; !equalAnyStringSlice(got, []string{"surface_id", "required_environment_classes", "preconditioned_environment_classes"}) {
		t.Fatalf("resolverInput surface_columns=%v", got)
	}
	if got := resolverInput["surface_columns"]; !equalAnyStringSlice(got, compactproofcontract.SurfaceColumns) {
		t.Fatalf("resolverInput surface_columns drifted from compact owner=%v", got)
	}
	rows := resolverInput["bindings"].([]any)
	if got := []any{rows[0].([]any)[0], rows[1].([]any)[0]}; !equalAnyStringSlice(got, []string{"REQ-PROOFKIT-ALPHA-001", "REQ-PROOFKIT-BETA-001"}) {
		t.Fatalf("resolverInput requirement order=%v, want source-set order", got)
	}
	if _, exitCode, err := requirementbinding.BuildResolver(resolverInput, requirementbinding.ResolverOptions{}); err != nil || exitCode != 0 {
		t.Fatalf("BuildResolver(resolverInput) exit=%d err=%v, want accepted resolver projection", exitCode, err)
	}
}

func TestBuildAllowsUnselectedKnownSourceTextsAndRejectsUnknownSourceText(t *testing.T) {
	input := validFragmentSourceSetInput(t)
	input["projection"] = map[string]any{
		"kind":              "resolver_input",
		"selectedSourceIds": []any{"source.beta"},
	}

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() with unselected known source text error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit=%d, want 0", exitCode)
	}
	record := output.(map[string]any)
	if record["sourceCount"] != 1 || record["sourceSetCount"] != 2 {
		t.Fatalf("source counts=%v/%v, want 1/2", record["sourceCount"], record["sourceSetCount"])
	}
	if got := record["inputPaths"]; !equalAnyStringSlice(got, []string{"docs/contracts/requirement-proof-bindings/beta.v1.json"}) {
		t.Fatalf("inputPaths=%v, want selected source path only", got)
	}
	resolverInput := record["resolverInput"].(map[string]any)
	rows := resolverInput["bindings"].([]any)
	if len(rows) != 1 || rows[0].([]any)[0] != "REQ-PROOFKIT-BETA-001" {
		t.Fatalf("resolverInput bindings=%v, want beta row only", rows)
	}
	surfaces := resolverInput["surfaces"].([]any)
	if len(surfaces) != 1 || surfaces[0].([]any)[0] != "source.beta" {
		t.Fatalf("resolverInput surfaces=%v, want beta surface only", surfaces)
	}
	if _, exitCode, err := requirementbinding.BuildResolver(resolverInput, requirementbinding.ResolverOptions{}); err != nil || exitCode != 0 {
		t.Fatalf("BuildResolver(selected resolverInput) exit=%d err=%v, want accepted beta-only projection", exitCode, err)
	}

	ignored := validFragmentSourceSetInput(t)
	ignored["projection"] = map[string]any{
		"kind":              "resolver_input",
		"selectedSourceIds": []any{"source.beta"},
	}
	ignored["sources"].([]any)[0].(map[string]any)["text"] = "not json but unselected"
	if _, exitCode, err := Build(ignored); err != nil || exitCode != 0 {
		t.Fatalf("Build() with invalid unselected source text exit=%d err=%v, want unselected text unused", exitCode, err)
	}

	rejected := validFragmentSourceSetInput(t)
	rejected["sources"] = append(rejected["sources"].([]any), map[string]any{
		"path": "docs/contracts/requirement-proof-bindings/extra.v1.json",
		"text": `{"contract_id":"unused"}`,
	})
	_, _, err = Build(rejected)
	if err == nil || !strings.Contains(err.Error(), "source text is not referenced by source set") {
		t.Fatalf("Build() error=%v, want unreferenced source text rejection", err)
	}
}

func TestBuildRejectsInvalidProjectionAndSourceIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "duplicate selected source id",
			mutate: func(input map[string]any) {
				input["projection"] = map[string]any{"selectedSourceIds": []any{"source.alpha", "source.alpha"}}
			},
			want: "duplicate requirement proof binding selected source_id",
		},
		{
			name: "missing selected source id",
			mutate: func(input map[string]any) {
				input["projection"] = map[string]any{"selectedSourceIds": []any{"source.missing"}}
			},
			want: "does not contain selected source_id",
		},
		{
			name: "empty selected source ids",
			mutate: func(input map[string]any) {
				input["projection"] = map[string]any{"selectedSourceIds": []any{}}
			},
			want: "must be a non-empty array when provided",
		},
		{
			name: "unsupported projection kind",
			mutate: func(input map[string]any) {
				input["projection"] = map[string]any{"kind": "repository_scan"}
			},
			want: "projection.kind",
		},
		{
			name: "unsupported projection field",
			mutate: func(input map[string]any) {
				input["projection"] = map[string]any{"kind": "resolver_input", "extra": true}
			},
			want: "unsupported field",
		},
		{
			name: "secret shaped selected source id",
			mutate: func(input map[string]any) {
				input["projection"] = map[string]any{"selectedSourceIds": []any{"ghp_secretvalue"}}
			},
			want: "must not contain secret-like values",
		},
		{
			name: "secret shaped source id",
			mutate: func(input map[string]any) {
				input["sourceSet"].(map[string]any)["sources"].([]any)[0].([]any)[0] = "ghp_secretvalue"
			},
			want: "must not contain secret-like values",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validFragmentSourceSetInput(t)
			item.mutate(input)
			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildRejectsNestedSourceSetPayload(t *testing.T) {
	input := validSourceSetInput(t)
	sourceSetText := compactJSON(t, input["sourceSet"])
	input["sourceSet"].(map[string]any)["sources"].([]any)[0].([]any)[2] = sha256Hex(sourceSetText)
	input["sources"].([]any)[0].(map[string]any)["text"] = sourceSetText

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "must not reference another source set") {
		t.Fatalf("Build() error=%v, want nested source-set rejection", err)
	}
}

func TestBuildInflatesFragmentV2Defaults(t *testing.T) {
	input := validFragmentSourceSetInput(t)
	input["projection"] = map[string]any{
		"kind":              "canonical_contract",
		"selectedSourceIds": []any{"source.beta"},
	}

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit=%d, want 0", exitCode)
	}
	contract := output.(map[string]any)["contract"].(map[string]any)
	rows := contract["bindings"].([]any)
	if len(rows) != 1 {
		t.Fatalf("binding count=%d, want 1", len(rows))
	}
	row := rows[0].([]any)
	if row[1] != "source.beta" || row[2] != "source.beta::beta_invariant" {
		t.Fatalf("v2 defaults surface/scenario=%v/%v, want source.beta/source.beta::beta_invariant", row[1], row[2])
	}
	positive := row[8].([]any)
	if got := positive[1]; !equalAnyStringSlice(got, []string{"local-go"}) {
		t.Fatalf("v2 positive environment classes=%v, want inherited local-go", got)
	}
	if got := positive[2]; !equalAnyStringSlice(got, []string{"go test ./..."}) {
		t.Fatalf("v2 positive verify commands=%v, want inherited command", got)
	}
}

func validSourceSetInput(t *testing.T) map[string]any {
	t.Helper()
	envelope := validCanonicalEnvelope()
	contract := canonicalContract(envelope, []any{
		[]any{
			"surface.local",
			[]any{"unit"},
			false,
			"not_allowed",
			"none",
			[]any{"local-go"},
			[]any{},
			"checked",
		},
	}, []any{
		[]any{
			"REQ-PROOFKIT-001",
			"surface.local",
			"surface.local::proofkit.scenario",
			"contract",
			"owned_invariant",
			"witness_backed",
			"blocking",
			[]any{"local-go"},
			[]any{"internal/test.go::TestPositive", []any{"local-go"}, []any{"go test ./..."}, json.Number("0")},
			[]any{"internal/test.go::TestNegative", []any{"local-go"}, []any{"go test ./..."}, json.Number("1")},
			[]any{"go test ./..."},
			"checked",
		},
	})
	text := compactJSON(t, contract)
	return map[string]any{
		"canonicalEnvelope": map[string]any{
			"schemaVersion":        json.Number("1"),
			"contractKind":         envelope.ContractKind,
			"contractId":           envelope.ContractID,
			"authorityState":       envelope.AuthorityState,
			"normalizationProfile": envelope.NormalizationProfile,
			"nonClaims":            stringSliceToAny(envelope.NonClaims),
			"surfaceColumns":       stringSliceToAny(envelope.SurfaceColumns),
			"bindingColumns":       stringSliceToAny(envelope.BindingColumns),
			"witnessColumns":       stringSliceToAny(envelope.WitnessColumns),
		},
		"sourceSet": map[string]any{
			"schema_version":        json.Number("1"),
			"contract_kind":         "requirement_proof_binding_source_set",
			"contract_id":           "requirement-proof-bindings/source-set/v1",
			"authority_state":       "requirement_proof_binding_source_index",
			"normalization_profile": "json/v1:utf8+lf+ordered-source-refs",
			"source_columns":        stringSliceToAny(sourceSetColumns),
			"sources": []any{
				[]any{
					"source.local",
					"docs/contracts/requirement-proof-bindings/local.v1.json",
					sha256Hex(text),
					"requirement_proof_binding_contract",
					[]any{"Source-set test input is not repository proof."},
				},
			},
			"non_claims": []any{"Source set test input does not prove repository coverage."},
		},
		"sources": []any{
			map[string]any{
				"path": "docs/contracts/requirement-proof-bindings/local.v1.json",
				"text": text,
			},
		},
	}
}

func validCanonicalEnvelope() Envelope {
	return Envelope{
		SchemaVersion:        1,
		ContractKind:         "requirement_proof_binding",
		ContractID:           "requirement-proof-bindings/v1",
		AuthorityState:       "canonical_requirement_to_proof_binding",
		NormalizationProfile: "json/v1:utf8+lf+compact-row-arrays",
		NonClaims:            []string{"Requirement proof binding test input does not prove repository coverage."},
		SurfaceColumns:       canonicalSurfaceColumns,
		BindingColumns:       canonicalBindingColumns,
		WitnessColumns:       canonicalWitnessColumns,
	}
}

func validFragmentSourceSetInput(t *testing.T) map[string]any {
	t.Helper()
	envelope := validCanonicalEnvelope()
	alpha := fragmentV1("source.alpha", "REQ-PROOFKIT-ALPHA-001", "alpha_invariant")
	beta := fragmentV2("source.beta", "REQ-PROOFKIT-BETA-001", "beta_invariant")
	alphaText := compactJSON(t, alpha)
	betaText := compactJSON(t, beta)
	return map[string]any{
		"canonicalEnvelope": map[string]any{
			"schemaVersion":        json.Number("1"),
			"contractKind":         envelope.ContractKind,
			"contractId":           envelope.ContractID,
			"authorityState":       envelope.AuthorityState,
			"normalizationProfile": envelope.NormalizationProfile,
			"nonClaims":            stringSliceToAny(envelope.NonClaims),
			"surfaceColumns":       stringSliceToAny(envelope.SurfaceColumns),
			"bindingColumns":       stringSliceToAny(envelope.BindingColumns),
			"witnessColumns":       stringSliceToAny(envelope.WitnessColumns),
		},
		"sourceSet": map[string]any{
			"schema_version":        json.Number("1"),
			"contract_kind":         "requirement_proof_binding_source_set",
			"contract_id":           "requirement-proof-bindings/source-set/v1",
			"authority_state":       "requirement_proof_binding_source_index",
			"normalization_profile": "json/v1:utf8+lf+ordered-source-refs",
			"source_columns":        stringSliceToAny(sourceSetColumns),
			"sources": []any{
				[]any{"source.alpha", "docs/contracts/requirement-proof-bindings/alpha.v1.json", sha256Hex(alphaText), "requirement_proof_binding_fragment", []any{"Alpha source owns alpha rows."}},
				[]any{"source.beta", "docs/contracts/requirement-proof-bindings/beta.v1.json", sha256Hex(betaText), "requirement_proof_binding_fragment", []any{"Beta source owns beta rows."}},
			},
			"non_claims": []any{"Source set test input does not prove repository coverage."},
		},
		"sources": []any{
			map[string]any{"path": "docs/contracts/requirement-proof-bindings/alpha.v1.json", "text": alphaText},
			map[string]any{"path": "docs/contracts/requirement-proof-bindings/beta.v1.json", "text": betaText},
		},
	}
}

func fragmentV1(sourceID string, requirementID string, ownedInvariant string) map[string]any {
	return map[string]any{
		"schema_version":        json.Number("1"),
		"contract_kind":         "requirement_proof_binding_fragment",
		"contract_id":           "requirement-proof-bindings/fragment/v1",
		"authority_state":       "canonical_requirement_to_proof_binding_fragment",
		"normalization_profile": "json/v1:utf8+lf+compact-owner-row-arrays",
		"source_id":             sourceID,
		"surfaces": []any{
			[]any{sourceID, []any{"unit"}, false, "not_allowed", "none", []any{"local-go"}, []any{}, "checked"},
		},
		"bindings": []any{
			[]any{
				requirementID,
				sourceID,
				sourceID + "::" + ownedInvariant,
				"contract",
				ownedInvariant,
				"witness_backed",
				"blocking",
				[]any{"local-go"},
				[]any{"internal/" + ownedInvariant + "_test.go::TestPositive", []any{"local-go"}, []any{"go test ./..."}, json.Number("0")},
				[]any{"internal/" + ownedInvariant + "_test.go::TestNegative", []any{"local-go"}, []any{"go test ./..."}, json.Number("1")},
				[]any{"go test ./..."},
				"checked",
			},
		},
	}
}

func fragmentV2(sourceID string, requirementID string, ownedInvariant string) map[string]any {
	return map[string]any{
		"schema_version":        json.Number("1"),
		"contract_kind":         "requirement_proof_binding_fragment",
		"contract_id":           "requirement-proof-bindings/fragment/v2",
		"authority_state":       "canonical_requirement_to_proof_binding_fragment",
		"normalization_profile": "json/v1:utf8+lf+owner-defaulted-row-arrays",
		"source_id":             sourceID,
		"surfaces": []any{
			[]any{sourceID, []any{"unit"}, false, "not_allowed", "none", []any{"local-go"}, []any{}, "checked"},
		},
		"bindings": []any{
			[]any{
				requirementID,
				ownedInvariant,
				"contract",
				"witness_backed",
				"blocking",
				[]any{"local-go"},
				[]any{"internal/" + ownedInvariant + "_test.go::TestPositive", json.Number("0")},
				[]any{"internal/" + ownedInvariant + "_test.go::TestNegative", json.Number("1")},
				[]any{"go test ./..."},
				"checked",
			},
		},
	}
}

func equalAnyStringSlice(raw any, expected []string) bool {
	values, ok := raw.([]any)
	if !ok || len(values) != len(expected) {
		return false
	}
	for index, expectedValue := range expected {
		if values[index] != expectedValue {
			return false
		}
	}
	return true
}

func compactJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal compact JSON: %v", err)
	}
	return string(encoded)
}
