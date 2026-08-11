package impact

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildRejectsSchemeAndDriveLikeChangedPaths(t *testing.T) {
	for _, path := range []string{"file:docs/report.json", "C:/outside/report.json"} {
		t.Run(path, func(t *testing.T) {
			input := validImpactInput()
			input["changedPaths"] = []any{path}
			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), "repository-relative POSIX path") {
				t.Fatalf("Build() error=%v, want path rejection", err)
			}
		})
	}
}

func TestBuildRejectsUnknownImpactFields(t *testing.T) {
	input := validImpactInput()
	input["ambientAuthority"] = true
	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Build() error=%v, want unsupported field rejection", err)
	}
}

func TestBuildRejectsSecretShapedReportText(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "preexisting failure",
			mutate: func(input map[string]any) {
				input["preexistingFailures"] = []any{"api_key=ghp_secretvalue"}
			},
		},
		{
			name: "unbound rationale",
			mutate: func(input map[string]any) {
				input["unboundProofChangeRationale"] = "Authorization: Bearer ghp_secretvalue"
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validImpactInput()
			item.mutate(input)

			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), "secret-like values") {
				t.Fatalf("Build() error=%v, want secret-like rejection", err)
			}
			if strings.Contains(err.Error(), "ghp_secretvalue") || strings.Contains(err.Error(), "api_key=") {
				t.Fatalf("Build() error leaked secret-shaped text: %v", err)
			}
		})
	}
}

func TestBuildRejectsShellControlTokensInObligationCommands(t *testing.T) {
	input := validImpactInput()
	input["obligationCatalog"] = []any{
		map[string]any{
			"bindingRecordId":                   testBindingRecordID,
			"blockingStatus":                    "blocking",
			"commands":                          []any{"go test ./... && curl https://example.invalid"},
			"declaredMutationResistanceClaimId": "claim.unverified",
			"preconditioned":                    false,
			"requirementId":                     "REQ-PROOFKIT-001",
			"requiredEnvironmentClasses":        []any{"local-go"},
			"scenarioId":                        "proofkit.surface::proofkit.scenario",
			"surfaceId":                         "proofkit.surface",
		},
	}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("Build() error=%v, want display command rejection", err)
	}
}

func TestBuildRejectsMalformedWitnessCoverageIdentities(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value any
	}{
		{name: "binding record id", field: "bindingRecordId", value: "binding:not-a-digest"},
		{name: "witness route id", field: "witnessRouteId", value: "sha256:short"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validImpactInput()
			input["obligationCatalog"] = []any{validImpactObligation()}
			route := validImpactRoute()
			route[test.field] = test.value
			coverage := map[string]any{
				"path":   "internal/command/impact/impact_test.go",
				"routes": []any{route},
			}
			input["changedWitnessPathCoverage"] = []any{coverage}

			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), "sha256") {
				t.Fatalf("Build() error=%v, want malformed %s rejection", err, test.field)
			}
		})
	}
}

func TestBuildRejectsContentAddressedIdentityMismatch(t *testing.T) {
	input := validImpactInput()
	obligation := validImpactObligation()
	obligation["bindingRecordId"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input["obligationCatalog"] = []any{obligation}
	if _, _, err := Build(input); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Build() error=%v, want binding identity mismatch", err)
	}

	input = validImpactInput()
	input["obligationCatalog"] = []any{validImpactObligation()}
	route := validImpactRoute()
	route["witnessRouteId"] = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input["changedWitnessPathCoverage"] = []any{map[string]any{
		"path": "internal/command/impact/impact_test.go", "routes": []any{route},
	}}
	if _, _, err := Build(input); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Build() error=%v, want route identity mismatch", err)
	}
}

func TestBuildFailsWhenChangedRequirementHasNoCurrentBinding(t *testing.T) {
	input := validImpactInput()
	input["changedRequirementIds"] = []any{"REQ-PROOFKIT-UNKNOWN-001"}

	report, code, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if code != 1 || report["impactState"] != "failed" {
		t.Fatalf("Build() code=%d report=%#v, want failed report", code, report)
	}
	failures := report["failures"].([]any)
	if len(failures) != 1 || failures[0] != "changed requirement has no obligation catalog binding: REQ-PROOFKIT-UNKNOWN-001" {
		t.Fatalf("Build() failures=%#v", failures)
	}
	if obligations := report["obligations"].([]any); len(obligations) != 0 {
		t.Fatalf("Build() obligations=%#v, want none", obligations)
	}
}

func TestBuildRoutesChangedRecordToObligationAndRejectsUnboundProofChange(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.004126818763873109094701885631231832544658829793890758986188782288995889572211")
	input := validImpactInput()
	input["changedRequirementIds"] = []any{"REQ-PROOFKIT-001"}
	input["obligationCatalog"] = []any{validImpactObligation()}
	result, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || result["impactState"] != "ok" {
		t.Fatalf("Build() exit=%d result=%#v, want ok", exitCode, result)
	}
	obligations := result["obligations"].([]any)
	if len(obligations) != 1 {
		t.Fatalf("proofObligations len=%d, want 1: %#v", len(obligations), obligations)
	}
	if !containsStringValue(result["nonClaims"].([]any), "Impact reports do not run git, scan repositories, execute witnesses, authenticate receipts, approve merge, or prove proof freshness.") {
		t.Fatalf("impact nonClaims missing command-owned boundary denial: %#v", result["nonClaims"])
	}

	input = validImpactInput()
	input["changedPaths"] = []any{"docs/contracts/proof.json"}
	input["proofLikePaths"] = []any{"docs/contracts/proof.json"}
	delete(input, "unboundProofChangeRationale")
	result, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() unbound proof change error=%v", err)
	}
	if exitCode == 0 || result["impactState"] != "failed" {
		t.Fatalf("Build() exit=%d result=%#v, want failed", exitCode, result)
	}
	failures := result["failures"].([]any)
	if len(failures) != 1 || !strings.Contains(failures[0].(string), "proof changes without parent record need a rationale") {
		t.Fatalf("failures=%#v, want unbound proof rationale failure", failures)
	}
}

func TestBuildPreservesExactWitnessRouteTuple(t *testing.T) {
	input := validImpactInput()
	input["changedPaths"] = []any{"internal/command/impact/impact_test.go"}
	input["obligationCatalog"] = []any{validImpactObligation()}
	input["changedWitnessPathCoverage"] = []any{map[string]any{
		"path":   "internal/command/impact/impact_test.go",
		"routes": []any{validImpactRoute()},
	}}
	report, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit=%d report=%#v", exitCode, report)
	}
	obligations := report["obligations"].([]any)
	if len(obligations) != 1 {
		t.Fatalf("obligations=%#v, want one", obligations)
	}
	routes := obligations[0].(map[string]any)["witnessRoutes"].([]any)
	if len(routes) != 1 {
		t.Fatalf("witnessRoutes=%#v, want one", routes)
	}
	route := routes[0].(map[string]any)
	if route["bindingRecordId"] != testBindingRecordID || route["witnessRouteId"] != testWitnessRouteID || route["role"] != "positive" || route["selector"] != "internal/command/impact/impact_test.go::TestWitness" {
		t.Fatalf("witness route tuple drifted: %#v", route)
	}
	if route["resolutionOrderIndex"] != 1 {
		t.Fatalf("resolutionOrderIndex=%v, want 1", route["resolutionOrderIndex"])
	}
}

func TestBuildRejectsWitnessRouteOutsideDeclaration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "different resolution order",
			mutate: func(route map[string]any) {
				route["resolutionOrderIndex"] = json.Number("7")
			},
		},
		{
			name: "self-consistent forged selector",
			mutate: func(route map[string]any) {
				selector := "internal/command/impact/impact_test.go::ForgedWitness"
				route["selector"] = selector
				routeID, err := compactproofcontract.WitnessRouteID(
					testBindingRecordID,
					compactproofcontract.PositiveWitnessRole,
					selector,
				)
				if err != nil {
					t.Fatal(err)
				}
				route["witnessRouteId"] = routeID
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validImpactInput()
			input["changedPaths"] = []any{"internal/command/impact/impact_test.go"}
			input["proofLikePaths"] = []any{"internal/command/impact/impact_test.go"}
			input["obligationCatalog"] = []any{validImpactObligation()}
			route := validImpactRoute()
			test.mutate(route)
			input["changedWitnessPathCoverage"] = []any{map[string]any{
				"path": "internal/command/impact/impact_test.go", "routes": []any{route},
			}}

			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), "does not match an obligation catalog declared witness route") {
				t.Fatalf("Build() error=%v, want undeclared route rejection", err)
			}
		})
	}
}

func TestBuildUsesCompactOwnerResolutionOrderBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   json.Number
		wantErr bool
	}{
		{name: "maximum JSON-safe integer", value: json.Number("9007199254740991")},
		{name: "first unsafe integer", value: json.Number("9007199254740992"), wantErr: true},
		{name: "unsafe integer with distinct decimal identity", value: json.Number("9007199254740993"), wantErr: true},
		{name: "negative", value: json.Number("-1"), wantErr: true},
		{name: "fractional", value: json.Number("1.5"), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validImpactInput()
			input["changedPaths"] = []any{"internal/command/impact/impact_test.go"}
			obligation := validImpactObligation()
			for _, raw := range obligation["declaredWitnessRoutes"].([]any) {
				declared := raw.(map[string]any)
				if declared["role"] == compactproofcontract.PositiveWitnessRole {
					declared["resolutionOrderIndex"] = test.value
				}
			}
			input["obligationCatalog"] = []any{obligation}
			route := validImpactRoute()
			route["resolutionOrderIndex"] = test.value
			input["changedWitnessPathCoverage"] = []any{map[string]any{
				"path": "internal/command/impact/impact_test.go", "routes": []any{route},
			}}

			_, _, err := Build(input)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "JSON-safe non-negative integer") {
					t.Fatalf("Build() error=%v, want JSON-safe integer rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
		})
	}
}

var testBindingRecordID = mustImpactBindingRecordID()
var testWitnessRouteID = mustImpactWitnessRouteID()

func mustImpactBindingRecordID() string {
	value, err := compactproofcontract.BindingRecordID(compactproofcontract.BindingIdentity{
		RequirementID: "REQ-PROOFKIT-001",
		ScenarioID:    "proofkit.surface::proofkit.scenario",
		SurfaceID:     "proofkit.surface",
	})
	if err != nil {
		panic(err)
	}
	return value
}

func mustImpactWitnessRouteID() string {
	value, err := compactproofcontract.WitnessRouteID(
		testBindingRecordID,
		compactproofcontract.PositiveWitnessRole,
		"internal/command/impact/impact_test.go::TestWitness",
	)
	if err != nil {
		panic(err)
	}
	return value
}

func validImpactObligation() map[string]any {
	return map[string]any{
		"bindingRecordId":                   testBindingRecordID,
		"blockingStatus":                    "blocking",
		"commands":                          []any{"go test ./..."},
		"declaredMutationResistanceClaimId": "claim.unverified",
		"declaredWitnessRoutes":             validDeclaredWitnessRoutes(),
		"preconditioned":                    false,
		"requirementId":                     "REQ-PROOFKIT-001",
		"requiredEnvironmentClasses":        []any{"local-go"},
		"scenarioId":                        "proofkit.surface::proofkit.scenario",
		"surfaceId":                         "proofkit.surface",
	}
}

func validDeclaredWitnessRoutes() []any {
	routes := []any{}
	for _, item := range []struct {
		role     string
		selector string
	}{
		{role: compactproofcontract.FalsificationWitnessRole, selector: "internal/command/impact/impact_test.go::TestRejectsWitness"},
		{role: compactproofcontract.PositiveWitnessRole, selector: "internal/command/impact/impact_test.go::TestWitness"},
	} {
		routeID, err := compactproofcontract.WitnessRouteID(testBindingRecordID, item.role, item.selector)
		if err != nil {
			panic(err)
		}
		routes = append(routes, map[string]any{
			"bindingRecordId":      testBindingRecordID,
			"environmentClasses":   []any{"local-go"},
			"resolutionOrderIndex": json.Number("1"),
			"role":                 item.role,
			"selector":             item.selector,
			"verifyCommands":       []any{"go test ./..."},
			"witnessRouteId":       routeID,
		})
	}
	sort.Slice(routes, func(left, right int) bool {
		return routes[left].(map[string]any)["witnessRouteId"].(string) < routes[right].(map[string]any)["witnessRouteId"].(string)
	})
	return routes
}

func validImpactRoute() map[string]any {
	return map[string]any{
		"bindingRecordId":      testBindingRecordID,
		"resolutionOrderIndex": json.Number("1"),
		"role":                 compactproofcontract.PositiveWitnessRole,
		"selector":             "internal/command/impact/impact_test.go::TestWitness",
		"witnessRouteId":       testWitnessRouteID,
	}
}

func validImpactInput() map[string]any {
	return map[string]any{
		"schemaVersion":               json.Number("2"),
		"baseCommit":                  "abc",
		"baseRef":                     "main",
		"changedBindingRecordIds":     []any{},
		"changedPaths":                []any{"docs/specs/example/requirements.v1.json"},
		"changedRequirementIds":       []any{},
		"changedWitnessPathCoverage":  []any{},
		"generatedArtifactRules":      []any{},
		"headCommit":                  nil,
		"headRef":                     "feature/test",
		"ignoredProofLikePaths":       []any{},
		"obligationCatalog":           []any{},
		"preexistingFailures":         []any{},
		"proofLikePaths":              []any{},
		"unboundProofChangeRationale": "No proof-like path changed.",
		"nonClaims":                   []any{"Impact fixture is not merge evidence."},
	}
}

func containsStringValue(values []any, want string) bool {
	for _, value := range values {
		if text, ok := value.(string); ok && text == want {
			return true
		}
	}
	return false
}
