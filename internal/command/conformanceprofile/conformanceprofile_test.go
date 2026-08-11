package conformanceprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildProfileResolvesRequiredSurfaceAndRejectsMissingSurface(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.018828880652012560180983294316467397502747610605037816609704340855648617186412")
	result, err := BuildProfile(validConformanceProfileInput(), "local")
	if err != nil {
		t.Fatalf("BuildProfile() error=%v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" || result.ProfileReport.ProfileResolutionState != "resolved" {
		t.Fatalf("BuildProfile() exit=%d state=%s profileState=%s", result.ExitCode, result.Report.State, result.ProfileReport.ProfileResolutionState)
	}
	if result.ProfileReport.BindingCount != 1 || result.ProfileReport.RequirementCount != 1 || result.ProfileReport.WitnessMappingCount != 2 {
		t.Fatalf("profile counts=%#v, want one binding, one requirement, and two witness routes", result.ProfileReport)
	}

	input := validConformanceProfileInput()
	manifestProfile := input["manifest"].(map[string]any)["profiles"].([]any)[0].(map[string]any)
	manifestProfile["requiredSurfaceIds"] = []any{"surface.missing"}
	result, err = BuildProfile(input, "local")
	if err != nil {
		t.Fatalf("BuildProfile() missing surface error=%v", err)
	}
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("BuildProfile() accepted missing surface: exit=%d report=%#v", result.ExitCode, result.Report)
	}
	if !strings.Contains(strings.Join(result.ProfileReport.Failures, "\n"), "surface.missing") {
		t.Fatalf("failures=%#v, want missing surface", result.ProfileReport.Failures)
	}
}

func TestBuildProfilePreservesMultipleBindingsAndRoleQualifiedRoutes(t *testing.T) {
	input := validConformanceProfileInput()
	proofContract := input["proofContract"].(map[string]any)
	proofContract["bindings"] = append(
		proofContract["bindings"].([]any),
		conformanceBindingFixture("go test ./... -run TestSecond", "surface.local::scenario.second"),
	)

	result, err := BuildProfile(input, "local")
	if err != nil {
		t.Fatalf("BuildProfile() error=%v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("BuildProfile() exit=%d failures=%#v", result.ExitCode, result.ProfileReport.Failures)
	}
	if result.ProfileReport.BindingCount != 2 || result.ProfileReport.RequirementCount != 1 || result.ProfileReport.WitnessMappingCount != 4 {
		t.Fatalf("profile counts=%#v", result.ProfileReport)
	}

	invalid := validConformanceProfileInput()
	refs := invalid["proofContract"].(map[string]any)["bindings"].([]any)[0].(map[string]any)["witnessRefs"].([]any)
	invalid["proofContract"].(map[string]any)["bindings"].([]any)[0].(map[string]any)["witnessRefs"] = refs[:1]
	if _, err := BuildProfile(invalid, "local"); err == nil || !strings.Contains(err.Error(), "exactly positive and falsification") {
		t.Fatalf("BuildProfile() missing-role error=%v", err)
	}
}

func TestBindingFromPreservesAndBoundsWitnessResolutionOrder(t *testing.T) {
	binding := conformanceBindingFixture("go test ./...", "surface.local::scenario")
	refs := binding["witnessRefs"].([]any)
	refs[0].(map[string]any)["resolutionOrderIndex"] = json.Number("7")
	refs[1].(map[string]any)["resolutionOrderIndex"] = json.Number("3")

	admitted, err := bindingFrom(binding)
	if err != nil {
		t.Fatalf("bindingFrom() error=%v", err)
	}
	if admitted.WitnessRefs[0].Role != compactproofcontract.FalsificationWitnessRole || admitted.WitnessRefs[0].ResolutionOrderIndex != 7 {
		t.Fatalf("falsification witness=%#v, want preserved resolution order 7", admitted.WitnessRefs[0])
	}
	if admitted.WitnessRefs[1].Role != compactproofcontract.PositiveWitnessRole || admitted.WitnessRefs[1].ResolutionOrderIndex != 3 {
		t.Fatalf("positive witness=%#v, want preserved resolution order 3", admitted.WitnessRefs[1])
	}
	assertStringSlice(t, admitted.WitnessRefs[0].EnvironmentClasses, []string{"local-go"})
	assertStringSlice(t, admitted.WitnessRefs[0].VerifyCommands, []string{"go test ./... -run TestFalsification"})
	assertStringSlice(t, admitted.WitnessRefs[1].EnvironmentClasses, []string{"local-go"})
	assertStringSlice(t, admitted.WitnessRefs[1].VerifyCommands, []string{"go test ./... -run TestPositive"})

	delete(refs[0].(map[string]any), "resolutionOrderIndex")
	if _, err := bindingFrom(binding); err == nil || !strings.Contains(err.Error(), "JSON-safe non-negative integer") {
		t.Fatalf("bindingFrom() missing resolutionOrderIndex error=%v", err)
	}

	binding = conformanceBindingFixture("go test ./...", "surface.local::scenario")
	binding["witnessRefs"].([]any)[0].(map[string]any)["resolutionOrderIndex"] = json.Number("9007199254740992")
	if _, err := bindingFrom(binding); err == nil || !strings.Contains(err.Error(), "JSON-safe non-negative integer") {
		t.Fatalf("bindingFrom() unsafe resolutionOrderIndex error=%v", err)
	}
}

func TestBuildProfileEvaluatesWitnessOwnedEnvironmentAndCommands(t *testing.T) {
	input := validConformanceProfileInput()
	binding := input["proofContract"].(map[string]any)["bindings"].([]any)[0].(map[string]any)
	positive := binding["witnessRefs"].([]any)[1].(map[string]any)
	positive["environmentClasses"] = []any{"remote-provider"}
	positive["verifyCommands"] = []any{"go test ./... -run TestRemotePositive"}
	input["policy"].(map[string]any)["knownEnvironmentClasses"] = []any{"local-go", "remote-provider"}

	result, err := BuildProfile(input, "local")
	if err != nil {
		t.Fatalf("BuildProfile() error=%v", err)
	}
	if result.ExitCode == 0 || !strings.Contains(strings.Join(result.ProfileReport.Failures, "\n"), "uses unallowed environment remote-provider") {
		t.Fatalf("BuildProfile() exit=%d failures=%#v, want witness environment rejection", result.ExitCode, result.ProfileReport.Failures)
	}
	if !contains(result.ProfileReport.VerifyCommands, "go test ./... -run TestRemotePositive") {
		t.Fatalf("profile commands=%#v, want witness-owned command", result.ProfileReport.VerifyCommands)
	}
}

func TestBuildProfileRejectsBindingForUndeclaredSurface(t *testing.T) {
	input := validConformanceProfileInput()
	proofContract := input["proofContract"].(map[string]any)
	existing := proofContract["bindings"].([]any)
	proofContract["bindings"] = []any{
		conformanceBindingFixtureForSurface("go test ./... -run TestGhost", "surface.ghost", "surface.ghost::scenario"),
		existing[0],
	}

	_, err := BuildProfile(input, "local")
	if err == nil || !strings.Contains(err.Error(), "references unknown surfaceId surface.ghost") {
		t.Fatalf("BuildProfile() dangling surface error=%v", err)
	}
}

func TestBuildVerificationRejectsDuplicateProfiles(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.049942093994206845167684609448858504077053804318310280433394779107021396059359")
	input := validConformanceProfileInput()
	profiles := input["manifest"].(map[string]any)["profiles"].([]any)
	input["manifest"].(map[string]any)["profiles"] = append(profiles, profiles[0])

	record, exitCode, err := BuildVerification(input)
	if err != nil {
		t.Fatalf("BuildVerification() unexpected error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("BuildVerification() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnosticContains(t, record.RuleResults, "duplicate profileId=local")
}

func TestBuildVerificationRejectsSecretLikeReportVisibleText(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	input := validConformanceProfileInput()
	input["manifest"].(map[string]any)["nonClaims"] = []any{secret}

	record, exitCode, err := BuildVerification(input)
	if err != nil {
		t.Fatalf("BuildVerification() unexpected error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("BuildVerification() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("report leaked secret-shaped caller text: %s", string(encoded))
	}
	assertRuleDiagnosticContains(t, record.RuleResults, "secret-like values")
}

func TestListReturnsSortedProfileIDsAndRejectsInvalidInput(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.051339077909994076367504988840992439039749956644468897314149305148259581754885")
	input := validConformanceProfileInput()
	manifest := input["manifest"].(map[string]any)
	profile := manifest["profiles"].([]any)[0].(map[string]any)
	second := map[string]any{}
	for key, value := range profile {
		second[key] = value
	}
	second["profileId"] = "alpha"
	manifest["profiles"] = []any{profile, second}

	profiles, err := List(input)
	if err != nil {
		t.Fatalf("List() error=%v", err)
	}
	assertStringSlice(t, profiles, []string{"alpha", "local"})

	input = validConformanceProfileInput()
	input["unexpected"] = true
	_, err = List(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("List() error=%v, want invalid input rejection", err)
	}
}

func TestBindingFromRejectsShellControlVerifyCommand(t *testing.T) {
	_, err := bindingFrom(conformanceBindingFixture("go test ./... && curl example.test", "surface.local::scenario"))
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("bindingFrom() error=%v, want display-only command rejection", err)
	}
}

func TestBindingFromRejectsIdentityOutsideCompactOwnerGrammar(t *testing.T) {
	tests := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{
			name: "unscoped scenario",
			edit: func(binding map[string]any) {
				binding["scenarioId"] = "unscoped-scenario"
			},
			want: "surface_id::stable_anchor",
		},
		{
			name: "scenario surface mismatch",
			edit: func(binding map[string]any) {
				binding["scenarioId"] = "surface.other::scenario"
			},
			want: "must be scoped under surfaceId surface.local",
		},
		{
			name: "unsafe selector",
			edit: func(binding map[string]any) {
				for _, raw := range binding["witnessRefs"].([]any) {
					ref := raw.(map[string]any)
					ref["selector"] = "../outside.go::TestOutside"
				}
			},
			want: "must not escape the repository root",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := conformanceBindingFixture("go test ./...", "surface.local::scenario")
			test.edit(binding)
			if _, err := bindingFrom(binding); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("bindingFrom() error=%v, want %q", err, test.want)
			}
		})
	}
}

func validConformanceProfileInput() map[string]any {
	manifestNonClaim := "Conformance profile test manifest is not live proof."
	return map[string]any{
		"schemaVersion": json.Number("2"),
		"profileId":     "local",
		"policy": map[string]any{
			"knownEnvironmentClasses":             []any{"local-go"},
			"localEnvironmentClasses":             []any{"local-go"},
			"blockingStatuses":                    []any{"blocking"},
			"failOnUnusedAllowedEnvironmentClass": true,
			"expectedManifest": map[string]any{
				"contractId":           "proofkit.test.conformance",
				"contractKind":         "proofkit.conformance-manifest",
				"authorityState":       "canonical",
				"normalizationProfile": "proofkit.test.v1",
				"sourceContract":       "docs/contracts/requirement-proof-bindings.v1.json",
				"nonClaims":            []any{manifestNonClaim},
			},
		},
		"manifest": map[string]any{
			"schemaVersion":        json.Number("1"),
			"contractId":           "proofkit.test.conformance",
			"contractKind":         "proofkit.conformance-manifest",
			"authorityState":       "canonical",
			"normalizationProfile": "proofkit.test.v1",
			"sourceContract":       "docs/contracts/requirement-proof-bindings.v1.json",
			"nonClaims":            []any{manifestNonClaim},
			"profiles": []any{
				map[string]any{
					"profileId":                 "local",
					"purpose":                   "Local proof profile.",
					"preconditionPolicy":        "local_only",
					"requiredSurfaceIds":        []any{"surface.local"},
					"optionalSurfaceIds":        []any{},
					"allowedEnvironmentClasses": []any{"local-go"},
					"nonClaims":                 []any{"Local profile test fixture does not execute commands."},
				},
			},
		},
		"proofContract": map[string]any{
			"contractId":      "proofkit.test.proof-contract",
			"declarationKind": "proofkit.requirement-proof-route-declaration",
			"schemaVersion":   json.Number("2"),
			"surfaces": []any{
				map[string]any{
					"surfaceId":                        "surface.local",
					"requiredEnvironmentClasses":       []any{"local-go"},
					"preconditionedEnvironmentClasses": []any{},
				},
			},
			"bindings": []any{conformanceBindingFixture("go test ./...", "surface.local::scenario")},
		},
	}
}

func conformanceBindingFixture(command, scenarioID string) map[string]any {
	return conformanceBindingFixtureForSurface(command, "surface.local", scenarioID)
}

func conformanceBindingFixtureForSurface(command, surfaceID, scenarioID string) map[string]any {
	identity := compactproofcontract.BindingIdentity{
		RequirementID: "REQ-PROOFKIT-001",
		ScenarioID:    scenarioID,
		SurfaceID:     surfaceID,
	}
	bindingRecordID, err := compactproofcontract.BindingRecordID(identity)
	if err != nil {
		panic(err)
	}
	selector := "internal/test.go::TestOK"
	falsificationRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, compactproofcontract.FalsificationWitnessRole, selector)
	if err != nil {
		panic(err)
	}
	positiveRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, compactproofcontract.PositiveWitnessRole, selector)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"bindingRecordId":                   bindingRecordID,
		"blockingStatus":                    "blocking",
		"declaredMutationResistanceClaimId": "proofkit.claim.mutation.test",
		"invariantRole":                     "contract",
		"ownedInvariant":                    "proofkit.test.invariant",
		"requiredEnvironmentClasses":        []any{"local-go"},
		"requirementId":                     identity.RequirementID,
		"scenarioId":                        identity.ScenarioID,
		"surfaceId":                         identity.SurfaceID,
		"verifyCommands":                    []any{command},
		"witnessRefs": []any{
			map[string]any{"environmentClasses": []any{"local-go"}, "resolutionOrderIndex": json.Number("0"), "role": "falsification", "selector": selector, "verifyCommands": []any{"go test ./... -run TestFalsification"}, "witnessRouteId": falsificationRouteID},
			map[string]any{"environmentClasses": []any{"local-go"}, "resolutionOrderIndex": json.Number("1"), "role": "positive", "selector": selector, "verifyCommands": []any{"go test ./... -run TestPositive"}, "witnessRouteId": positiveRouteID},
		},
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

func assertStringSlice(t *testing.T, actual []string, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("slice length=%d want %d; actual=%#v", len(actual), len(expected), actual)
	}
	for index, expectedValue := range expected {
		if actual[index] != expectedValue {
			t.Fatalf("slice[%d]=%q want %q; actual=%#v", index, actual[index], expectedValue, actual)
		}
	}
}

func TestMarkdownEscapesCommandCodeSpans(t *testing.T) {
	output := Markdown(ProfileReport{
		ProfileID:              "proofkit.profile",
		ProfileResolutionState: "resolved",
		Purpose:                "<b>rendered purpose</b>",
		VerifyCommands:         []string{"go test ./`pkg`"},
		NonClaims:              []string{"<script>alert(1)</script>"},
	})
	for _, forbidden := range []string{"<b>", "<script>"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("Markdown() output contains unescaped markup %q:\n%s", forbidden, output)
		}
	}
	if !strings.Contains(output, "``go test ./`pkg```") {
		t.Fatalf("Markdown() output missing widened code span:\n%s", output)
	}
}
