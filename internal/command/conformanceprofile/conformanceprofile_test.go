package conformanceprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildProfileResolvesRequiredSurfaceAndRejectsMissingSurface(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.058560543430386671975862540474631351828433682994553568983923953081174649721029")
	result, err := BuildProfile(validConformanceProfileInput(), "local")
	if err != nil {
		t.Fatalf("BuildProfile() error=%v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" || result.ProfileReport.ProfileResolutionState != "resolved" {
		t.Fatalf("BuildProfile() exit=%d state=%s profileState=%s", result.ExitCode, result.Report.State, result.ProfileReport.ProfileResolutionState)
	}
	if result.ProfileReport.RequirementCount != 1 || result.ProfileReport.WitnessMappingCount != 1 {
		t.Fatalf("profile counts=%#v, want one requirement and witness", result.ProfileReport)
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

func TestBuildVerificationRejectsDuplicateProfiles(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.059839663405963145056826817506435791735368004114196862540174073017127636205209")
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
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.087092535541262698904962014459883891376365242892684917393349609831025338348503")
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
	_, err := bindingFrom(map[string]any{
		"blockingStatus":             "blocking",
		"proofContractState":         "witness_backed",
		"requiredEnvironmentClasses": []any{"local-go"},
		"requirementId":              "REQ-PROOFKIT-001",
		"scenarioId":                 "proofkit.scenario",
		"surfaceId":                  "proofkit.surface",
		"verifyCommands":             []any{"go test ./... && curl example.test"},
		"witnessRefs": []any{map[string]any{
			"role":     "unit",
			"selector": "internal/test.go",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("bindingFrom() error=%v, want display-only command rejection", err)
	}
}

func validConformanceProfileInput() map[string]any {
	manifestNonClaim := "Conformance profile test manifest is not live proof."
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"profileId":     "local",
		"policy": map[string]any{
			"knownEnvironmentClasses":             []any{"local-go"},
			"localEnvironmentClasses":             []any{"local-go"},
			"allowedProofContractStates":          []any{"witness_backed"},
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
			"contractId": "proofkit.test.proof-contract",
			"surfaces": []any{
				map[string]any{
					"surfaceId":                        "surface.local",
					"requiredEnvironmentClasses":       []any{"local-go"},
					"preconditionedEnvironmentClasses": []any{},
				},
			},
			"bindings": []any{
				map[string]any{
					"requirementId":              "REQ-PROOFKIT-001",
					"surfaceId":                  "surface.local",
					"scenarioId":                 "proofkit.scenario",
					"blockingStatus":             "blocking",
					"proofContractState":         "witness_backed",
					"requiredEnvironmentClasses": []any{"local-go"},
					"verifyCommands":             []any{"go test ./..."},
					"witnessRefs": []any{
						map[string]any{"role": "unit", "selector": "internal/test.go::TestOK"},
					},
				},
			},
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
