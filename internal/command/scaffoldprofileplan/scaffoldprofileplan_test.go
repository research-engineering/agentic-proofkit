package scaffoldprofileplan

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildAcceptsCommandMatcherHints(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.013321323303874251949085998799870857902727560387311658432878441406042996018615")
	result, err := BuildResult(validScaffoldInput())
	if err != nil {
		t.Fatalf("BuildResult() error = %v", err)
	}
	if result.ExitCode != 0 || result.Record.State != "passed" {
		t.Fatalf("BuildResult() exit=%d state=%s, want passed", result.ExitCode, result.Record.State)
	}
	if result.Record.Summary["commandMatcherCount"] != 1 {
		t.Fatalf("commandMatcherCount=%v, want 1", result.Record.Summary["commandMatcherCount"])
	}
	assertScaffoldPlanShape(t, result.Plan)
	second, err := BuildResult(validScaffoldInput())
	if err != nil {
		t.Fatalf("second BuildResult() error = %v", err)
	}
	firstEncoded, _ := json.Marshal(result.Plan)
	secondEncoded, _ := json.Marshal(second.Plan)
	if string(firstEncoded) != string(secondEncoded) {
		t.Fatalf("scaffold plan is not deterministic:\nfirst=%s\nsecond=%s", firstEncoded, secondEncoded)
	}
}

func TestBuildSupportsExactArgvMatcherVocabulary(t *testing.T) {
	input := validScaffoldInput()
	input["commandMatcherHints"] = []any{map[string]any{
		"allowedArgv":     []any{"go", "test", "./..."},
		"credentialClass": "none",
		"id":              "proofkit.go-test",
		"kind":            "exact_argv",
		"networkPolicy":   "none",
		"parallelGroup":   "local",
	}}

	result, err := BuildResult(input)
	if err != nil {
		t.Fatalf("BuildResult() error = %v", err)
	}
	draft := result.Plan["repoProfileDraft"].(map[string]any)
	matchers := draft["commandMatchers"].([]any)
	if len(matchers) != 1 {
		t.Fatalf("matcher count=%d, want 1", len(matchers))
	}
	matcher := matchers[0].(map[string]any)
	if matcher["kind"] != "exact_argv" {
		t.Fatalf("matcher kind=%v, want exact_argv", matcher["kind"])
	}
	got := matcher["allowedArgv"].([]any)
	want := []string{"go", "test", "./..."}
	if len(got) != len(want) {
		t.Fatalf("allowedArgv length=%d, want %d: %v", len(got), len(want), got)
	}
	for index, value := range want {
		if got[index] != value {
			t.Fatalf("allowedArgv[%d]=%v, want %s", index, got[index], value)
		}
	}
}

func TestBuildRejectsExactArgvMatcherShellTokens(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{name: "shell control", token: "&&"},
		{name: "quoted", token: `"./..."`},
		{name: "whitespace", token: "go test"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validScaffoldInput()
			input["commandMatcherHints"] = []any{map[string]any{
				"allowedArgv":     []any{"go", "test", item.token},
				"credentialClass": "none",
				"id":              "proofkit.go-test",
				"kind":            "exact_argv",
				"networkPolicy":   "none",
				"parallelGroup":   "local",
			}}

			_, err := BuildResult(input)
			if err == nil || !strings.Contains(err.Error(), "literal argv tokens only") {
				t.Fatalf("BuildResult() error=%v, want literal argv rejection", err)
			}
		})
	}
}

func TestBuildRejectsUnknownScaffoldInputField(t *testing.T) {
	input := validScaffoldInput()
	input["implicitPolicy"] = true

	_, err := BuildResult(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("BuildResult() error = %v, want unsupported field rejection", err)
	}
}

func TestBuildRejectsUnknownCommandMatcherField(t *testing.T) {
	input := validScaffoldInput()
	input["commandMatcherHints"].([]any)[0].(map[string]any)["implicitScript"] = true

	_, err := BuildResult(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("BuildResult() error = %v, want unsupported field rejection", err)
	}
}

func TestBuildRejectsSecretLikeReportVisibleText(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	input := validScaffoldInput()
	input["nonClaims"] = []any{secret}

	_, err := BuildResult(input)
	if err == nil {
		t.Fatal("BuildResult() accepted secret-shaped nonClaim")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret-shaped caller text: %v", err)
	}
	if !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("error=%v, want secret-like rejection", err)
	}
}

func validScaffoldInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"planId":        "proofkit.test.scaffold",
		"repository": map[string]any{
			"name":             "agentic-proofkit",
			"primaryLanguages": []any{"go"},
			"profilePath":      "proofkit/repo-profile.v1.json",
			"rootPackageName":  "agentic-proofkit",
		},
		"paths": map[string]any{
			"bindingPath":           "proofkit/bindings.v1.json",
			"generatedArtifacts":    []any{},
			"policyPath":            "proofkit/repo-profile.v1.json",
			"proofLikePaths":        []any{"docs/specs/proofkit/requirements.v1.json"},
			"retiredProofLikePaths": []any{},
			"routerPath":            "AGENTS.md",
			"specGlobs":             []any{"docs/specs/**/*.json"},
		},
		"requirements": map[string]any{
			"idPattern": "REQ-PROOFKIT-[0-9]+",
		},
		"environmentClasses": []any{"local-go"},
		"commandMatcherHints": []any{map[string]any{
			"allowedScripts":  []any{"check"},
			"credentialClass": "none",
			"id":              "proofkit.check",
			"kind":            "bun_repo_script",
			"networkPolicy":   "none",
			"parallelGroup":   "local",
		}},
		"nonClaims": []any{"Scaffold test input does not claim generated files were written."},
	}
}

func assertScaffoldPlanShape(t *testing.T, plan map[string]any) {
	t.Helper()
	if plan["planKind"] != "proofkit.repo-profile-scaffold-plan" || plan["schemaVersion"] != 1 {
		t.Fatalf("unexpected plan identity: %#v", plan)
	}
	nonClaims := plan["nonClaims"].([]any)
	for _, want := range []string{
		"Repo-profile scaffold plans do not read repository state.",
		"Repo-profile scaffold plans do not write files.",
		"Repo-profile scaffold plans do not execute native witnesses.",
		"Repo-profile scaffold plans do not prove profile correctness, proof freshness, merge readiness, or rollout readiness.",
	} {
		if !anySliceContains(nonClaims, want) {
			t.Fatalf("nonClaims missing %q: %#v", want, nonClaims)
		}
	}
	provenance := plan["provenance"].([]any)
	for _, want := range []string{"repository.name", "commandMatchers", "proofs.environmentClasses"} {
		if !diagnosticAnyContains(provenance, want) {
			t.Fatalf("provenance missing %s: %#v", want, provenance)
		}
	}
	gaps := plan["callerRequiredGaps"].([]any)
	if len(gaps) == 0 || !diagnosticAnyContains(gaps, "tracked-facts") {
		t.Fatalf("callerRequiredGaps missing tracked facts gap: %#v", gaps)
	}
	draft := plan["repoProfileDraft"].(map[string]any)
	if draft["schema"] != "proofkit.repo-profile.v1" {
		t.Fatalf("unexpected draft schema: %#v", draft)
	}
	if len(draft["commandMatchers"].([]any)) != 1 {
		t.Fatalf("draft command matcher count=%#v", draft["commandMatchers"])
	}
	draftNonClaims := draft["nonClaims"].([]any)
	if !anySliceContains(draftNonClaims, "This repository profile draft is caller-reviewed starter content.") {
		t.Fatalf("draft nonClaims missing caller-reviewed boundary: %#v", draftNonClaims)
	}
}

func anySliceContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func diagnosticAnyContains(values []any, needle string) bool {
	encoded, _ := json.Marshal(values)
	return strings.Contains(string(encoded), needle)
}
