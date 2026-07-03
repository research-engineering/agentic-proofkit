package scaffoldprofileplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAcceptsCommandMatcherHints(t *testing.T) {
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
