package impact

import (
	"encoding/json"
	"strings"
	"testing"
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
			"blockingStatus":             "blocking",
			"commands":                   []any{"go test ./... && curl https://example.invalid"},
			"preconditioned":             false,
			"proofContractState":         "witness_backed",
			"recordId":                   "REQ-PROOFKIT-001",
			"requiredEnvironmentClasses": []any{"local-go"},
			"scenarioId":                 "proofkit.scenario",
			"surfaceId":                  "proofkit.surface",
		},
	}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("Build() error=%v, want display command rejection", err)
	}
}

func TestBuildRoutesChangedRecordToObligationAndRejectsUnboundProofChange(t *testing.T) {
	input := validImpactInput()
	input["changedRecordIds"] = []any{"REQ-PROOFKIT-001"}
	input["obligationCatalog"] = []any{
		map[string]any{
			"blockingStatus":             "blocking",
			"commands":                   []any{"go test ./..."},
			"preconditioned":             false,
			"proofContractState":         "witness_backed",
			"recordId":                   "REQ-PROOFKIT-001",
			"requiredEnvironmentClasses": []any{"local-go"},
			"scenarioId":                 "proofkit.scenario",
			"surfaceId":                  "proofkit.surface",
		},
	}
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

func validImpactInput() map[string]any {
	return map[string]any{
		"schemaVersion":               json.Number("1"),
		"baseCommit":                  "abc",
		"baseRef":                     "main",
		"changedBindingRecordIds":     []any{},
		"changedPaths":                []any{"docs/specs/example/requirements.v1.json"},
		"changedRecordIds":            []any{},
		"changedWitnessPathCoverage":  []any{},
		"generatedArtifactRules":      []any{},
		"headCommit":                  nil,
		"headRef":                     "feature/test",
		"ignoredProofLikePaths":       []any{},
		"obligationCatalog":           []any{},
		"preexistingFailures":         []any{},
		"proofLikePaths":              []any{},
		"unboundProofChangeRationale": "No proof-like path changed.",
	}
}
