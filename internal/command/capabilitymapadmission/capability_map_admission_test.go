package capabilitymapadmission

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildCodeBaselineEmitsCandidateRequirementsAndBindings(t *testing.T) {
	t.Parallel()

	record, exitCode, err := Build(validCapabilityMapInput("code_baseline"))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	if record.Summary["candidateRequirementSeedCount"] != 1 || record.Summary["candidateProofBindingSeedCount"] != 1 {
		t.Fatalf("summary=%#v, want one candidate requirement and binding", record.Summary)
	}
	diagnostics := record.JSONValue()["diagnostics"].([]any)
	if !diagnosticContains(diagnostics, "candidateRequirementSeeds", "REQ-SAMPLE-AUTH-001") {
		t.Fatalf("candidate requirement missing from diagnostics: %#v", diagnostics)
	}
	if !diagnosticContains(diagnostics, "candidateRequirementSeeds", "negative_test") {
		t.Fatalf("candidate requirement did not preserve requiredEvidence: %#v", diagnostics)
	}
	if !diagnosticContains(diagnostics, "candidateProofBindingSeeds", "service/tests/auth_test.py::test_missing_bearer_fails_closed") {
		t.Fatalf("candidate proof binding missing from diagnostics: %#v", diagnostics)
	}
	if !diagnosticContains(diagnostics, "candidateProofBindingSeeds", "negative_test") {
		t.Fatalf("candidate proof binding did not preserve requiredEvidence: %#v", diagnostics)
	}
}

func TestBuildCodeBaselineFailsMissingCandidateRequirementAndAnchor(t *testing.T) {
	t.Parallel()

	input := validCapabilityMapInput("code_baseline")
	shape := firstScenarioShape(input)
	delete(shape, "candidateRequirementId")
	input["scenarioAnchors"] = []any{}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, _ := json.Marshal(record.JSONValue())
	if !strings.Contains(string(encoded), "candidateRequirementId in code_baseline mode") {
		t.Fatalf("baseline failure did not mention missing candidate requirement: %s", encoded)
	}
	if !strings.Contains(string(encoded), "active scenario anchor in code_baseline mode") {
		t.Fatalf("baseline failure did not mention missing anchor: %s", encoded)
	}
}

func TestBuildCodeBaselineDoesNotEmitBindingSeedForNonExecutableAnchor(t *testing.T) {
	t.Parallel()

	input := validCapabilityMapInput("code_baseline")
	anchor := firstScenarioAnchor(input)
	anchor["commandRefs"] = []any{}
	anchor["positiveWitness"] = false
	anchor["falsificationWitness"] = false

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	if record.Summary["candidateRequirementSeedCount"] != 1 || record.Summary["candidateProofBindingSeedCount"] != 0 {
		t.Fatalf("summary=%#v, want requirement seed without proof-binding seed", record.Summary)
	}
	encoded, _ := json.Marshal(record.JSONValue())
	if strings.Contains(string(encoded), `"candidateProofBindingSeeds":[{`) {
		t.Fatalf("non-executable anchor emitted candidate proof binding seed: %s", encoded)
	}
	if !strings.Contains(string(encoded), "must declare an executable positive or falsification anchor") {
		t.Fatalf("failure did not mention missing executable anchor: %s", encoded)
	}
}

func TestBuildAuditModeAllowsMissingAnchorAsOwnerAction(t *testing.T) {
	t.Parallel()

	input := validCapabilityMapInput("audit_from_code")
	input["scenarioAnchors"] = []any{}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed audit guidance", exitCode, record.State)
	}
	encoded, _ := json.Marshal(record.JSONValue())
	if !strings.Contains(string(encoded), "add_scenario_anchor") {
		t.Fatalf("audit mode did not emit missing-anchor owner action: %s", encoded)
	}
	if !strings.Contains(string(encoded), "Treat code observations as untrusted hypotheses") {
		t.Fatalf("audit mode did not emit untrusted-code instruction: %s", encoded)
	}
}

func TestBuildAuditModeMarksCandidateSeedsAsUntrustedOwnerDrafts(t *testing.T) {
	t.Parallel()

	record, exitCode, err := Build(validCapabilityMapInput("audit_from_code"))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed audit guidance", exitCode, record.State)
	}
	encoded, _ := json.Marshal(record.JSONValue())
	for _, want := range []string{
		`"sourceTrustMode":"audit_from_code"`,
		`"promotionState":"owner_review_required"`,
		`"evidenceAuthority":"untrusted_code_observation"`,
		`"executableEvidenceState":"not_executable_until_owner_materialized"`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("audit candidate seeds missing %s: %s", want, encoded)
		}
	}
	if strings.Contains(string(encoded), `"executableEvidenceState":"candidate_executable_anchor"`) {
		t.Fatalf("audit candidate seed looked executable before owner materialization: %s", encoded)
	}
}

func TestBuildRejectsUnsafePathsUnknownModeAndSecretText(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "unknown mode",
			mutate: func(input map[string]any) {
				input["trustMode"] = "trust_me"
			},
			want: "capability map trustMode must be one of",
		},
		{
			name: "unsafe source path",
			mutate: func(input map[string]any) {
				firstCapability(input)["sourcePaths"] = []any{"../backend"}
			},
			want: "must not escape the repository root",
		},
		{
			name: "secret-shaped caller text",
			mutate: func(input map[string]any) {
				firstScenarioShape(input)["summary"] = "Bearer abcdefghijklmnop should not appear"
			},
			want: "must not contain secret-like values",
		},
		{
			name: "selector without source separator",
			mutate: func(input map[string]any) {
				firstScenarioAnchor(input)["selector"] = "test_missing_bearer_fails_closed"
			},
			want: "must use source::selector form",
		},
		{
			name: "selector source path drift",
			mutate: func(input map[string]any) {
				firstScenarioAnchor(input)["selector"] = "service/tests/other_test.py::test_missing_bearer_fails_closed"
			},
			want: "sourcePath must match selector path",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validCapabilityMapInput("code_baseline")
			item.mutate(input)
			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func validCapabilityMapInput(mode string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"mapId":         "sample.backend.auth.capability_map",
		"authority":     "caller_owned_observation",
		"trustMode":     mode,
		"repository": map[string]any{
			"repositoryId":     "sample_repo",
			"primaryLanguages": []any{"python", "typescript"},
			"nonClaims":        []any{"Repository metadata is a test fixture."},
		},
		"proofScope": map[string]any{
			"scopeId":    "sample.backend.auth.scope",
			"dirtyState": "clean",
			"baseRef":    "origin/main",
			"headRef":    "HEAD",
			"nonClaims":  []any{"Proof scope fixture does not prove checkout freshness."},
		},
		"capabilities": []any{
			map[string]any{
				"capabilityId": "sample.backend.auth",
				"ownerId":      "sample.backend",
				"summary":      "Authentication requests resolve authorization headers and fail closed when they are absent.",
				"sourcePaths":  []any{"service/src/auth", "service/tests/auth_test.py"},
				"riskClasses":  []any{"runtime", "security"},
				"nonClaims":    []any{"Capability fixture does not claim production auth readiness."},
				"scenarioShapes": []any{
					map[string]any{
						"scenarioId":             "sample.backend.auth.missing_bearer_fails_closed",
						"candidateRequirementId": "REQ-SAMPLE-AUTH-001",
						"summary":                "Requests without authentication headers fail closed before protected backend state is accessed.",
						"requiredEvidence":       []any{"negative_test"},
						"ownerQuestions":         []any{"Should anonymous health checks bypass this invariant?"},
						"nonClaims":              []any{"Scenario fixture does not claim every auth edge case."},
					},
				},
			},
		},
		"scenarioAnchors": []any{
			map[string]any{
				"scenarioId":           "sample.backend.auth.missing_bearer_fails_closed",
				"selector":             "service/tests/auth_test.py::test_missing_bearer_fails_closed",
				"sourcePath":           "service/tests/auth_test.py",
				"commandRefs":          []any{"sample.pytest.auth"},
				"status":               "candidate",
				"positiveWitness":      false,
				"falsificationWitness": true,
				"nonClaims":            []any{"Anchor fixture does not execute pytest."},
			},
		},
		"requiredVerification": []any{
			map[string]any{
				"commandId":        "sample.pytest.auth",
				"command":          "uv run pytest service/tests/auth_test.py",
				"environmentClass": "local_python",
				"reason":           "Auth failure mode needs an executable negative witness.",
				"nonClaims":        []any{"Command fixture does not prove test freshness."},
			},
		},
		"nonClaims": []any{"Capability map fixture is not merge evidence."},
	}
}

func firstCapability(input map[string]any) map[string]any {
	return input["capabilities"].([]any)[0].(map[string]any)
}

func firstScenarioShape(input map[string]any) map[string]any {
	return firstCapability(input)["scenarioShapes"].([]any)[0].(map[string]any)
}

func firstScenarioAnchor(input map[string]any) map[string]any {
	return input["scenarioAnchors"].([]any)[0].(map[string]any)
}

func diagnosticContains(diagnostics []any, key string, needle string) bool {
	for _, raw := range diagnostics {
		diagnostic := raw.(map[string]any)
		if diagnostic["key"] != key {
			continue
		}
		encoded, _ := json.Marshal(diagnostic["value"])
		if strings.Contains(string(encoded), needle) {
			return true
		}
	}
	return false
}
