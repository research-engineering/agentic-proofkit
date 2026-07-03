package pilotadmission

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAcceptsCompletePilotContract(t *testing.T) {
	record, exitCode, err := Build(validPilotInput(), Options{})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s rules=%#v, want passed", exitCode, record.State, record.RuleResults)
	}
}

func TestBuildRejectsUnknownPilotContractField(t *testing.T) {
	input := validPilotInput()
	input["ignoredPolicy"] = true

	_, _, err := Build(input, Options{})
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Build() error = %v, want unsupported field rejection", err)
	}
}

func TestBuildRejectsPilotDisplayCommandShellControlTokens(t *testing.T) {
	input := validPilotInput()
	input["agentReportRoutes"].([]any)[0].(map[string]any)["command"] = "agentic-proofkit render && curl example.test"

	_, _, err := Build(input, Options{})
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("Build() error = %v, want display-only command rejection", err)
	}
}

func validPilotInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"pilotId":       "proofkit.test.pilot",
		"profile": map[string]any{
			"commandMatcherBridge":      "none",
			"customRuleBoundary":        "profile_only",
			"primaryLanguages":          []any{"go"},
			"repositoryClass":           "go_cli",
			"repositoryId":              "proofkit.test",
			"structuredWitnessCommands": true,
			"verifierCodeCopied":        false,
		},
		"blockingRequirements": map[string]any{
			"dispositionPolicy":              "all_blocking_requirements_must_be_witnessed_or_explicitly_deferred",
			"explicitlyDeferredRequirements": json.Number("0"),
			"requirements": []any{map[string]any{
				"evidence":      "docs/specs/proofkit/requirements.v1.json",
				"owner":         "proofkit",
				"requirementId": "REQ-PROOFKIT-001",
				"status":        "witness_backed",
			}},
			"totalBlockingRequirements": json.Number("1"),
			"unmappedRequirements":      json.Number("0"),
			"witnessBackedRequirements": json.Number("1"),
		},
		"agentReportRoutes": []any{map[string]any{
			"artifactPath":       "artifacts/proofkit/report.json",
			"command":            "agentic-proofkit render",
			"expectedUpdatePath": "docs/specs/proofkit/requirements.v1.json",
			"reportKind":         "proofkit.report",
			"schemaId":           "proofkit.schema",
			"taskType":           "proofkit.review",
		}},
		"cacheScheduler": map[string]any{
			"cacheKeyInputs":                []any{"go.mod"},
			"destructiveConcurrencyAllowed": false,
			"invalidationInputs":            []any{"go.sum"},
			"maxParallelGroups":             json.Number("1"),
			"parallelGroups":                []any{"local"},
			"schedulerPolicy":               "bounded_parallel_groups",
		},
		"timingBudget": map[string]any{
			"maxAddedSeconds":          json.Number("5"),
			"measuredSeparately":       true,
			"reportArtifactPath":       "artifacts/proofkit/timing.json",
			"trackedFixtureAsBaseline": false,
		},
		"infrastructureBudget": map[string]any{
			"copiedVerifierFileCount":    json.Number("0"),
			"customRuleCount":            json.Number("0"),
			"customRules":                []any{},
			"manualTruthSurfaceCount":    json.Number("0"),
			"manualUpdateStepCount":      json.Number("0"),
			"maxCustomRuleCount":         json.Number("0"),
			"maxManualTruthSurfaceCount": json.Number("0"),
			"maxManualUpdateStepCount":   json.Number("0"),
			"maxProfileLines":            json.Number("100"),
			"profileLines":               json.Number("20"),
		},
		"falsePositiveBudget": map[string]any{
			"dispositionOwner":             "proofkit",
			"enforcementMode":              "non_blocking",
			"maxAllowedFalsePositiveCount": json.Number("0"),
			"sampleWindowRuns":             json.Number("1"),
		},
		"rollback": map[string]any{
			"owner":           "proofkit",
			"rollbackCommand": "agentic-proofkit previous-version",
			"versionPin":      "package.json",
		},
		"impactDemos": []any{map[string]any{
			"demoId":                  "proofkit.impact.demo",
			"generatedMirrorPaths":    []any{"docs/generated/requirements.md"},
			"sourceOwnedChangedPaths": []any{"docs/specs/proofkit/requirements.v1.json"},
			"impactInput": map[string]any{
				"schemaVersion":              json.Number("1"),
				"baseCommit":                 "base",
				"baseRef":                    "main",
				"changedBindingRecordIds":    []any{},
				"changedPaths":               []any{"docs/specs/proofkit/requirements.v1.json"},
				"changedRecordIds":           []any{"REQ-PROOFKIT-001"},
				"changedWitnessPathCoverage": []any{},
				"generatedArtifactRules":     []any{},
				"headCommit":                 nil,
				"headRef":                    "feature/proofkit",
				"ignoredProofLikePaths":      []any{},
				"obligationCatalog": []any{map[string]any{
					"blockingStatus":             "blocking",
					"commands":                   []any{"go test ./..."},
					"preconditioned":             false,
					"proofContractState":         "witness_backed",
					"recordId":                   "REQ-PROOFKIT-001",
					"requiredEnvironmentClasses": []any{"local-go"},
					"scenarioId":                 "proofkit.scenario",
					"surfaceId":                  "proofkit.surface",
				}},
				"preexistingFailures":         []any{},
				"proofLikePaths":              []any{},
				"unboundProofChangeRationale": "No unbound proof-like path changed.",
			},
		}},
		"cacheNegativeChecks": []any{},
		"nonClaims":           []any{"Pilot admission test input does not claim rollout readiness."},
		"packageVersionRef":   "package.json",
		"pilotMode":           "non_blocking",
		"rolloutClaim":        false,
	}
}
