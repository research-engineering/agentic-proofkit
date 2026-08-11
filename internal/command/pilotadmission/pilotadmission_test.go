package pilotadmission

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
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
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.057912462745542653837414866608340350115558004021771379883888595693744581144285")
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

func TestBuildAllFromContractEnvelopeAdmitsBothOwnedInputs(t *testing.T) {
	firstInput := validPilotInput()
	stackDiverseInput := validPilotInput()
	stackDiverseInput["pilotId"] = "proofkit.test.pilot.stack-diverse"
	stackDiverseInput["stackDiversity"] = validStackDiversity()
	stackDiverseInput["cacheNegativeChecks"] = validCacheNegativeChecks()
	impactInput := stackDiverseInput["impactDemos"].([]any)[0].(map[string]any)["impactInput"].(map[string]any)
	impactInput["changedBindingRecordIds"] = []any{"REQ-PROOFKIT-001"}
	impactInput["changedPaths"] = []any{
		"docs/specs/proofkit/requirements.v1.json",
		"internal/proofkit/witness_test.go",
	}
	impactInput["changedWitnessPathCoverage"] = []any{
		map[string]any{
			"path":      "internal/proofkit/witness_test.go",
			"recordIds": []any{"REQ-PROOFKIT-001"},
		},
	}

	envelope := map[string]any{
		"schema":            "proofkit.pilot-admission.v1",
		"input":             firstInput,
		"stackDiverseInput": stackDiverseInput,
	}
	first, firstExitCode, stackDiverse, stackDiverseExitCode, err := BuildAllFromContractEnvelope(envelope)
	if err != nil {
		t.Fatalf("BuildAllFromContractEnvelope() error = %v", err)
	}
	if firstExitCode != 0 || first.State != "passed" {
		t.Fatalf("first exit=%d state=%s, want passed", firstExitCode, first.State)
	}
	if stackDiverseExitCode != 0 || stackDiverse.State != "passed" {
		t.Fatalf("stack-diverse exit=%d state=%s rules=%#v, want passed", stackDiverseExitCode, stackDiverse.State, stackDiverse.RuleResults)
	}

	delete(envelope, "stackDiverseInput")
	if _, _, _, _, err := BuildAllFromContractEnvelope(envelope); err == nil || !strings.Contains(err.Error(), "must declare object stackDiverseInput") {
		t.Fatalf("BuildAllFromContractEnvelope() error = %v, want missing field rejection", err)
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

func validStackDiversity() map[string]any {
	dimensions := make([]any, 0, len(stackDiversityDimensions))
	for _, dimension := range stackDiversityDimensions {
		dimensions = append(dimensions, map[string]any{
			"baseline":  "baseline-" + dimension,
			"candidate": "candidate-" + dimension,
			"dimension": dimension,
			"evidence":  "docs/evidence/" + dimension + ".md",
		})
	}
	return map[string]any{
		"baselinePilotId": "proofkit.test.pilot",
		"dimensions":      dimensions,
	}
}

func validCacheNegativeChecks() []any {
	checks := make([]any, 0, len(cacheInvalidationClasses))
	for _, inputClass := range cacheInvalidationClasses {
		checks = append(checks, map[string]any{
			"checkId":                     "proofkit.test.cache." + inputClass,
			"evidence":                    "Cache invalidates on " + inputClass + " changes.",
			"expectedOutcome":             "invalidate_output",
			"invalidatedInputClass":       inputClass,
			"liveOrCredentialedCacheable": false,
		})
	}
	return checks
}
