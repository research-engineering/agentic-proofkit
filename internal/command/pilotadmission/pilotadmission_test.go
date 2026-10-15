package pilotadmission

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/compactfixture"
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
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.022694204409755669452952597914671471098671263975815015361039173611690240692220")
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
	impactInput["changedBindingRecordIds"] = []any{pilotTestBindingRecordID}
	impactInput["changedPaths"] = []any{
		"docs/specs/proofkit/requirements.v1.json",
		"internal/proofkit/witness_test.go",
	}
	impactInput["changedWitnessPathCoverage"] = []any{
		map[string]any{
			"path": "internal/proofkit/witness_test.go",
			"routes": []any{map[string]any{
				"bindingRecordId":      pilotTestBindingRecordID,
				"resolutionOrderIndex": json.Number("0"),
				"role":                 "positive",
				"selector":             pilotTestWitnessSelector,
				"witnessRouteId":       pilotTestWitnessRouteID,
			}},
		},
	}

	envelope := map[string]any{
		"schema":            contractEnvelopeSchema,
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
		"schemaVersion": json.Number("2"),
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
				"schemaVersion":              json.Number("2"),
				"baseCommit":                 "base",
				"baseRef":                    "main",
				"changedBindingRecordIds":    []any{},
				"changedPaths":               []any{"docs/specs/proofkit/requirements.v1.json"},
				"changedRequirementIds":      []any{"REQ-PROOFKIT-001"},
				"changedWitnessPathCoverage": []any{},
				"generatedArtifactRules":     []any{},
				"headCommit":                 nil,
				"headRef":                    "feature/proofkit",
				"ignoredProofLikePaths":      []any{},
				"obligationCatalog": []any{map[string]any{
					"bindingRecordId":                   pilotTestBindingRecordID,
					"blockingStatus":                    "blocking",
					"commands":                          []any{"go test ./..."},
					"declaredWitnessRoutes":             pilotTestRoutes.Values([]string{"local-go"}, []string{"go test ./..."}),
					"declaredMutationResistanceClaimId": "claim.unverified",
					"preconditioned":                    false,
					"requirementId":                     "REQ-PROOFKIT-001",
					"requiredEnvironmentClasses":        []any{"local-go"},
					"scenarioId":                        "proofkit.surface::proofkit.scenario",
					"surfaceId":                         "proofkit.surface",
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

func TestBuildRejectsCompleteLegacyV1Inputs(t *testing.T) {
	direct := validPilotInput()
	direct["schemaVersion"] = json.Number("1")
	if _, _, err := Build(direct, Options{}); err == nil || !strings.Contains(err.Error(), "schemaVersion must be 2") {
		t.Fatalf("Build() error = %v, want complete v1 direct-input rejection", err)
	}

	first := validPilotInput()
	stackDiverse := validPilotInput()
	legacyFirstEnvelope := map[string]any{
		"schema": "proofkit.pilot-admission.v1",
		"input":  first,
	}
	if _, _, err := BuildFromContractEnvelope(legacyFirstEnvelope, "input", Options{}); err == nil || !strings.Contains(err.Error(), "schema drift") {
		t.Fatalf("BuildFromContractEnvelope() error = %v, want complete v1 envelope rejection", err)
	}

	legacyAggregateEnvelope := map[string]any{
		"schema":            "proofkit.pilot-admission.v1",
		"input":             first,
		"stackDiverseInput": stackDiverse,
	}
	if _, _, _, _, err := BuildAllFromContractEnvelope(legacyAggregateEnvelope); err == nil || !strings.Contains(err.Error(), "schema drift") {
		t.Fatalf("BuildAllFromContractEnvelope() error = %v, want complete v1 aggregate rejection", err)
	}
}

const (
	pilotTestWitnessSelector              = "internal/proofkit/witness_test.go::TestWitness"
	pilotTestFalsificationWitnessSelector = "internal/proofkit/witness_test.go::TestWitnessFalsification"
)

var pilotTestRoutes = compactfixture.MustRoutes(compactproofcontract.BindingIdentity{
	RequirementID: "REQ-PROOFKIT-001",
	ScenarioID:    "proofkit.surface::proofkit.scenario",
	SurfaceID:     "proofkit.surface",
}, pilotTestWitnessSelector, pilotTestFalsificationWitnessSelector)

var pilotTestBindingRecordID = pilotTestRoutes.BindingRecordID
var pilotTestWitnessRouteID = pilotTestRoutes.PositiveRouteID

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

// Caller text that the report echoes is admitted before projection: secret-
// shaped values refuse the input without a report and are never repeated,
// while ordinary wrong values stay collected failures with their echo.
func TestBuildAdmitsReportVisibleCallerTextBeforeProjection(t *testing.T) {
	secret := "GL" + "PAT" + "-EXAMPLE-01"
	if !admit.ContainsSecretLikeValue(secret) {
		t.Fatal("synthetic value must satisfy the shared secret-like predicate")
	}
	sites := []struct {
		name string
		set  func(map[string]any, any)
	}{
		{"blocking status", func(input map[string]any, value any) {
			input["blockingRequirements"].(map[string]any)["requirements"].([]any)[0].(map[string]any)["status"] = value
		}},
		{"pilot mode", func(input map[string]any, value any) { input["pilotMode"] = value }},
		{"stack dimension", func(input map[string]any, value any) {
			input["stackDiversity"].(map[string]any)["dimensions"].([]any)[0].(map[string]any)["dimension"] = value
		}},
		{"cache outcome", func(input map[string]any, value any) {
			input["cacheNegativeChecks"].([]any)[0].(map[string]any)["expectedOutcome"] = value
		}},
		{"cache input class", func(input map[string]any, value any) {
			input["cacheNegativeChecks"].([]any)[0].(map[string]any)["invalidatedInputClass"] = value
		}},
	}
	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			input := validPilotInput()
			input["stackDiversity"] = validStackDiversity()
			input["cacheNegativeChecks"] = validCacheNegativeChecks()
			if record, code, err := Build(input, Options{}); err != nil || code != 0 || record.State != "passed" {
				t.Fatalf("control input must pass: code=%d err=%v rules=%#v", code, err, record.RuleResults)
			}
			for _, value := range []any{secret, "prefix " + secret} {
				refused := validPilotInputWith(site.set, value)
				record, code, err := Build(refused, Options{})
				if err == nil || code != 1 || record.ReportKind != "" || !strings.Contains(err.Error(), "must not contain secret-like values") {
					t.Fatalf("secret-shaped %s was not refused before the report: code=%d err=%v", site.name, code, err)
				}
				if strings.Contains(err.Error(), secret) {
					t.Fatal("refused value reached the error")
				}
			}
			ordinary := validPilotInputWith(site.set, "unrecognized_value")
			record, code, err := Build(ordinary, Options{})
			wire, _ := json.Marshal(record.JSONValue())
			if err != nil || code != 1 || record.State != "failed" || !strings.Contains(string(wire), "unrecognized_value") {
				t.Fatalf("ordinary wrong %s must stay a collected failure: code=%d err=%v", site.name, code, err)
			}
		})
	}
	// The raw pilotMode JSON value is echoed, so nested keys and strings count.
	for name, value := range map[string]any{
		"nested value": map[string]any{"mode": []any{secret}},
		"nested key":   map[string]any{secret: "non_blocking"},
	} {
		_, code, err := Build(validPilotInputWith(func(input map[string]any, value any) { input["pilotMode"] = value }, value), Options{})
		if err == nil || code != 1 || strings.Contains(err.Error(), secret) {
			t.Fatalf("pilotMode %s was not refused without echo: code=%d err=%v", name, code, err)
		}
	}
}

// The summary echoes pilotMode as serialized JSON, so the shared secret-like
// predicate is applied to that serialization: a credential label and its value
// split across a key and a string, or across array members, refuse the input.
// Empty or control-character keys are not secrets; such ordinary values stay
// collected failures with their echo.
func TestBuildAdmitsSerializedPilotModeBeforeEcho(t *testing.T) {
	setMode := func(input map[string]any, value any) { input["pilotMode"] = value }
	sensitive := "synthetic-fixture-value"
	token := "GL" + "PAT" + "-EXAMPLE-01"
	for name, value := range map[string]any{
		"password pair":         map[string]any{"password": sensitive},
		"token pair":            map[string]any{"token": "abcdefghijklmnop"},
		"authorization pair":    map[string]any{"authorization": "Basic " + sensitive},
		"split array":           []any{"password=", sensitive},
		"token after empty key": map[string]any{"": "ordinary", "z": token},
	} {
		t.Run(name, func(t *testing.T) {
			record, code, err := Build(validPilotInputWith(setMode, value), Options{})
			if err == nil || code != 1 || record.ReportKind != "" || err.Error() != "proofkit pilot pilotMode must not contain secret-like values" {
				t.Fatalf("pilotMode %v was not refused before the report: code=%d err=%v", value, code, err)
			}
		})
	}
	for name, value := range map[string]any{
		"empty key":   map[string]any{"": "ordinary"},
		"control key": map[string]any{"a\u0001": "ordinary"},
	} {
		t.Run(name, func(t *testing.T) {
			record, code, err := Build(validPilotInputWith(setMode, value), Options{})
			if err != nil || code != 1 || record.State != "failed" {
				t.Fatalf("ordinary pilotMode must stay a collected failure: code=%d err=%v", code, err)
			}
			wire, _ := json.Marshal(record.JSONValue())
			if !strings.Contains(string(wire), "pilotMode must be non_blocking") || !strings.Contains(string(wire), `"ordinary"`) {
				t.Fatalf("ordinary pilotMode failure or echo is missing: %s", wire)
			}
		})
	}
}

func validPilotInputWith(set func(map[string]any, any), value any) map[string]any {
	input := validPilotInput()
	input["stackDiversity"] = validStackDiversity()
	input["cacheNegativeChecks"] = validCacheNegativeChecks()
	set(input, value)
	return input
}

func TestBuildRejectsDuplicateCustomRuleIDsRegardlessOfPosition(t *testing.T) {
	withRules := func(ids ...string) map[string]any {
		input := validPilotInput()
		budget := input["infrastructureBudget"].(map[string]any)
		rules := []any{}
		for index, id := range ids {
			rules = append(rules, map[string]any{
				"downgradeGenericFailures": false,
				"owner":                    "proofkit.owner." + string(rune('a'+index)),
				"purpose":                  "Custom rule purpose.",
				"ruleId":                   id,
			})
		}
		count := json.Number(string(rune('0' + len(ids))))
		budget["customRules"], budget["customRuleCount"], budget["maxCustomRuleCount"] = rules, count, count
		return input
	}
	for _, ids := range [][]string{
		{"proofkit.custom.a", "proofkit.custom.a", "proofkit.custom.b"},
		{"proofkit.custom.a", "proofkit.custom.b", "proofkit.custom.a"},
	} {
		record, exitCode, err := Build(withRules(ids...), Options{})
		if err != nil {
			t.Fatalf("Build(%v) error=%v", ids, err)
		}
		encoded, _ := json.Marshal(record)
		if exitCode != 1 || record.State != "failed" || !strings.Contains(string(encoded), "custom rule ruleId must be sorted and unique") {
			t.Fatalf("Build(%v) admitted duplicate custom rule IDs: exit=%d record=%s", ids, exitCode, encoded)
		}
	}
	for _, ids := range [][]string{{}, {"proofkit.custom.a", "proofkit.custom.b"}, {"proofkit.custom.b", "proofkit.custom.a"}} {
		record, exitCode, err := Build(withRules(ids...), Options{})
		if err != nil || exitCode != 0 || record.State != "passed" {
			t.Fatalf("Build(%v) rejected unique custom rule IDs: exit=%d err=%v", ids, exitCode, err)
		}
		rules := diagnosticValue(t, record, "customRules").([]any)
		for index, id := range ids {
			if rules[index].(map[string]any)["ruleId"] != id {
				t.Fatalf("Build(%v) reordered custom rule diagnostics: %#v", ids, rules)
			}
		}
	}
}

func diagnosticValue(t *testing.T, record report.Record, key string) any {
	t.Helper()
	for _, diagnostic := range record.Diagnostics {
		if diagnostic.Key == key {
			return diagnostic.Value
		}
	}
	t.Fatalf("missing diagnostic %s", key)
	return nil
}
