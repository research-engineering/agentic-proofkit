package adoptioncontract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/pilotadmission"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildRejectsMalformedAggregateRoot(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		options Options
		want    string
	}{
		{
			name: "schema drift",
			mutate: func(input map[string]any) {
				input["schema"] = "proofkit.other.v1"
			},
			options: Options{Mode: "workflow"},
			want:    "schema drift",
		},
		{
			name: "missing envelope id",
			mutate: func(input map[string]any) {
				delete(input, "envelopeId")
			},
			options: Options{Mode: "workflow"},
			want:    "envelopeId",
		},
		{
			name: "malformed non claims",
			mutate: func(input map[string]any) {
				input["nonClaims"] = "not an array"
			},
			options: Options{Mode: "workflow"},
			want:    "nonClaims",
		},
		{
			name: "unknown root key",
			mutate: func(input map[string]any) {
				input["ambientPolicy"] = true
			},
			options: Options{Mode: "workflow"},
			want:    "unsupported field",
		},
		{
			name: "missing unrelated pilot payload still fails workflow mode",
			mutate: func(input map[string]any) {
				delete(input, "pilot")
			},
			options: Options{Mode: "workflow"},
			want:    "pilot",
		},
		{
			name: "missing unrelated gradual payload still fails workflow mode",
			mutate: func(input map[string]any) {
				delete(input, "gradual")
			},
			options: Options{Mode: "workflow"},
			want:    "gradual",
		},
		{
			name: "missing root non claims fails",
			mutate: func(input map[string]any) {
				delete(input, "nonClaims")
			},
			options: Options{Mode: "workflow"},
			want:    "nonClaims",
		},
		{
			name: "selected child schema drift fails",
			mutate: func(input map[string]any) {
				input["workflow"].(map[string]any)["schema"] = "proofkit.wrong.v1"
			},
			options: Options{Mode: "workflow"},
			want:    "workflow envelope schema drift",
		},
		{
			name: "unselected sibling child schema drift still fails",
			mutate: func(input map[string]any) {
				input["pilot"].(map[string]any)["schema"] = "proofkit.wrong.v1"
			},
			options: Options{Mode: "workflow"},
			want:    "pilot envelope schema drift",
		},
		{
			name: "unselected sibling missing child key still fails",
			mutate: func(input map[string]any) {
				delete(input["gradual"].(map[string]any), "guidance")
			},
			options: Options{Mode: "workflow"},
			want:    "gradual envelope must declare object guidance",
		},
		{
			name: "missing unrelated workflow payload still fails pilot mode",
			mutate: func(input map[string]any) {
				delete(input, "workflow")
			},
			options: Options{Mode: "pilot"},
			want:    "workflow",
		},
		{
			name:    "unknown mode",
			mutate:  func(map[string]any) {},
			options: Options{Mode: "unknown"},
			want:    "mode must be adoption, bootstrap, guidance, pilot, or workflow",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validAggregateEnvelope()
			item.mutate(input)
			_, _, err := Build(input, item.options)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestValidateOptionsOwnsModePilotAndCompatibilityPolicy(t *testing.T) {
	cases := []struct {
		name    string
		options Options
		want    string
	}{
		{name: "unknown mode", options: Options{Mode: "unknown"}, want: "mode must be adoption, bootstrap, guidance, pilot, or workflow"},
		{name: "unknown pilot", options: Options{Mode: "pilot", Pilot: "later"}, want: "--pilot requires first, stack-diverse, or all"},
		{name: "agent envelope incompatible mode", options: Options{Mode: "adoption", AgentEnvelope: true}, want: "--agent-envelope is valid only"},
		{name: "materialization manifest incompatible mode", options: Options{Mode: "workflow", MaterializationManifest: true}, want: "--materialization-manifest is valid only"},
		{name: "mutually exclusive output modes", options: Options{Mode: "bootstrap", AgentEnvelope: true, MaterializationManifest: true}, want: "mutually exclusive"},
		{name: "pilot flag incompatible mode", options: Options{Mode: "workflow", Pilot: "all"}, want: "--pilot is valid only"},
		{name: "guidance flag incompatible mode", options: Options{Mode: "workflow", Guidance: gradualadoption.GuidanceOptions{GuidanceMode: "observe"}}, want: "valid only for guidance mode"},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := ValidateOptions(item.options)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("ValidateOptions() error=%v, want %q", err, item.want)
			}
		})
	}

	if err := ValidateOptions(Options{Mode: "guidance", Guidance: gradualadoption.GuidanceOptions{GuidanceMode: "observe"}}); err != nil {
		t.Fatalf("ValidateOptions() rejected valid guidance override: %v", err)
	}
}

func TestBuildDelegatesModesWithParity(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.064840772979561884532437014395024443929767634378814122316392969426222714882392")
	cases := []struct {
		name    string
		options Options
		direct  func(t *testing.T, input map[string]any) (any, int)
	}{
		{
			name:    "workflow",
			options: Options{Mode: "workflow"},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := adoptionworkflow.BuildFromContractEnvelope(testWorkflowEnvelope(input))
				if err != nil {
					t.Fatalf("direct workflow failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name:    "workflow agent envelope",
			options: Options{Mode: "workflow", AgentEnvelope: true},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := adoptionworkflow.BuildEnvelopeFromContractEnvelope(testWorkflowEnvelope(input))
				if err != nil {
					t.Fatalf("direct workflow envelope failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name:    "adoption",
			options: Options{Mode: "adoption"},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := gradualadoption.BuildFromContractEnvelope(testAdoptionEnvelope(input))
				if err != nil {
					t.Fatalf("direct adoption failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name:    "bootstrap",
			options: Options{Mode: "bootstrap"},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := gradualadoption.BuildBootstrapFromContractEnvelope(testBootstrapEnvelope(input))
				if err != nil {
					t.Fatalf("direct bootstrap failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name:    "bootstrap agent envelope",
			options: Options{Mode: "bootstrap", AgentEnvelope: true},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := gradualadoption.BuildBootstrapEnvelopeFromContractEnvelope(testBootstrapEnvelope(input))
				if err != nil {
					t.Fatalf("direct bootstrap envelope failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name:    "bootstrap materialization",
			options: Options{Mode: "bootstrap", MaterializationManifest: true},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := gradualadoption.BuildBootstrapMaterializationManifestFromContractEnvelope(testBootstrapEnvelope(input))
				if err != nil {
					t.Fatalf("direct bootstrap materialization failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name: "guidance with overrides",
			options: Options{
				Mode: "guidance",
				Guidance: gradualadoption.GuidanceOptions{
					CheckedScope: "none",
					GuidanceMode: "warn",
				},
			},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := gradualadoption.BuildGuidanceFromContractEnvelope(testGuidanceEnvelope(input), gradualadoption.GuidanceOptions{
					CheckedScope: "none",
					GuidanceMode: "warn",
				})
				if err != nil {
					t.Fatalf("direct guidance failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name: "guidance agent envelope",
			options: Options{
				AgentEnvelope: true,
				Mode:          "guidance",
				Guidance: gradualadoption.GuidanceOptions{
					CheckedScope: "none",
					GuidanceMode: "warn",
				},
			},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				output, exitCode, err := gradualadoption.BuildGuidanceEnvelopeFromContractEnvelope(testGuidanceEnvelope(input), gradualadoption.GuidanceOptions{
					CheckedScope: "none",
					GuidanceMode: "warn",
				})
				if err != nil {
					t.Fatalf("direct guidance envelope failed: %v", err)
				}
				return output, exitCode
			},
		},
		{
			name:    "pilot first",
			options: Options{Mode: "pilot", Pilot: "first"},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				record, exitCode, err := pilotadmission.BuildFromContractEnvelope(testPilotEnvelope(input, "input"), "input", pilotadmission.Options{})
				if err != nil {
					t.Fatalf("direct pilot first failed: %v", err)
				}
				return record.JSONValue(), exitCode
			},
		},
		{
			name:    "pilot stack diverse",
			options: Options{Mode: "pilot", Pilot: "stack-diverse"},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				record, exitCode, err := pilotadmission.BuildFromContractEnvelope(testPilotEnvelope(input, "stackDiverseInput"), "stackDiverseInput", pilotadmission.Options{RequireStackDiverseReleaseCandidate: true})
				if err != nil {
					t.Fatalf("direct pilot stack-diverse failed: %v", err)
				}
				return record.JSONValue(), exitCode
			},
		},
		{
			name:    "pilot all",
			options: Options{Mode: "pilot", Pilot: "all"},
			direct: func(t *testing.T, input map[string]any) (any, int) {
				t.Helper()
				first, firstExitCode, err := pilotadmission.BuildFromContractEnvelope(testPilotEnvelope(input, "input"), "input", pilotadmission.Options{})
				if err != nil {
					t.Fatalf("direct pilot first failed: %v", err)
				}
				stack, stackExitCode, err := pilotadmission.BuildFromContractEnvelope(testPilotEnvelope(input, "stackDiverseInput"), "stackDiverseInput", pilotadmission.Options{RequireStackDiverseReleaseCandidate: true})
				if err != nil {
					t.Fatalf("direct pilot stack-diverse failed: %v", err)
				}
				exitCode := 0
				if firstExitCode != 0 || stackExitCode != 0 {
					exitCode = 1
				}
				return []any{first.JSONValue(), stack.JSONValue()}, exitCode
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validAggregateEnvelope()
			got, gotExitCode, err := Build(input, item.options)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			want, wantExitCode := item.direct(t, input)
			if gotExitCode != wantExitCode {
				t.Fatalf("exit=%d want %d", gotExitCode, wantExitCode)
			}
			if stableJSON(t, got) != stableJSON(t, want) {
				t.Fatalf("aggregate output drift\n got: %s\nwant: %s", stableJSON(t, got), stableJSON(t, want))
			}
		})
	}
}

func TestBuildRejectsInvalidFlagCombinations(t *testing.T) {
	cases := []struct {
		name    string
		options Options
		want    string
	}{
		{name: "agent envelope on adoption", options: Options{Mode: "adoption", AgentEnvelope: true}, want: "--agent-envelope"},
		{name: "materialization on guidance", options: Options{Mode: "guidance", MaterializationManifest: true}, want: "--materialization-manifest"},
		{name: "agent envelope with materialization", options: Options{Mode: "bootstrap", AgentEnvelope: true, MaterializationManifest: true}, want: "mutually exclusive"},
		{name: "pilot flag on workflow", options: Options{Mode: "workflow", Pilot: "all"}, want: "--pilot"},
		{name: "guidance override on bootstrap", options: Options{Mode: "bootstrap", Guidance: gradualadoption.GuidanceOptions{GuidanceMode: "warn"}}, want: "--guidance-mode"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, _, err := Build(validAggregateEnvelope(), item.options)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildStackDiverseCannotRouteThroughFirstPilotPayload(t *testing.T) {
	input := validAggregateEnvelope()
	pilot := input["pilot"].(map[string]any)
	pilot["stackDiverseInput"] = pilot["input"]

	output, exitCode, err := Build(input, Options{Mode: "pilot", Pilot: "stack-diverse"})
	if err != nil {
		t.Fatalf("Build() unexpected error=%v", err)
	}
	if exitCode == 0 {
		t.Fatalf("stack-diverse route through first payload must fail: %#v", output)
	}
	if !strings.Contains(stableJSON(t, output), "stack-diverse pilot must declare stackDiversity") {
		t.Fatalf("failed stack-diverse route did not expose stack-diverse failure: %s", stableJSON(t, output))
	}
}

func stableJSON(t *testing.T, value any) string {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal stable JSON: %v", err)
	}
	return string(content)
}

func testWorkflowEnvelope(input map[string]any) map[string]any {
	workflow := input["workflow"].(map[string]any)
	return map[string]any{"schema": workflow["schema"], "workflow": workflow["workflow"]}
}

func testAdoptionEnvelope(input map[string]any) map[string]any {
	gradual := input["gradual"].(map[string]any)
	return map[string]any{"schema": gradual["schema"], "input": gradual["input"]}
}

func testBootstrapEnvelope(input map[string]any) map[string]any {
	gradual := input["gradual"].(map[string]any)
	return map[string]any{
		"bootstrap": gradual["bootstrap"],
		"guidance":  gradual["guidance"],
		"input":     gradual["input"],
		"schema":    gradual["schema"],
	}
}

func testGuidanceEnvelope(input map[string]any) map[string]any {
	gradual := input["gradual"].(map[string]any)
	return map[string]any{"guidance": gradual["guidance"], "input": gradual["input"], "schema": gradual["schema"]}
}

func testPilotEnvelope(input map[string]any, field string) map[string]any {
	pilot := input["pilot"].(map[string]any)
	return map[string]any{"schema": pilot["schema"], field: pilot[field]}
}

func validAggregateEnvelope() map[string]any {
	return map[string]any{
		"schema":     "proofkit.adoption-contract-envelope.v1",
		"envelopeId": "proofkit.test.adoption.aggregate",
		"workflow": map[string]any{
			"schema":   "proofkit.adoption-workflow.v1",
			"workflow": workflowInput(),
		},
		"gradual": map[string]any{
			"schema":    "proofkit.gradual-adoption-profile.v1",
			"input":     adoptionInput(),
			"bootstrap": bootstrapContract(),
			"guidance":  guidanceContract(),
		},
		"pilot": map[string]any{
			"schema":            "proofkit.pilot-admission.v1",
			"input":             pilotInput("proofkit.test.pilot.first", false),
			"stackDiverseInput": pilotInput("proofkit.test.pilot.stack-diverse", true),
		},
		"nonClaims": []any{"Aggregate adoption contract fixture does not execute native witnesses."},
	}
}

func workflowInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"workflowId":    "proofkit.test.workflow",
		"scenario":      "release_channel",
		"presetId":      nil,
		"inputRefs": []any{
			map[string]any{"inputKind": "release_authority", "path": "proofkit/release-authority.v1.json", "refId": "proofkit.release-authority"},
			map[string]any{"inputKind": "registry_consumer", "path": "proofkit/registry-consumer.v1.json", "refId": "proofkit.registry-consumer"},
		},
		"nonClaims": []any{"Workflow fixture does not execute generated commands."},
	}
}

func adoptionInput() map[string]any {
	return map[string]any{
		"schemaVersion":     json.Number("1"),
		"adoptionId":        "proofkit.test.adoption",
		"adoptionMode":      "non_blocking",
		"packageVersionRef": "agentic-proofkit@local",
		"rolloutClaim":      false,
		"nonClaims":         []any{"Gradual adoption fixture does not prove rollout readiness."},
		"repository": map[string]any{
			"customRuleBoundary": "profile_only",
			"primaryLanguages":   []any{"go"},
			"profilePath":        "proofkit/profile.json",
			"repositoryClass":    "go_cli",
			"repositoryId":       "proofkit.test.repo",
			"verifierCodeCopied": false,
		},
		"module": map[string]any{
			"moduleId":       "proofkit.test.module",
			"requirementIds": []any{"REQ-PROOFKIT-TEST-001"},
			"specPath":       "docs/specs/test/requirements.v1.json",
		},
		"proofBinding": map[string]any{
			"bindingFormat":     "requirement_to_witness",
			"bindingPath":       "proofkit/proof-bindings.json",
			"requirementIds":    []any{"REQ-PROOFKIT-TEST-001"},
			"witnessCommandIds": []any{"proofkit.test.command"},
		},
		"nativeWitnesses": nativeWitnesses(),
		"agentReport": map[string]any{
			"artifactPath":   "artifacts/proofkit/gradual-adoption.json",
			"outputMode":     "non_blocking",
			"reportKind":     "proofkit.gradual-adoption",
			"routeQuestions": []any{"what changed", "what proves it", "who owns it"},
			"schemaId":       "proofkit.gradual-adoption-profile.v1",
		},
		"budget": budget(),
		"rollback": map[string]any{
			"disableCommand": "remove proofkit gradual-adoption report from non-blocking CI",
			"owner":          "repo-maintainers",
			"versionPin":     "agentic-proofkit@previous",
		},
	}
}

func bootstrapContract() map[string]any {
	return map[string]any{
		"bootstrapId": "proofkit.test.bootstrap",
		"defaultMode": "observe",
		"paths": map[string]any{
			"adoptionGuidancePath":       "proofkit/guidance.json",
			"adoptionProfilePath":        "proofkit/profile.json",
			"adoptionReportArtifactPath": "artifacts/proofkit/adoption.json",
			"guidanceReportArtifactPath": "artifacts/proofkit/guidance.json",
			"witnessPlanInputPath":       "proofkit/witness-plan.json",
		},
		"scopeEvidence": map[string]any{
			"checkedScope":   "none",
			"touchedRuleIds": []any{},
		},
		"commands":  []any{"go test ./internal/command/gradualadoption"},
		"nonClaims": []any{"Bootstrap fixture does not prove rollout readiness."},
	}
}

func guidanceContract() map[string]any {
	return map[string]any{
		"guidanceId":  "proofkit.test.guidance",
		"defaultMode": "observe",
		"scopeEvidence": map[string]any{
			"checkedScope":   "none",
			"touchedRuleIds": []any{},
		},
		"ownerRoute": map[string]any{
			"evidencePaths":     []any{"artifacts/proofkit/source.json"},
			"primaryOwner":      "repo-maintainers",
			"proofBindingPaths": []any{"proofkit/proof-bindings.json"},
			"specPaths":         []any{"docs/specs/test/requirements.v1.json"},
		},
		"agentGuidance": map[string]any{
			"artifactPath":                     "artifacts/proofkit/guidance.json",
			"blockedPreconditions":             []any{},
			"callerSuggestedAutofixCandidates": []any{},
			"commands":                         []any{},
			"minimalAdoptionPath":              []any{"Keep proofkit adoption non-blocking until owner review."},
			"proofBindingsMissing":             []any{},
			"reportKind":                       "proofkit.gradual-adoption-guidance",
			"requiredNextActions":              []any{},
			"routeQuestions":                   []any{"what changed", "what proves it", "who owns it"},
			"schemaId":                         "proofkit.gradual-adoption-guidance.v1",
		},
		"modernization": map[string]any{
			"candidateBoundaries":         []any{},
			"promoteOnlyAfterOwnerReview": true,
		},
		"nonClaims": []any{"Guidance fixture does not prove rollout readiness."},
	}
}

func nativeWitnesses() map[string]any {
	return map[string]any{
		"vocabulary": map[string]any{
			"artifactKinds":      []any{"json"},
			"credentialClasses":  []any{"none"},
			"environmentClasses": []any{"local-go"},
			"environmentClassPolicies": []any{map[string]any{
				"cachePolicies":     []any{"read-only"},
				"credentialClasses": []any{"none"},
				"environmentClass":  "local-go",
				"networkPolicies":   []any{"none"},
			}},
			"parallelGroups": []any{"local-go"},
		},
		"commands": []any{map[string]any{
			"schemaVersion":     json.Number("1"),
			"id":                "proofkit.test.command",
			"argv":              []any{"go", "test", "./..."},
			"cachePolicy":       "read-only",
			"credentialClass":   "none",
			"cwd":               ".",
			"environment":       map[string]any{"allowlist": []any{}, "classes": []any{"local-go"}, "inherit": "none"},
			"exitCodePolicy":    map[string]any{"kind": "zero", "successCodes": []any{json.Number("0")}},
			"expectedArtifacts": []any{},
			"networkPolicy":     "none",
			"parallelGroup":     "local-go",
			"timeoutMs":         json.Number("60000"),
		}},
	}
}

func budget() map[string]any {
	return map[string]any{
		"copiedVerifierFileCount": json.Number("0"),
		"customRuleCount":         json.Number("0"),
		"maxAddedSeconds":         json.Number("10"),
		"maxCustomRuleCount":      json.Number("0"),
		"maxProfileLines":         json.Number("80"),
		"maxSetupMinutes":         json.Number("20"),
		"profileLines":            json.Number("42"),
	}
}

func pilotInput(pilotID string, stackDiverse bool) map[string]any {
	input := map[string]any{
		"schemaVersion": json.Number("1"),
		"pilotId":       pilotID,
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
		"impactDemos":         []any{impactDemo("proofkit.impact.demo", false)},
		"cacheNegativeChecks": []any{},
		"nonClaims":           []any{"Pilot admission fixture does not claim rollout readiness."},
		"packageVersionRef":   "package.json",
		"pilotMode":           "non_blocking",
		"rolloutClaim":        false,
	}
	if stackDiverse {
		input["stackDiversity"] = stackDiversity()
		input["cacheNegativeChecks"] = cacheNegativeChecks()
		input["impactDemos"] = []any{impactDemo("proofkit.impact.demo.stack", true)}
	}
	return input
}

func stackDiversity() map[string]any {
	dimensions := []any{}
	for _, dimension := range []string{"docs_spec_layout", "generated_artifact_policy", "language_runtime_test_shape", "proof_environment_classes", "repository_topology"} {
		dimensions = append(dimensions, map[string]any{
			"baseline":  "baseline-" + dimension,
			"candidate": "candidate-" + dimension,
			"dimension": dimension,
			"evidence":  "docs/evidence/" + dimension + ".md",
		})
	}
	return map[string]any{
		"baselinePilotId": "proofkit.test.pilot.first",
		"dimensions":      dimensions,
	}
}

func cacheNegativeChecks() []any {
	checks := []any{}
	for _, inputClass := range []string{"package_version", "profile", "schema", "source"} {
		checks = append(checks, map[string]any{
			"checkId":                     "proofkit.cache." + inputClass,
			"evidence":                    "Cache invalidates on " + inputClass + " changes.",
			"expectedOutcome":             "invalidate_output",
			"invalidatedInputClass":       inputClass,
			"liveOrCredentialedCacheable": false,
		})
	}
	return checks
}

func impactDemo(demoID string, stackDiverse bool) map[string]any {
	impactInput := map[string]any{
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
	}
	if stackDiverse {
		impactInput["changedBindingRecordIds"] = []any{"REQ-PROOFKIT-001"}
		impactInput["changedPaths"] = []any{"docs/specs/proofkit/requirements.v1.json", "internal/proofkit/witness_test.go"}
		impactInput["changedWitnessPathCoverage"] = []any{
			map[string]any{"path": "internal/proofkit/witness_test.go", "recordIds": []any{"REQ-PROOFKIT-001"}},
		}
	}
	return map[string]any{
		"demoId":                  demoID,
		"generatedMirrorPaths":    []any{"docs/generated/requirements.md"},
		"sourceOwnedChangedPaths": []any{"docs/specs/proofkit/requirements.v1.json"},
		"impactInput":             impactInput,
	}
}
