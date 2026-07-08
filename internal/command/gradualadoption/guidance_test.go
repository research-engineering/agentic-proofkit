package gradualadoption

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestGuidanceReportsCandidateBoundariesAsAdvisoryOnly(t *testing.T) {
	cases := []struct {
		mode       string
		wantStatus string
	}{
		{mode: "observe", wantStatus: "skipped"},
		{mode: "warn", wantStatus: "warning"},
	}
	for _, item := range cases {
		t.Run(item.mode, func(t *testing.T) {
			output, exitCode, err := BuildGuidance(guidanceInputWithCandidateBoundary(item.mode), GuidanceOptions{})
			if err != nil {
				t.Fatalf("BuildGuidance returned error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("advisory candidate boundary must not fail %s mode: exit=%d output=%#v", item.mode, exitCode, output)
			}
			assertState(t, output, "passed")
			summary := output["summary"].(map[string]any)
			if summary["candidateBoundaryCount"] != 1 {
				t.Fatalf("candidateBoundaryCount=%v want 1", summary["candidateBoundaryCount"])
			}
			assertRuleStatus(t, output, "proofkit.gradual-adoption-guidance.candidate-boundaries", item.wantStatus)
			guidance := diagnosticValue(t, output, "guidance").(map[string]any)
			if len(anyArrayFromMap(guidance, "candidateBoundaries")) != 1 {
				t.Fatalf("guidance must expose one candidate boundary: %#v", guidance["candidateBoundaries"])
			}
			if !actionPlanHasPhase(guidance, "modernize-boundary") {
				t.Fatalf("guidance action plan must route candidate boundary resolution: %#v", guidance["agentActionPlan"])
			}
		})
	}
}

func TestGuidanceEnforcementFailsClosedForCandidateBoundaries(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.014122077686373699171401312512146978765072555275124478915795819268469905855861")
	cases := []struct {
		name           string
		mode           string
		checkedScope   string
		touchedRuleIDs []any
	}{
		{
			name:           "enforce all",
			mode:           "enforce-all",
			checkedScope:   "all",
			touchedRuleIDs: []any{},
		},
		{
			name:           "enforce touched",
			mode:           "enforce-touched",
			checkedScope:   "touched",
			touchedRuleIDs: []any{"proofkit.gradual-adoption-guidance.structure"},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := guidanceInputWithCandidateBoundary(item.mode)
			scope := input["scopeEvidence"].(map[string]any)
			scope["checkedScope"] = item.checkedScope
			scope["touchedRuleIds"] = item.touchedRuleIDs

			output, exitCode, err := BuildGuidance(input, GuidanceOptions{})
			if err != nil {
				t.Fatalf("BuildGuidance returned error: %v", err)
			}
			if exitCode != 1 {
				t.Fatalf("candidate boundaries must block enforcement before owner admission: exit=%d output=%#v", exitCode, output)
			}
			assertState(t, output, "failed")
			assertFailureContains(t, output, "enforcement modes require candidate boundaries to be owner-admitted before enforcement")
		})
	}
}

func TestGuidanceRejectsInvalidModeAndScopePairs(t *testing.T) {
	cases := []struct {
		name         string
		mode         any
		checkedScope any
		wantError    string
	}{
		{
			name:         "unknown mode",
			mode:         "audit",
			checkedScope: "all",
			wantError:    "guidanceMode must be one of",
		},
		{
			name:         "unknown scope",
			mode:         "observe",
			checkedScope: "partial",
			wantError:    "checkedScope must be one of",
		},
		{
			name:         "enforce all without full scope",
			mode:         "enforce-all",
			checkedScope: "touched",
			wantError:    "enforce-all requires checkedScope all",
		},
		{
			name:         "enforce touched without checked scope",
			mode:         "enforce-touched",
			checkedScope: "none",
			wantError:    "enforce-touched requires checkedScope touched or all",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := guidanceInput("observe")
			input["guidanceMode"] = item.mode
			input["scopeEvidence"].(map[string]any)["checkedScope"] = item.checkedScope

			output, exitCode, err := BuildGuidance(input, GuidanceOptions{})
			if err != nil {
				if !strings.Contains(err.Error(), item.wantError) {
					t.Fatalf("BuildGuidance error=%v, want %q", err, item.wantError)
				}
				return
			}
			if exitCode != 1 {
				t.Fatalf("BuildGuidance exit=%d output=%#v, want failure containing %q", exitCode, output, item.wantError)
			}
			assertFailureContains(t, output, item.wantError)
		})
	}
}

func TestGuidanceRejectsCandidateBoundaryWithoutAdvisoryNonClaim(t *testing.T) {
	input := guidanceInputWithCandidateBoundary("warn")
	candidate := firstCandidate(input)
	candidate["nonClaims"] = []any{"Candidate boundary is owned by the caller."}

	output, exitCode, err := BuildGuidance(input, GuidanceOptions{})
	if err != nil {
		t.Fatalf("BuildGuidance returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("missing advisory non-claim must fail: exit=%d output=%#v", exitCode, output)
	}
	assertFailureContains(t, output, "nonClaims must include candidate boundary advisory non-claim")
}

func TestGuidanceRejectsMalformedModernizationField(t *testing.T) {
	input := guidanceInput("warn")
	input["modernization"] = "not an object"

	output, exitCode, err := BuildGuidance(input, GuidanceOptions{})
	if err != nil {
		t.Fatalf("BuildGuidance returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("malformed modernization field must fail: exit=%d output=%#v", exitCode, output)
	}
	assertFailureContains(t, output, "gradual adoption modernization must be an object")
}

func TestGuidanceRejectsMalformedSourceReportWithoutPanic(t *testing.T) {
	input := guidanceInput("warn")
	input["sourceReport"].(map[string]any)["state"] = json.Number("1")

	_, _, err := BuildGuidance(input, GuidanceOptions{})
	if err == nil || !strings.Contains(err.Error(), "sourceReport state") {
		t.Fatalf("BuildGuidance error=%v, want typed sourceReport state admission failure", err)
	}
}

func TestGuidanceRejectsFutureSourceReportSchemaVersion(t *testing.T) {
	input := guidanceInput("warn")
	input["sourceReport"].(map[string]any)["schemaVersion"] = json.Number("2")

	_, _, err := BuildGuidance(input, GuidanceOptions{})
	if err == nil || !strings.Contains(err.Error(), "sourceReport schemaVersion must be 1") {
		t.Fatalf("BuildGuidance error=%v, want schemaVersion admission failure", err)
	}
}

func TestGuidanceEnvelopeRoutesCandidateBoundaryContextAndQuestions(t *testing.T) {
	output, exitCode, err := BuildGuidanceEnvelope(guidanceInputWithCandidateBoundary("warn"), GuidanceOptions{})
	if err != nil {
		t.Fatalf("BuildGuidanceEnvelope returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("advisory candidate boundary envelope must pass in warn mode: exit=%d output=%#v", exitCode, output)
	}
	assertEnvelopeContextRole(t, output, "candidate_boundary")
	assertEnvelopeQuestion(t, output, "Should auth own the webhook request admission boundary?")
	assertEnvelopeActionPhase(t, output, "modernize-boundary")
	assertEnvelopeActionEvidenceRef(t, output, "modernize-boundary", "test/auth-webhook.test.ts")
	assertEnvelopeActionEvidenceRef(t, output, "modernize-boundary", "docs/contracts/auth-webhook.json")
	assertEnvelopeActionRationale(t, output, "modernize-boundary", "Candidate boundaries remain advisory")
}

func TestGuidanceContractEnvelopePreservesModernization(t *testing.T) {
	input := guidanceInputWithCandidateBoundary("warn")
	input["defaultMode"] = "warn"
	contractEnvelope := map[string]any{
		"guidance": input,
		"input":    minimalAdoptionInput(),
		"schema":   "proofkit.gradual-adoption-profile.v1",
	}

	output, exitCode, err := BuildGuidanceFromContractEnvelope(contractEnvelope, GuidanceOptions{})
	if err != nil {
		t.Fatalf("BuildGuidanceFromContractEnvelope returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("contract-envelope candidate boundary must remain advisory in warn mode: exit=%d output=%#v", exitCode, output)
	}
	summary := output["summary"].(map[string]any)
	if summary["candidateBoundaryCount"] != 1 {
		t.Fatalf("contract envelope lost modernization candidate boundaries: summary=%#v", summary)
	}
}

func guidanceInputWithCandidateBoundary(mode string) map[string]any {
	input := guidanceInput(mode)
	input["modernization"] = map[string]any{
		"candidateBoundaries": []any{map[string]any{
			"admissionState":       "advisory",
			"affectedPaths":        []any{"src/auth/webhook.ts"},
			"blockedPreconditions": []any{},
			"boundaryId":           "candidate.auth-webhook-boundary",
			"candidateOwner":       "repository owner",
			"contractWitnessRefs":  []any{"docs/contracts/auth-webhook.json"},
			"migrationRefs":        []any{"docs/plans/auth-boundary.md"},
			"nativeWitnessRefs":    []any{"test/auth-webhook.test.ts"},
			"nonClaims":            []any{candidateBoundaryNonClaim},
			"observedFacts":        []any{"Webhook admission and signature checks change together."},
			"ownerQuestions":       []any{"Should auth own the webhook request admission boundary?"},
			"proofBindingRefs":     []any{"docs/contracts/requirement-proof-bindings.v1.json"},
			"requirementRefs":      []any{"REQ-AUTH-001"},
			"uncertainties":        []any{"Runtime ownership is not yet declared in stable requirements."},
		}},
		"promoteOnlyAfterOwnerReview": true,
	}
	return input
}

func guidanceInput(mode string) map[string]any {
	return map[string]any{
		"agentGuidance": map[string]any{
			"artifactPath":                     "artifacts/guidance.json",
			"blockedPreconditions":             []any{},
			"callerSuggestedAutofixCandidates": []any{},
			"commands":                         []any{"npm run check"},
			"minimalAdoptionPath":              []any{"Keep proofkit guidance advisory until owner routes are admitted."},
			"proofBindingsMissing":             []any{},
			"reportKind":                       "proofkit.gradual-adoption-guidance",
			"requiredNextActions":              []any{},
			"routeQuestions":                   []any{"what changed", "what proves it", "who owns it"},
			"schemaId":                         "proofkit.gradual-adoption-guidance.v1",
		},
		"guidanceId":   "proofkit.test.guidance",
		"guidanceMode": mode,
		"nonClaims": []any{
			"Guidance reports do not execute native witnesses.",
			"Guidance reports do not own repository proof truth.",
			"Guidance reports do not prove rollout readiness.",
		},
		"ownerRoute": map[string]any{
			"evidencePaths":     []any{"artifacts/guidance.json"},
			"primaryOwner":      "repository owner",
			"proofBindingPaths": []any{"docs/contracts/requirement-proof-bindings.v1.json"},
			"specPaths":         []any{"docs/specs/auth/requirements.v1.json"},
		},
		"schemaVersion": json.Number("1"),
		"scopeEvidence": map[string]any{
			"basis":          "caller_provided_touched_rule_ids",
			"checkedScope":   "all",
			"touchedRuleIds": []any{},
		},
		"sourceReport": passedSourceReport(),
	}
}

func minimalAdoptionInput() map[string]any {
	return map[string]any{
		"adoptionId":        "proofkit.test.adoption",
		"adoptionMode":      "non_blocking",
		"agentReport":       minimalAgentReport(),
		"budget":            minimalBudget(),
		"module":            minimalModule(),
		"nativeWitnesses":   minimalNativeWitnesses(),
		"nonClaims":         []any{"Gradual adoption does not prove rollout readiness."},
		"packageVersionRef": "agentic-proofkit@local",
		"proofBinding":      minimalProofBinding(),
		"repository":        minimalRepository(),
		"rollback":          map[string]any{"disableCommand": "remove proofkit command", "owner": "repository owner", "versionPin": "package.json"},
		"rolloutClaim":      false,
		"schemaVersion":     json.Number("1"),
	}
}

func minimalAgentReport() map[string]any {
	return map[string]any{
		"artifactPath":   "artifacts/adoption.json",
		"outputMode":     "non_blocking",
		"reportKind":     "proofkit.gradual-adoption",
		"routeQuestions": []any{"what changed", "what proves it", "who owns it"},
		"schemaId":       "proofkit.gradual-adoption.v1",
	}
}

func minimalBudget() map[string]any {
	return map[string]any{
		"copiedVerifierFileCount": json.Number("0"),
		"customRuleCount":         json.Number("0"),
		"maxAddedSeconds":         json.Number("5"),
		"maxCustomRuleCount":      json.Number("0"),
		"maxProfileLines":         json.Number("10"),
		"maxSetupMinutes":         json.Number("5"),
		"profileLines":            json.Number("1"),
	}
}

func minimalModule() map[string]any {
	return map[string]any{
		"moduleId":       "proofkit.test.module",
		"requirementIds": []any{"REQ-AUTH-001"},
		"specPath":       "docs/specs/auth/requirements.v1.json",
	}
}

func minimalProofBinding() map[string]any {
	return map[string]any{
		"bindingFormat":     "requirement_to_witness",
		"bindingPath":       "docs/contracts/requirement-proof-bindings.v1.json",
		"requirementIds":    []any{"REQ-AUTH-001"},
		"witnessCommandIds": []any{"proofkit.test.witness"},
	}
}

func minimalNativeWitnesses() map[string]any {
	return map[string]any{
		"commands": []any{map[string]any{
			"argv":            []any{"npm", "run", "check"},
			"cachePolicy":     "disabled",
			"credentialClass": "none",
			"cwd":             ".",
			"environment": map[string]any{
				"allowlist": []any{},
				"classes":   []any{"local-go"},
				"inherit":   "none",
			},
			"exitCodePolicy": map[string]any{
				"kind":         "zero",
				"successCodes": []any{json.Number("0")},
			},
			"expectedArtifacts": []any{map[string]any{
				"kind":     "report",
				"path":     "artifacts/proofkit/report.json",
				"required": true,
			}},
			"id":            "proofkit.test.witness",
			"networkPolicy": "none",
			"parallelGroup": "local",
			"schemaVersion": json.Number("1"),
			"timeoutMs":     json.Number("60000"),
		}},
		"vocabulary": map[string]any{
			"artifactKinds":                 []any{"report"},
			"credentialClasses":             []any{"none"},
			"environmentClasses":            []any{"local-go"},
			"maxTimeoutMs":                  json.Number("60000"),
			"nonCacheableCredentialClasses": []any{},
			"parallelGroups":                []any{"local"},
			"environmentClassPolicies": []any{map[string]any{
				"cachePolicies":     []any{"disabled"},
				"credentialClasses": []any{"none"},
				"environmentClass":  "local-go",
				"networkPolicies":   []any{"none"},
			}},
		},
	}
}

func minimalRepository() map[string]any {
	return map[string]any{
		"customRuleBoundary": "profile_only",
		"primaryLanguages":   []any{"go"},
		"profilePath":        "proofkit/adoption-profile.json",
		"repositoryClass":    "go-cli",
		"repositoryId":       "proofkit.test.repository",
		"verifierCodeCopied": false,
	}
}

func passedSourceReport() map[string]any {
	return map[string]any{
		"diagnostics":   []any{},
		"nonClaims":     []any{"Source report does not prove rollout readiness."},
		"reportId":      "proofkit.test.source",
		"reportKind":    "proofkit.test.source",
		"ruleResults":   []any{},
		"schemaVersion": json.Number("1"),
		"state":         "passed",
		"summary":       map[string]any{},
	}
}

func firstCandidate(input map[string]any) map[string]any {
	modernization := input["modernization"].(map[string]any)
	candidates := modernization["candidateBoundaries"].([]any)
	return candidates[0].(map[string]any)
}

func assertState(t *testing.T, output map[string]any, want string) {
	t.Helper()
	if output["state"] != want {
		t.Fatalf("state=%v want %s output=%#v", output["state"], want, output)
	}
}

func assertRuleStatus(t *testing.T, output map[string]any, ruleID string, want string) {
	t.Helper()
	for _, raw := range output["ruleResults"].([]any) {
		rule := raw.(map[string]any)
		if rule["ruleId"] == ruleID {
			if rule["status"] != want {
				t.Fatalf("%s status=%v want %s", ruleID, rule["status"], want)
			}
			return
		}
	}
	t.Fatalf("missing rule %s in %#v", ruleID, output["ruleResults"])
}

func assertFailureContains(t *testing.T, output map[string]any, want string) {
	t.Helper()
	for _, raw := range output["ruleResults"].([]any) {
		rule := raw.(map[string]any)
		message, _ := rule["message"].(string)
		if rule["status"] == "failed" && strings.Contains(message, want) {
			return
		}
	}
	t.Fatalf("missing failure containing %q in %#v", want, output["ruleResults"])
}

func diagnosticValue(t *testing.T, output map[string]any, key string) any {
	t.Helper()
	for _, raw := range output["diagnostics"].([]any) {
		diagnostic := raw.(map[string]any)
		if diagnostic["key"] == key {
			return diagnostic["value"]
		}
	}
	t.Fatalf("missing diagnostic %s", key)
	return nil
}

func actionPlanHasPhase(guidance map[string]any, phase string) bool {
	for _, raw := range guidance["agentActionPlan"].([]any) {
		action := raw.(map[string]any)
		if action["phase"] == phase {
			return true
		}
	}
	return false
}

func assertEnvelopeContextRole(t *testing.T, output map[string]any, role string) {
	t.Helper()
	for _, raw := range output["contextRefs"].([]any) {
		ref := raw.(map[string]any)
		if ref["role"] == role {
			return
		}
	}
	t.Fatalf("missing context role %s in %#v", role, output["contextRefs"])
}

func assertEnvelopeQuestion(t *testing.T, output map[string]any, want string) {
	t.Helper()
	for _, raw := range output["clarificationQuestions"].([]any) {
		question := raw.(map[string]any)
		if question["question"] == want {
			return
		}
	}
	t.Fatalf("missing clarification question %q in %#v", want, output["clarificationQuestions"])
}

func assertEnvelopeActionPhase(t *testing.T, output map[string]any, phase string) {
	t.Helper()
	for _, raw := range output["actionPlan"].([]any) {
		action := raw.(map[string]any)
		if action["phase"] == phase {
			return
		}
	}
	t.Fatalf("missing action phase %s in %#v", phase, output["actionPlan"])
}

func assertEnvelopeActionEvidenceRef(t *testing.T, output map[string]any, phase string, want string) {
	t.Helper()
	action := envelopeActionByPhase(t, output, phase)
	for _, raw := range action["evidenceRefs"].([]any) {
		if raw == want {
			return
		}
	}
	t.Fatalf("missing evidence ref %q for phase %s in %#v", want, phase, action["evidenceRefs"])
}

func assertEnvelopeActionRationale(t *testing.T, output map[string]any, phase string, wantPrefix string) {
	t.Helper()
	action := envelopeActionByPhase(t, output, phase)
	rationale, _ := action["rationale"].(string)
	if !strings.HasPrefix(rationale, wantPrefix) {
		t.Fatalf("rationale=%q want prefix %q", rationale, wantPrefix)
	}
}

func envelopeActionByPhase(t *testing.T, output map[string]any, phase string) map[string]any {
	t.Helper()
	for _, raw := range output["actionPlan"].([]any) {
		action := raw.(map[string]any)
		if action["phase"] == phase {
			return action
		}
	}
	t.Fatalf("missing action phase %s in %#v", phase, output["actionPlan"])
	return nil
}
