package adoptiondoctor

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildReportsObserveAndWarnWithoutBlockingAdvisoryGaps(t *testing.T) {
	for _, mode := range []string{"observe", "warn"} {
		t.Run(mode, func(t *testing.T) {
			input := baseInput()
			input["mode"] = mode
			input["checkedScope"] = "touched"
			report, exitCode, err := Build(decodeInput(t, input))
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if exitCode != 0 || report["state"] != "passed" {
				t.Fatalf("state=%v exit=%d, want passed/0", report["state"], exitCode)
			}
			summary := report["summary"].(map[string]any)
			if summary["gapCount"].(int) == 0 {
				t.Fatalf("summary=%#v, want advisory gap count", summary)
			}
		})
	}
}

func TestBuildFailsEnforcementForCandidateBoundaryAndMissingRoutes(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.007421917124002404912211613315239198743059540465995158650367800592497462368119")
	input := baseInput()
	input["mode"] = "enforce-all"
	input["checkedScope"] = "all"
	report, exitCode, err := Build(decodeInput(t, input))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 1 || report["state"] != "failed" {
		t.Fatalf("state=%v exit=%d, want failed/1", report["state"], exitCode)
	}
	if !hasRuleStatus(report, "failed") {
		t.Fatalf("report has no failed rule: %#v", report["ruleResults"])
	}
}

func TestBuildRejectsInvalidModeAndScopePairs(t *testing.T) {
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
			wantError:    "adoption doctor mode must be one of",
		},
		{
			name:         "unknown scope",
			mode:         "observe",
			checkedScope: "partial",
			wantError:    "adoption doctor checkedScope must be one of",
		},
		{
			name:         "enforce all without full scope",
			mode:         "enforce-all",
			checkedScope: "touched",
			wantError:    "adoption doctor enforce-all requires checkedScope all",
		},
		{
			name:         "enforce touched without checked scope",
			mode:         "enforce-touched",
			checkedScope: "none",
			wantError:    "adoption doctor enforce-touched requires checkedScope touched or all",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := baseInput()
			input["mode"] = item.mode
			input["checkedScope"] = item.checkedScope

			_, _, err := Build(decodeInput(t, input))
			if err == nil || !strings.Contains(err.Error(), item.wantError) {
				t.Fatalf("Build() error=%v, want %q", err, item.wantError)
			}
		})
	}
}

func TestBuildFailsEnforceAllWhenOwnerRouteInventoryIsEmpty(t *testing.T) {
	input := baseInput()
	input["mode"] = "enforce-all"
	input["checkedScope"] = "all"
	input["ownerRoutes"] = []any{}
	input["modernization"] = map[string]any{"candidateBoundaries": []any{}}
	input["childReports"] = []any{}
	input["touchedRuleIds"] = []any{}
	report, exitCode, err := Build(decodeInput(t, input))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 1 || report["state"] != "failed" {
		t.Fatalf("state=%v exit=%d, want failed/1", report["state"], exitCode)
	}
	if !hasRule(report, "proofkit.adoption-doctor.missing_owner_route", "failed") {
		t.Fatalf("report has no failed missing_owner_route rule: %#v", report["ruleResults"])
	}
	readiness := diagnosticMap(t, report, "promotionReadiness")
	if readiness["route"] != "blocked_missing_owner_route" || readiness["promote"] != "not_ready" {
		t.Fatalf("promotionReadiness=%#v, want blocked route and no promotion", readiness)
	}
}

func TestBuildFailsEnforceTouchedWhenTouchedRequirementHasNoOwnerRoute(t *testing.T) {
	input := baseInput()
	input["mode"] = "enforce-touched"
	input["checkedScope"] = "touched"
	input["modernization"] = map[string]any{"candidateBoundaries": []any{}}
	input["childReports"] = []any{}
	input["touchedRuleIds"] = []any{"REQ-CONSUMER-MISSING"}
	routes := input["ownerRoutes"].([]any)
	route := routes[0].(map[string]any)
	route["touchedRuleIds"] = []any{"REQ-CONSUMER-OTHER"}
	route["commands"] = []any{"go test ./..."}
	route["nativeWitnessRefs"] = []any{"internal/command/adoptiondoctor/adoptiondoctor_test.go"}
	route["proofBindingPaths"] = []any{"proofkit/requirement-bindings.json"}

	report, exitCode, err := Build(decodeInput(t, input))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 1 || report["state"] != "failed" {
		t.Fatalf("state=%v exit=%d, want failed/1", report["state"], exitCode)
	}
	if !hasRule(report, "proofkit.adoption-doctor.missing_owner_route", "failed") {
		t.Fatalf("report has no failed missing_owner_route rule: %#v", report["ruleResults"])
	}
	gaps := diagnosticSlice(t, report, "gaps")
	if !gapHasRule(gaps, "REQ-CONSUMER-MISSING") {
		t.Fatalf("missing owner route gap does not name touched requirement: %#v", gaps)
	}
}

func TestBuildBlocksEnforcementForExternalPreconditions(t *testing.T) {
	input := baseInput()
	input["mode"] = "enforce-all"
	input["checkedScope"] = "all"
	input["blockedPreconditions"] = []any{
		map[string]any{
			"evidenceRefs":   []any{"docs/proofkit-contract-map.md"},
			"nonClaim":       "The blocked precondition is caller-owned.",
			"owner":          "consumer.repository",
			"preconditionId": "consumer.live-db-unavailable",
			"reason":         "Live database credentials are intentionally unavailable.",
			"touchedRuleIds": []any{"REQ-CONSUMER-001"},
		},
	}
	report, exitCode, err := Build(decodeInput(t, input))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 1 || report["state"] != "blocked" {
		t.Fatalf("state=%v exit=%d, want blocked/1", report["state"], exitCode)
	}
}

func TestBuildFailsEnforcementForNonPassingChildReports(t *testing.T) {
	for _, mode := range []string{"enforce-all", "enforce-touched"} {
		for _, childState := range []string{"skipped", "warning"} {
			t.Run(mode+"/"+childState, func(t *testing.T) {
				input := completeInput()
				input["mode"] = mode
				input["checkedScope"] = "all"
				child := input["childReports"].([]any)[0].(map[string]any)
				child["state"] = childState
				child["summary"] = "Child report did not produce merge-satisfying evidence."

				report, exitCode, err := Build(decodeInput(t, input))
				if err != nil {
					t.Fatalf("Build() error=%v", err)
				}
				if exitCode != 1 || report["state"] != "failed" {
					t.Fatalf("state=%v exit=%d, want failed/1", report["state"], exitCode)
				}
				ruleID := "proofkit.adoption-doctor.child_report_" + childState
				if !hasRule(report, ruleID, "failed") {
					t.Fatalf("report has no failed %s rule: %#v", ruleID, report["ruleResults"])
				}
				readiness := diagnosticMap(t, report, "promotionReadiness")
				if readiness["promote"] != "not_ready" {
					t.Fatalf("promotionReadiness=%#v, want no promotion", readiness)
				}
			})
		}
	}
}

func TestBuildRejectsShellControlRouteCommand(t *testing.T) {
	input := baseInput()
	routes := input["ownerRoutes"].([]any)
	route := routes[0].(map[string]any)
	route["commands"] = []any{"npm run check && npm publish"}
	_, _, err := Build(decodeInput(t, input))
	if err == nil || !strings.Contains(err.Error(), "display-only command text without shell control tokens") {
		t.Fatalf("Build() error=%v, want shell-control rejection", err)
	}
}

func TestBuildFailsEnforcementForCurrentStaleAuthorityVocabulary(t *testing.T) {
	input := completeInput()
	input["mode"] = "enforce-all"
	input["checkedScope"] = "all"
	input["staleAuthority"] = staleAuthorityInput("current", "docs/adr/0002-proofkit-extraction-delivery-model.md", "")

	report, exitCode, err := Build(decodeInput(t, input))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 1 || report["state"] != "failed" {
		t.Fatalf("state=%v exit=%d, want failed/1", report["state"], exitCode)
	}
	if !hasRule(report, "proofkit.adoption-doctor.stale_authority_current_vocabulary", "failed") {
		t.Fatalf("report has no failed stale authority rule: %#v", report["ruleResults"])
	}
	summary := report["summary"].(map[string]any)
	if summary["staleAuthoritySurfaceCount"].(int) != 1 || summary["forbiddenVocabularyCount"].(int) != 1 {
		t.Fatalf("summary=%#v, want stale authority counts", summary)
	}
	gaps := diagnosticSlice(t, report, "gaps")
	if !gapHasRule(gaps, "REQ-PROOFKIT-RETIRE-008") {
		t.Fatalf("stale authority gap does not preserve touched rule: %#v", gaps)
	}
}

func TestBuildAdmitsRetiredStaleAuthorityVocabularyInsideHistoricalScope(t *testing.T) {
	input := completeInput()
	input["mode"] = "enforce-all"
	input["checkedScope"] = "all"
	input["staleAuthority"] = staleAuthorityInput("retired", "docs/archive/proofkit-extraction-history.md", "consumer.historical-proofkit")

	report, exitCode, err := Build(decodeInput(t, input))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || report["state"] != "passed" {
		t.Fatalf("state=%v exit=%d, want passed/0", report["state"], exitCode)
	}
	readiness := diagnosticMap(t, report, "promotionReadiness")
	if readiness["retire-stale-authority"] == "blocked" {
		t.Fatalf("promotionReadiness=%#v, want retired scoped vocabulary admitted", readiness)
	}
}

func TestBuildFailsRetiredStaleAuthorityVocabularyOutsideHistoricalScope(t *testing.T) {
	input := completeInput()
	input["mode"] = "enforce-all"
	input["checkedScope"] = "all"
	input["staleAuthority"] = staleAuthorityInput("retired", "docs/adr/0002-proofkit-extraction-delivery-model.md", "consumer.historical-proofkit")

	report, exitCode, err := Build(decodeInput(t, input))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 1 || report["state"] != "failed" {
		t.Fatalf("state=%v exit=%d, want failed/1", report["state"], exitCode)
	}
	if !hasRule(report, "proofkit.adoption-doctor.stale_authority_retired_scope", "failed") {
		t.Fatalf("report has no failed retired-scope rule: %#v", report["ruleResults"])
	}
}

func TestBuildRejectsStaleAuthoritySurfaceWithUnknownVocabulary(t *testing.T) {
	input := completeInput()
	input["staleAuthority"] = staleAuthorityInput("current", "docs/adr/0002-proofkit-extraction-delivery-model.md", "")
	surface := input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)
	surface["matchedVocabularyIds"] = []any{"legacy.unknown-proofkit"}

	_, _, err := Build(decodeInput(t, input))
	if err == nil || !strings.Contains(err.Error(), "must reference declared forbidden vocabulary ids") {
		t.Fatalf("Build() error=%v, want unknown stale vocabulary rejection", err)
	}
}

func TestBuildAgentEnvelopeRoutesBoundedActionPlan(t *testing.T) {
	input := baseInput()
	envelope, exitCode, err := BuildEnvelope(decodeInput(t, input))
	if err != nil {
		t.Fatalf("BuildEnvelope() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit=%d, want 0 for advisory envelope", exitCode)
	}
	actions := envelope["actionPlan"].([]any)
	if len(actions) == 0 {
		t.Fatalf("action plan must contain owner-specific guidance")
	}
	bounds := envelope["bounds"].(map[string]any)
	if bounds["fanout"] != "bounded" {
		t.Fatalf("bounds=%#v, want bounded fanout", bounds)
	}
	if !strings.Contains(envelope["sourceReport"].(map[string]any)["reportKind"].(string), "adoption-doctor") {
		t.Fatalf("unexpected source report: %#v", envelope["sourceReport"])
	}
	candidateAction := findAction(t, actions, "consumer.example-boundary.candidate-boundary-not-admitted")
	if candidateAction["owner"] != "consumer.repository" || candidateAction["phase"] != "modernize-boundary" {
		t.Fatalf("candidate action lost owner/phase: %#v", candidateAction)
	}
	assertStringSliceContains(t, candidateAction["observedFacts"], "A cohesive module candidate was observed.")
	assertStringSliceContains(t, candidateAction["uncertainties"], "Proof ownership still needs owner review.")
	assertStringSliceContains(t, candidateAction["ownerQuestions"], "Should this candidate become a stable requirement owner?")
	selectors := candidateAction["selectors"].(map[string]any)
	assertStringSliceContains(t, selectors["affectedPaths"], "packages/example/src/index.ts")
	if candidateAction["missingWitness"] != "candidate_witness_not_admitted" {
		t.Fatalf("candidate action missing witness diagnostic: %#v", candidateAction["missingWitness"])
	}
	if !strings.Contains(candidateAction["candidateAction"].(string), "admitted semantic owner") {
		t.Fatalf("candidate action is not owner-specific: %#v", candidateAction["candidateAction"])
	}
	routeAction := findAction(t, actions, "consumer.example-route.missing_proof_binding")
	routeSelectors := routeAction["selectors"].(map[string]any)
	assertStringSliceContains(t, routeSelectors["specPaths"], "docs/specs/example/requirements.v1.json")
	if routeAction["proofCommand"] != "missing_command_route" || routeAction["missingWitness"] != "missing_proof_binding" {
		t.Fatalf("route action lost proof/witness diagnostics: %#v", routeAction)
	}
}

func findAction(t *testing.T, actions []any, suffix string) map[string]any {
	t.Helper()
	for _, raw := range actions {
		action := raw.(map[string]any)
		if strings.HasSuffix(action["stepId"].(string), suffix) {
			return action
		}
	}
	t.Fatalf("missing action with suffix %s in %#v", suffix, actions)
	return nil
}

func assertStringSliceContains(t *testing.T, raw any, want string) {
	t.Helper()
	for _, value := range raw.([]any) {
		if value == want {
			return
		}
	}
	t.Fatalf("%#v does not contain %q", raw, want)
}

func hasRuleStatus(report map[string]any, status string) bool {
	rules := report["ruleResults"].([]any)
	for _, rawRule := range rules {
		rule := rawRule.(map[string]any)
		if rule["status"] == status {
			return true
		}
	}
	return false
}

func hasRule(report map[string]any, ruleID string, status string) bool {
	rules := report["ruleResults"].([]any)
	for _, rawRule := range rules {
		rule := rawRule.(map[string]any)
		if rule["ruleId"] == ruleID && rule["status"] == status {
			return true
		}
	}
	return false
}

func diagnosticMap(t *testing.T, report map[string]any, key string) map[string]any {
	t.Helper()
	for _, raw := range report["diagnostics"].([]any) {
		diagnostic := raw.(map[string]any)
		if diagnostic["key"] == key {
			return diagnostic["value"].(map[string]any)
		}
	}
	t.Fatalf("missing diagnostic %s", key)
	return nil
}

func diagnosticSlice(t *testing.T, report map[string]any, key string) []any {
	t.Helper()
	for _, raw := range report["diagnostics"].([]any) {
		diagnostic := raw.(map[string]any)
		if diagnostic["key"] == key {
			return diagnostic["value"].([]any)
		}
	}
	t.Fatalf("missing diagnostic %s", key)
	return nil
}

func gapHasRule(gaps []any, ruleID string) bool {
	for _, raw := range gaps {
		gap := raw.(map[string]any)
		for _, rawRuleID := range gap["ruleRefs"].([]any) {
			if rawRuleID == ruleID {
				return true
			}
		}
	}
	return false
}

func baseInput() map[string]any {
	return map[string]any{
		"blockedPreconditions": []any{},
		"checkedScope":         "touched",
		"childReports": []any{
			map[string]any{
				"evidenceRefs":   []any{"docs/specs/proofkit-consumer-infra-retirement/requirements.v1.json"},
				"nonClaim":       "Child report state is caller-provided evidence only.",
				"reportId":       "consumer.source-admission",
				"reportKind":     "proofkit.requirement-source-admission",
				"state":          "passed",
				"summary":        "Requirement source admission passed.",
				"touchedRuleIds": []any{"REQ-CONSUMER-001"},
			},
		},
		"doctorId": "consumer.adoption-doctor",
		"mode":     "observe",
		"modernization": map[string]any{
			"candidateBoundaries": []any{
				map[string]any{
					"admissionState":       "advisory",
					"affectedPaths":        []any{"packages/example/src/index.ts"},
					"blockedPreconditions": []any{},
					"boundaryId":           "consumer.example-boundary",
					"candidateOwner":       "consumer.repository",
					"contractWitnessRefs":  []any{},
					"nativeWitnessRefs":    []any{},
					"nonClaims":            []any{"Candidate boundaries are advisory until owner admission."},
					"observedFacts":        []any{"A cohesive module candidate was observed."},
					"ownerQuestions":       []any{"Should this candidate become a stable requirement owner?"},
					"proofBindingRefs":     []any{},
					"requirementRefs":      []any{"REQ-CONSUMER-001"},
					"uncertainties":        []any{"Proof ownership still needs owner review."},
				},
			},
		},
		"nonClaims": []any{"The consuming repository owns native witness execution."},
		"ownerRoutes": []any{
			map[string]any{
				"commands":          []any{},
				"nativeWitnessRefs": []any{},
				"nonClaims":         []any{"Owner route evidence is caller-provided."},
				"owner":             "consumer.repository",
				"proofBindingPaths": []any{},
				"routeId":           "consumer.example-route",
				"specPaths":         []any{"docs/specs/example/requirements.v1.json"},
				"touchedRuleIds":    []any{"REQ-CONSUMER-001"},
			},
		},
		"schemaVersion":  1,
		"touchedRuleIds": []any{"REQ-CONSUMER-001"},
	}
}

func completeInput() map[string]any {
	input := baseInput()
	input["modernization"] = map[string]any{"candidateBoundaries": []any{}}
	routes := input["ownerRoutes"].([]any)
	route := routes[0].(map[string]any)
	route["commands"] = []any{"go test ./internal/command/adoptiondoctor"}
	route["nativeWitnessRefs"] = []any{"internal/command/adoptiondoctor/adoptiondoctor_test.go"}
	route["proofBindingPaths"] = []any{"proofkit/requirement-bindings.json"}
	return input
}

func staleAuthorityInput(authorityState string, path string, retiredScopeID string) map[string]any {
	surface := map[string]any{
		"authorityState":       authorityState,
		"evidenceRefs":         []any{},
		"matchedVocabularyIds": []any{"legacy.old-proofkit-package"},
		"nonClaims":            []any{"Stale vocabulary facts are caller-provided; Proofkit does not scan source files."},
		"owner":                "consumer.docs",
		"path":                 path,
		"surfaceId":            "consumer.proofkit-delivery-adr",
		"touchedRuleIds":       []any{"REQ-PROOFKIT-RETIRE-008"},
	}
	if retiredScopeID != "" {
		surface["retiredScopeId"] = retiredScopeID
	}
	return map[string]any{
		"currentPackage": map[string]any{
			"name":    "agentic-proofkit",
			"version": "0.1.133",
		},
		"forbiddenVocabulary": []any{
			map[string]any{
				"replacementText": "agentic-proofkit",
				"text":            "legacy-proofkit-package",
				"vocabularyId":    "legacy.old-proofkit-package",
			},
		},
		"authoritySurfaces": []any{surface},
		"retiredScopes": []any{
			map[string]any{
				"allowedVocabularyIds": []any{"legacy.old-proofkit-package"},
				"nonClaim":             "Retired scope admits historical evidence only.",
				"pathPrefixes":         []any{"docs/archive"},
				"scopeId":              "consumer.historical-proofkit",
			},
		},
	}
}

func decodeInput(t *testing.T, value map[string]any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	return decoded
}
