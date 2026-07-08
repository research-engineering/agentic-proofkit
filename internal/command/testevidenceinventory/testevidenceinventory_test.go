package testevidenceinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestBuildAdmitsSemanticFalsifierInventory(t *testing.T) {
	record, exitCode, err := Build(validInventory(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() state=%s exit=%d report=%#v", record.State, exitCode, record.JSONValue())
	}
	if record.ReportKind != ReportKind || record.ReportID != "proofkit.test.inventory" {
		t.Fatalf("unexpected report identity: %#v", record.JSONValue())
	}
	if record.Summary["semanticFalsifierCount"] != 1 {
		t.Fatalf("semanticFalsifierCount=%v", record.Summary["semanticFalsifierCount"])
	}
	if record.Summary["agentActionCount"] != 0 {
		t.Fatalf("clean inventory emitted agent actions: %#v", record.JSONValue())
	}
	if actions := agentActions(record.JSONValue()); len(actions) != 0 {
		t.Fatalf("clean inventory agent actions=%#v, want none", actions)
	}
}

func TestBuildDiscoveryDraftEmitsCandidateOnlyInventory(t *testing.T) {
	record, exitCode, err := BuildDiscoveryDraft(validDiscoveryDraft())
	if err != nil {
		t.Fatalf("BuildDiscoveryDraft() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" || record.ReportKind != discoveryDraftReportKind {
		t.Fatalf("BuildDiscoveryDraft() state=%s exit=%d report=%#v", record.State, exitCode, record.JSONValue())
	}
	value := record.JSONValue()
	if value["summary"].(map[string]any)["candidateInventoryEntryCount"] != 1 {
		t.Fatalf("unexpected summary: %#v", value["summary"])
	}
	candidate := diagnosticValue(value, "candidateInventory").(map[string]any)
	if candidate["authority"] != discoveryCandidateInventoryAuthority || candidate["candidateKind"] != discoveryCandidateInventoryKind {
		t.Fatalf("candidate inventory must use non-strict authority/kind: %#v", candidate)
	}
	if _, err := Evaluate(candidate); err == nil || !strings.Contains(err.Error(), "candidateKind") {
		t.Fatalf("strict inventory admission accepted candidate inventory: err=%v", err)
	}
	entries := candidate["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("candidate entries=%#v", entries)
	}
	entry := entries[0].(map[string]any)
	if entry["evidenceClass"] != "routing_smoke_nonclaim" {
		t.Fatalf("discovery draft must stay route-only: %#v", entry)
	}
	if !stringSliceContains(anyStrings(entry["requirementRefs"]), "REQ-SAMPLE-AUTH-001") {
		t.Fatalf("discovery draft dropped candidate requirement refs: %#v", entry)
	}
	if !stringSliceContains(anyStrings(entry["ownerInvariantRefs"]), "sample.auth.missing_token") {
		t.Fatalf("discovery draft dropped owner invariant refs: %#v", entry)
	}
	if entry["falsifier"] != nil || entry["oracle"] != nil {
		t.Fatalf("discovery draft leaked semantic coverage proof fields: %#v", entry)
	}
	reportNonClaims := anyStrings(value["nonClaims"])
	candidateNonClaims := anyStrings(candidate["nonClaims"])
	entryNonClaims := anyStrings(entry["nonClaims"])
	for _, want := range []string{
		"Discovery draft fixture does not prove inventory completeness.",
		"Repository fixture does not prove checkout freshness.",
		"Runner fixture does not execute pytest.",
	} {
		if !stringSliceContains(reportNonClaims, want) {
			t.Fatalf("report nonClaims missing %q: %#v", want, reportNonClaims)
		}
		if !stringSliceContains(candidateNonClaims, want) {
			t.Fatalf("candidate inventory nonClaims missing %q: %#v", want, candidateNonClaims)
		}
		if !stringSliceContains(entryNonClaims, want) {
			t.Fatalf("candidate entry nonClaims missing %q: %#v", want, entryNonClaims)
		}
	}
	warnings := strings.Join(stringDiagnostics(value, "warnings"), "\n")
	for _, want := range []string{"candidate_only:test.discovery.semantic", "selector_fragility:test.discovery.semantic"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings missing %q: %s", want, warnings)
		}
	}
}

func TestBuildDiscoveryDraftDefaultsOptionalNonClaims(t *testing.T) {
	input := validDiscoveryDraft()
	delete(input, "nonClaims")
	delete(input["repository"].(map[string]any), "nonClaims")
	delete(input["runner"].(map[string]any), "nonClaims")
	delete(firstDiscoveryTest(input), "nonClaims")

	record, exitCode, err := BuildDiscoveryDraft(input)
	if err != nil {
		t.Fatalf("BuildDiscoveryDraft() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("BuildDiscoveryDraft() state=%s exit=%d report=%#v", record.State, exitCode, record.JSONValue())
	}
	candidate := diagnosticValue(record.JSONValue(), "candidateInventory").(map[string]any)
	if candidate["candidateKind"] != discoveryCandidateInventoryKind {
		t.Fatalf("candidate inventory missing expected kind: %#v", candidate)
	}
}

func TestBuildDiscoveryDraftClassifiesWeakOracleSignals(t *testing.T) {
	input := validDiscoveryDraft()
	strong := firstDiscoveryTest(input)
	weak := cloneMap(strong)
	weak["testId"] = "test.discovery.weak_oracle"
	weak["selector"] = "tests/test_auth.py::test_snapshot_only"
	weak["title"] = "test_snapshot_only"
	weak["oracleSignals"] = []any{"snapshot_only"}
	weak["selectorSignals"] = []any{"structured_selector"}
	input["discoveredTests"] = []any{strong, weak}

	record, exitCode, err := BuildDiscoveryDraft(input)
	if err != nil {
		t.Fatalf("BuildDiscoveryDraft() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("BuildDiscoveryDraft() state=%s exit=%d report=%#v", record.State, exitCode, record.JSONValue())
	}
	value := record.JSONValue()
	if value["summary"].(map[string]any)["weakOracleWarningCount"] != 1 {
		t.Fatalf("weakOracleWarningCount=%#v want 1", value["summary"].(map[string]any)["weakOracleWarningCount"])
	}
	warnings := strings.Join(stringDiagnostics(value, "warnings"), "\n")
	if !strings.Contains(warnings, "weak_or_empty_oracle:test.discovery.weak_oracle") {
		t.Fatalf("warnings missing weak oracle diagnostic: %s", warnings)
	}
	if strings.Contains(warnings, "weak_or_empty_oracle:test.discovery.semantic") {
		t.Fatalf("strong oracle row emitted weak oracle diagnostic: %s", warnings)
	}
	actions := diagnosticValue(value, "agentActionPlan").([]any)
	foundAction := false
	for _, raw := range actions {
		action := raw.(map[string]any)
		if action["testId"] == "test.discovery.weak_oracle" && action["type"] == "weak_or_empty_oracle" {
			foundAction = true
		}
	}
	if !foundAction {
		t.Fatalf("agentActionPlan missing weak_or_empty_oracle action: %#v", actions)
	}
	candidate := diagnosticValue(value, "candidateInventory").(map[string]any)
	for _, rawEntry := range candidate["entries"].([]any) {
		entry := rawEntry.(map[string]any)
		if entry["testId"] != "test.discovery.weak_oracle" {
			continue
		}
		findings := entry["qualityFindings"].([]any)
		for _, rawFinding := range findings {
			finding := rawFinding.(map[string]any)
			if finding["class"] == "empty_oracle" {
				return
			}
		}
		t.Fatalf("weak oracle candidate entry missing empty_oracle quality finding: %#v", entry)
	}
	t.Fatalf("candidate inventory missing weak oracle row: %#v", candidate)
}

func TestBuildDiscoveryDraftRejectsUnsafeAndContradictoryFacts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "unsafe source path",
			mutate: func(input map[string]any) {
				firstDiscoveryTest(input)["sourcePath"] = "../tests/test_auth.py"
			},
			want: "must not escape the repository root",
		},
		{
			name: "selector source drift",
			mutate: func(input map[string]any) {
				firstDiscoveryTest(input)["selector"] = "tests/other_test.py::test_rejects_missing_token"
			},
			want: "sourcePath must match selector path",
		},
		{
			name: "duplicate test id",
			mutate: func(input map[string]any) {
				tests := input["discoveredTests"].([]any)
				clone := cloneMap(tests[0].(map[string]any))
				input["discoveredTests"] = append(tests, clone)
			},
			want: "testIds must be sorted and unique",
		},
		{
			name: "unknown oracle signal",
			mutate: func(input map[string]any) {
				firstDiscoveryTest(input)["oracleSignals"] = []any{"looks_good"}
			},
			want: "oracleSignals must be one of",
		},
		{
			name: "malformed requirement id",
			mutate: func(input map[string]any) {
				firstDiscoveryTest(input)["candidateRequirementRefs"] = []any{"DISCOVERY-001"}
			},
			want: "REQ-* identifiers",
		},
		{
			name: "secret shaped title",
			mutate: func(input map[string]any) {
				firstDiscoveryTest(input)["title"] = "Bearer abcdefghijklmnop"
			},
			want: "must not contain secret-like values",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := validDiscoveryDraft()
			tc.mutate(input)
			_, _, err := BuildDiscoveryDraft(input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildDiscoveryDraft() error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildRejectsWeakOracleAndDuplicateFalsifier(t *testing.T) {
	input := validInventory(t)
	entries := input.(map[string]any)["entries"].([]any)
	first := cloneMap(entries[0].(map[string]any))
	first["testId"] = "test.inventory.duplicate"
	first["falsifier"] = cloneMap(first["falsifier"].(map[string]any))
	first["falsifier"].(map[string]any)["falsifierId"] = "falsifier.inventory.duplicate"
	entries = append(entries, first)
	weak := cloneMap(entries[0].(map[string]any))
	weak["testId"] = "test.inventory.weak"
	weak["falsifier"] = map[string]any{
		"dominanceGroup":             "inventory.weak",
		"falsifierId":                "falsifier.inventory.weak",
		"negativeCaseId":             "case.inventory.weak",
		"supersedes":                 []any{},
		"wrongImplementationClassId": "wrong.inventory.weak",
	}
	weak["oracle"] = map[string]any{
		"assertionSummary":      "",
		"expectedPublicOutcome": "failed report with diagnostic",
		"oracleId":              "oracle.inventory.weak",
		"oracleKind":            "negative_exit_and_diagnostic",
	}
	entries = append(entries, weak)
	input.(map[string]any)["entries"] = entries

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted weak inventory: %#v", record.JSONValue())
	}
	failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n")
	for _, want := range []string{"declared_duplicate_falsifier:", "weak_or_empty_oracle:test.inventory.weak"} {
		if !strings.Contains(failures, want) {
			t.Fatalf("failures missing %q: %s", want, failures)
		}
	}
	requireDiagnosticClassifications(t, record.JSONValue(), "failureClassifications", "failure", map[string]string{
		"declared_duplicate_falsifier:test.inventory.duplicate:test.inventory.semantic": "declared_duplicate_falsifier",
		"weak_or_empty_oracle:test.inventory.weak":                                      "weak_or_empty_oracle",
	})
	requireAgentAction(t, record.JSONValue(), "declared_duplicate_falsifier", "failure")
	requireAgentAction(t, record.JSONValue(), "weak_or_empty_oracle", "failure")
}

func TestBuildRejectsDuplicateFalsifierIDAcrossDifferentEquivalenceKeys(t *testing.T) {
	input := validInventory(t)
	entries := input.(map[string]any)["entries"].([]any)
	duplicate := cloneMap(entries[0].(map[string]any))
	duplicate["testId"] = "test.inventory.duplicate_falsifier_id"
	duplicate["falsifier"] = cloneMap(duplicate["falsifier"].(map[string]any))
	duplicate["falsifier"].(map[string]any)["negativeCaseId"] = "case.inventory.other"
	duplicate["falsifier"].(map[string]any)["wrongImplementationClassId"] = "wrong.inventory.other"
	duplicate["falsifier"].(map[string]any)["dominanceGroup"] = "inventory.other"
	duplicate["oracle"] = cloneMap(duplicate["oracle"].(map[string]any))
	duplicate["oracle"].(map[string]any)["oracleId"] = "oracle.inventory.other"
	input.(map[string]any)["entries"] = append(entries, duplicate)

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "falsifierIds must be sorted and unique") {
		t.Fatalf("Build() error=%v, want duplicate falsifierId admission failure", err)
	}
}

func TestBuildRejectsArbitraryFalsifierSupersedes(t *testing.T) {
	input := validInventory(t)
	entries := input.(map[string]any)["entries"].([]any)
	replacement := cloneMap(entries[0].(map[string]any))
	replacement["falsifier"] = cloneMap(replacement["falsifier"].(map[string]any))
	replacement["testId"] = "test.inventory.invalid_supersedes"
	replacement["falsifier"].(map[string]any)["falsifierId"] = "falsifier.inventory.invalid_supersedes"
	replacement["falsifier"].(map[string]any)["supersedes"] = []any{"falsifier.inventory.unrelated"}
	replacement["falsifier"].(map[string]any)["supersessionProofRef"] = "proof.inventory.invalid_supersedes"
	replacement["ownerInvariantRefs"] = []any{"proof.inventory.invalid_supersedes"}
	input.(map[string]any)["entries"] = append(entries, replacement)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted arbitrary supersedes: %#v", record.JSONValue())
	}
	failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n")
	if !strings.Contains(failures, "invalid_falsifier_supersession:test.inventory.invalid_supersedes") {
		t.Fatalf("failures missing invalid supersession diagnostic: %s", failures)
	}
	requireDiagnosticClassifications(t, record.JSONValue(), "failureClassifications", "failure", map[string]string{
		"invalid_falsifier_supersession:test.inventory.invalid_supersedes:unknown:falsifier.inventory.unrelated": "invalid_falsifier_supersession",
	})
}

func TestBuildRejectsSameEquivalenceFalsifierSupersessionWithoutDominanceProof(t *testing.T) {
	input := validInventory(t)
	entries := input.(map[string]any)["entries"].([]any)
	replacement := cloneMap(entries[0].(map[string]any))
	replacement["falsifier"] = cloneMap(replacement["falsifier"].(map[string]any))
	replacement["testId"] = "test.inventory.superseding"
	replacement["falsifier"].(map[string]any)["falsifierId"] = "falsifier.inventory.superseding"
	replacement["falsifier"].(map[string]any)["supersedes"] = []any{"falsifier.inventory.semantic"}
	input.(map[string]any)["entries"] = append(entries, replacement)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted supersession without dominance proof: %#v", record.JSONValue())
	}
	failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n")
	if !strings.Contains(failures, "invalid_falsifier_supersession:test.inventory.superseding:missing_dominance_proof:falsifier.inventory.semantic") {
		t.Fatalf("failures missing dominance proof diagnostic: %s", failures)
	}
}

func TestBuildRejectsSameEquivalenceFalsifierSupersessionWithUnownedDominanceProof(t *testing.T) {
	input := validInventory(t)
	entries := input.(map[string]any)["entries"].([]any)
	replacement := cloneMap(entries[0].(map[string]any))
	replacement["falsifier"] = cloneMap(replacement["falsifier"].(map[string]any))
	replacement["testId"] = "test.inventory.unowned_superseding"
	replacement["falsifier"].(map[string]any)["falsifierId"] = "falsifier.inventory.unowned_superseding"
	replacement["falsifier"].(map[string]any)["supersedes"] = []any{"falsifier.inventory.semantic"}
	replacement["falsifier"].(map[string]any)["supersessionProofRef"] = "proof.inventory.unowned_superseding"
	input.(map[string]any)["entries"] = append(entries, replacement)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted supersession with unowned dominance proof: %#v", record.JSONValue())
	}
	failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n")
	if !strings.Contains(failures, "invalid_falsifier_supersession:test.inventory.unowned_superseding:unowned_dominance_proof:proof.inventory.unowned_superseding") {
		t.Fatalf("failures missing unowned dominance proof diagnostic: %s", failures)
	}
}

func TestBuildAdmitsSameEquivalenceFalsifierSupersessionWithDominanceProof(t *testing.T) {
	input := validInventory(t)
	entries := input.(map[string]any)["entries"].([]any)
	replacement := cloneMap(entries[0].(map[string]any))
	replacement["falsifier"] = cloneMap(replacement["falsifier"].(map[string]any))
	replacement["testId"] = "test.inventory.superseding"
	replacement["falsifier"].(map[string]any)["falsifierId"] = "falsifier.inventory.superseding"
	replacement["falsifier"].(map[string]any)["supersedes"] = []any{"falsifier.inventory.semantic"}
	replacement["falsifier"].(map[string]any)["supersessionProofRef"] = "proof.inventory.superseding"
	replacement["ownerInvariantRefs"] = []any{"proof.inventory.superseding"}
	input.(map[string]any)["entries"] = append(entries, replacement)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() rejected proven same-equivalence supersession: %#v", record.JSONValue())
	}
}

func TestBuildAdmitsSupersessionIndependentOfTestIDSortOrder(t *testing.T) {
	input := validInventory(t)
	entries := input.(map[string]any)["entries"].([]any)
	replacement := cloneMap(entries[0].(map[string]any))
	replacement["falsifier"] = cloneMap(replacement["falsifier"].(map[string]any))
	replacement["testId"] = "test.inventory.aaa_superseding"
	replacement["falsifier"].(map[string]any)["falsifierId"] = "falsifier.inventory.aaa_superseding"
	replacement["falsifier"].(map[string]any)["supersedes"] = []any{"falsifier.inventory.semantic"}
	replacement["falsifier"].(map[string]any)["supersessionProofRef"] = "proof.inventory.aaa_superseding"
	replacement["ownerInvariantRefs"] = []any{"proof.inventory.aaa_superseding"}
	input.(map[string]any)["entries"] = append(entries, replacement)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() rejected order-independent supersession: %#v", record.JSONValue())
	}
}

func TestBuildRejectsSemanticFalsifierWithoutCommandRefs(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["commandRefs"] = []any{}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted semantic falsifier without commands: %#v", record.JSONValue())
	}
	failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n")
	if !strings.Contains(failures, "missing_executable_command_ref:test.inventory.semantic") {
		t.Fatalf("failures missing executable command diagnostic: %s", failures)
	}
	requireDiagnosticClassifications(t, record.JSONValue(), "failureClassifications", "failure", map[string]string{
		"missing_executable_command_ref:test.inventory.semantic": "missing_executable_command_ref",
	})
}

func TestBuildRejectsSemanticFalsifierWithoutExpectedPublicOutcome(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["oracle"].(map[string]any)["expectedPublicOutcome"] = ""

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted semantic falsifier without expected public outcome: %#v", record.JSONValue())
	}
	failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n")
	if !strings.Contains(failures, "weak_or_empty_oracle:test.inventory.semantic") {
		t.Fatalf("failures missing weak oracle diagnostic: %s", failures)
	}
}

func TestBuildAdmitsRouteOnlyNonClaimAndEmitsWarningGuidance(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["evidenceClass"] = "routing_smoke_nonclaim"
	entry["requirementRefs"] = []any{}
	entry["ownerInvariantRefs"] = []any{}
	entry["falsifier"] = nil
	entry["oracle"] = nil
	entry["nonClaims"] = []any{"Route-only smoke proves wiring only."}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() rejected route-only nonclaim: %#v", record.JSONValue())
	}
	requireDiagnosticClassifications(t, record.JSONValue(), "warningClassifications", "warning", map[string]string{
		"route_only_nonclaim:test.inventory.semantic": "routing_smoke_only",
	})
	requireAgentAction(t, record.JSONValue(), "routing_smoke_only", "warning")
}

func TestBuildClassifiesCallerOwnedQualityFindings(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["qualityFindings"] = []any{
		map[string]any{
			"class":            "snapshot_without_oracle",
			"evidenceRefs":     []any{"test.inventory.semantic"},
			"findingId":        "finding.inventory.snapshot",
			"nonClaims":        []any{"Caller-owned finding does not prove inventory completeness."},
			"ownerReviewState": "candidate",
			"severity":         "warning",
		},
		map[string]any{
			"class":            "implementation_mirror",
			"evidenceRefs":     []any{"test.inventory.semantic"},
			"findingId":        "finding.inventory.implementation-mirror",
			"nonClaims":        []any{"Caller-owned finding does not execute tests."},
			"ownerReviewState": "confirmed",
			"severity":         "failure",
		},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("failure quality finding should fail inventory report: %#v", record.JSONValue())
	}
	requireDiagnosticClassifications(t, record.JSONValue(), "failureClassifications", "failure", map[string]string{
		"quality_finding:implementation_mirror:test.inventory.semantic:finding.inventory.implementation-mirror": "implementation_mirror",
	})
	requireDiagnosticClassifications(t, record.JSONValue(), "warningClassifications", "warning", map[string]string{
		"quality_finding:snapshot_without_oracle:test.inventory.semantic:finding.inventory.snapshot": "snapshot_without_oracle",
	})

	normalized, normalizedExitCode, err := BuildNormalized(input)
	if err != nil {
		t.Fatalf("BuildNormalized() error = %v", err)
	}
	if normalizedExitCode == 0 {
		t.Fatalf("failed quality finding must not emit usable normalized inventory: %#v", normalized)
	}
	if _, ok := normalized["inventory"]; ok {
		t.Fatalf("failed normalized output leaked usable inventory: %#v", normalized)
	}
}

func TestBuildNormalizedPreservesWarningOnlyQualityFindings(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["qualityFindings"] = []any{
		map[string]any{
			"class":            "snapshot_without_oracle",
			"evidenceRefs":     []any{"test.inventory.semantic"},
			"findingId":        "finding.inventory.snapshot",
			"nonClaims":        []any{"Caller-owned finding does not prove inventory completeness."},
			"ownerReviewState": "candidate",
			"severity":         "warning",
		},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("warning-only quality finding should not fail inventory report: %#v", record.JSONValue())
	}
	if record.Summary["qualityFindingFailureCount"] != 0 || record.Summary["qualityFindingWarningCount"] != 1 {
		t.Fatalf("unexpected quality finding summary: %#v", record.Summary)
	}
	requireDiagnosticClassifications(t, record.JSONValue(), "warningClassifications", "warning", map[string]string{
		"quality_finding:snapshot_without_oracle:test.inventory.semantic:finding.inventory.snapshot": "snapshot_without_oracle",
	})

	normalized, normalizedExitCode, err := BuildNormalized(input)
	if err != nil {
		t.Fatalf("BuildNormalized() error = %v", err)
	}
	if normalizedExitCode != 0 {
		t.Fatalf("warning-only quality finding should still emit normalized inventory: %#v", normalized)
	}
	entries := normalized["inventory"].(map[string]any)["entries"].([]any)
	findings := entries[0].(map[string]any)["qualityFindings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("normalized qualityFindings len=%d want 1: %#v", len(findings), normalized)
	}
	finding := findings[0].(map[string]any)
	if finding["findingId"] != "finding.inventory.snapshot" ||
		finding["class"] != "snapshot_without_oracle" ||
		finding["severity"] != "warning" ||
		finding["ownerReviewState"] != "candidate" {
		t.Fatalf("normalized quality finding drift: %#v", finding)
	}
}

func TestBuildRejectsUnknownQualityFindingClass(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["qualityFindings"] = []any{
		map[string]any{
			"class":            "made_up_weak_test_class",
			"evidenceRefs":     []any{"test.inventory.semantic"},
			"findingId":        "finding.inventory.unknown",
			"nonClaims":        []any{"Fixture-only finding."},
			"ownerReviewState": "candidate",
			"severity":         "warning",
		},
	}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "qualityFinding #1 class") {
		t.Fatalf("Build() error=%v, want unknown quality finding class rejection", err)
	}
}

func TestBuildRejectsSemanticEntryWithoutStableAnchor(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["requirementRefs"] = []any{}
	entry["ownerInvariantRefs"] = []any{}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted anchorless semantic entry: %#v", record.JSONValue())
	}
	if failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n"); !strings.Contains(failures, "missing_semantic_anchor:test.inventory.semantic") {
		t.Fatalf("missing semantic anchor failure not reported: %s", failures)
	}
}

func TestBuildRejectsRouteOnlySemanticAnchor(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["evidenceClass"] = "routing_smoke_nonclaim"
	entry["falsifier"] = nil
	entry["oracle"] = nil
	entry["nonClaims"] = []any{"Route-only smoke proves wiring only."}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted route-only semantic anchor: %#v", record.JSONValue())
	}
	if failures := strings.Join(stringDiagnostics(record.JSONValue(), "failures"), "\n"); !strings.Contains(failures, "wrong_evidence_boundary:test.inventory.semantic") {
		t.Fatalf("unexpected failures: %s", failures)
	}
}

func TestBuildAdmitsStructuredSelectorMatchingSourcePath(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["selector"] = "internal/command/testevidenceinventory/testevidenceinventory_test.go::TestSemantic"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() state=%s exit=%d report=%#v", record.State, exitCode, record.JSONValue())
	}

	normalized, normalizedExitCode, err := BuildNormalized(input)
	if err != nil {
		t.Fatalf("BuildNormalized() error = %v", err)
	}
	if normalizedExitCode != 0 {
		t.Fatalf("BuildNormalized() exit=%d output=%#v", normalizedExitCode, normalized)
	}
	normalizedEntry := normalized["inventory"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	if normalizedEntry["selector"] != entry["selector"] || normalizedEntry["sourcePath"] != entry["sourcePath"] {
		t.Fatalf("normalized entry drifted: %#v", normalizedEntry)
	}
}

func TestBuildRejectsStructuredSelectorSourcePathDrift(t *testing.T) {
	cases := []struct {
		name     string
		selector string
		want     string
	}{
		{
			name:     "mismatched path",
			selector: "internal/command/testevidenceinventory/other_test.go::TestSemantic",
			want:     "sourcePath must match selector path",
		},
		{
			name:     "unsafe path",
			selector: "../testevidenceinventory_test.go::TestSemantic",
			want:     "escape the repository root",
		},
		{
			name:     "invalid anchor",
			selector: "internal/command/testevidenceinventory/testevidenceinventory_test.go::bad anchor",
			want:     "stable rule identifier",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validInventory(t)
			entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
			entry["selector"] = item.selector

			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildRejectsUnsortedRequirementRefsAsAdmissionError(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["requirementRefs"] = []any{"REQ-PROOFKIT-TEST-002", "REQ-PROOFKIT-TEST-001"}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "requirementRefs must be sorted and unique") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildAdmitsWrappedSourceSetInventory(t *testing.T) {
	input := validSourceSetInventory(t)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() state=%s exit=%d report=%#v", record.State, exitCode, record.JSONValue())
	}
	if record.Summary["sourceCount"] != 1 || record.Summary["inputPathCount"] != 1 {
		t.Fatalf("unexpected source summary: %#v", record.Summary)
	}
	if record.Summary["semanticFalsifierCount"] != 1 {
		t.Fatalf("semanticFalsifierCount=%v", record.Summary["semanticFalsifierCount"])
	}
}

func TestBuildNormalizedInventoryFlattensSourceSet(t *testing.T) {
	output, exitCode, err := BuildNormalized(validSourceSetInventory(t))
	if err != nil {
		t.Fatalf("BuildNormalized() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildNormalized() exit=%d output=%#v", exitCode, output)
	}
	if output["normalizedKind"] != NormalizedInventoryKind ||
		output["normalizedInventoryId"] != "proofkit.test.inventory.source_set.normalized" ||
		output["sourceAuthority"] != sourceSetAuthority {
		t.Fatalf("unexpected normalized identity: %#v", output)
	}
	if _, err := admit.PreserveSortedTextArray(output["nonClaims"], "normalized inventory nonClaims", false); err != nil {
		t.Fatalf("normalized inventory top-level nonClaims must be downstream-admissible: %v", err)
	}
	inputPaths := output["inputPaths"].([]any)
	if len(inputPaths) != 1 || inputPaths[0] != "docs/contracts/test-inventory/alpha.v1.json" {
		t.Fatalf("unexpected input paths: %#v", inputPaths)
	}
	sourceColumns := output["sourceColumns"].([]any)
	if len(sourceColumns) != len(sourceSetColumns) || sourceColumns[0] != "source_id" {
		t.Fatalf("unexpected source columns: %#v", sourceColumns)
	}
	sourceRows := output["sources"].([]any)
	if len(sourceRows) != 1 {
		t.Fatalf("sources=%d want 1", len(sourceRows))
	}
	sourceRow := sourceRows[0].([]any)
	if len(sourceRow) != len(sourceSetColumns) {
		t.Fatalf("source row length=%d want %d: %#v", len(sourceRow), len(sourceSetColumns), sourceRow)
	}
	sourceRowNonClaims := sourceRow[4].([]any)
	if sourceRow[0] != "source.alpha" ||
		sourceRow[1] != "docs/contracts/test-inventory/alpha.v1.json" ||
		sourceRow[2] != sha256Text(wrappedInventoryText(t, "source.alpha")) ||
		sourceRow[3] != "test_evidence_inventory_fragment" ||
		len(sourceRowNonClaims) != 1 ||
		sourceRowNonClaims[0] != "Alpha source is fixture-only." {
		t.Fatalf("unexpected source metadata: %#v", sourceRow)
	}
	entrySources := output["entrySources"].([]any)
	if len(entrySources) != 1 {
		t.Fatalf("entrySources=%d want 1", len(entrySources))
	}
	entrySource := entrySources[0].(map[string]any)
	if entrySource["testId"] != "test.inventory.semantic" ||
		entrySource["sourceId"] != "source.alpha" ||
		entrySource["path"] != "docs/contracts/test-inventory/alpha.v1.json" {
		t.Fatalf("unexpected entry source metadata: %#v", entrySource)
	}
	inventory := output["inventory"].(map[string]any)
	if inventory["authority"] != directAuthority || inventory["inventoryId"] != "proofkit.test.inventory.source_set" {
		t.Fatalf("unexpected normalized inventory: %#v", inventory)
	}
	entries := inventory["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries=%d want 1", len(entries))
	}
	entry := entries[0].(map[string]any)
	if entry["testId"] != "test.inventory.semantic" || entry["sourcePath"] != "internal/command/testevidenceinventory/testevidenceinventory_test.go" {
		t.Fatalf("unexpected normalized entry: %#v", entry)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatalf("marshal normalized inventory: %v", err)
	}
	decoded, err := admission.DecodeJSON(strings.NewReader(string(encoded)), int64(len(encoded)+1))
	if err != nil {
		t.Fatalf("decode normalized inventory: %v", err)
	}
	record, roundTripExitCode, err := Build(decoded)
	if err != nil {
		t.Fatalf("normalized inventory must remain admissible as direct inventory: %v", err)
	}
	if roundTripExitCode != 0 || record.State != "passed" {
		t.Fatalf("normalized inventory round-trip state=%s exit=%d report=%#v", record.State, roundTripExitCode, record.JSONValue())
	}

	multiOutput, multiExitCode, err := BuildNormalized(multiSourceSetInventory(t))
	if err != nil {
		t.Fatalf("BuildNormalized(multi) error = %v", err)
	}
	if multiExitCode != 0 {
		t.Fatalf("BuildNormalized(multi) exit=%d output=%#v", multiExitCode, multiOutput)
	}
	entrySourceByTestID := map[string]string{}
	for _, raw := range multiOutput["entrySources"].([]any) {
		row := raw.(map[string]any)
		entrySourceByTestID[row["testId"].(string)] = row["sourceId"].(string) + "|" + row["path"].(string)
	}
	wantEntrySources := map[string]string{
		"test.inventory.source_alpha.primary":   "source.alpha|docs/contracts/test-inventory/alpha.v1.json",
		"test.inventory.source_alpha.secondary": "source.alpha|docs/contracts/test-inventory/alpha.v1.json",
		"test.inventory.source_beta.primary":    "source.beta|docs/contracts/test-inventory/beta.v1.json",
	}
	if len(entrySourceByTestID) != len(wantEntrySources) {
		t.Fatalf("entry source count=%d want %d: %#v", len(entrySourceByTestID), len(wantEntrySources), entrySourceByTestID)
	}
	for testID, want := range wantEntrySources {
		if entrySourceByTestID[testID] != want {
			t.Fatalf("entry source for %s = %q, want %q; all=%#v", testID, entrySourceByTestID[testID], want, entrySourceByTestID)
		}
	}
}

func TestAdmitNormalizedProjectionOwnsSourceSetEnvelope(t *testing.T) {
	output, exitCode, err := BuildNormalized(validSourceSetInventory(t))
	if err != nil || exitCode != 0 {
		t.Fatalf("BuildNormalized() exit=%d error=%v output=%#v", exitCode, err, output)
	}
	projection, err := AdmitNormalizedProjection(output, nil, "normalizedTestEvidenceInventory")
	if err != nil {
		t.Fatalf("AdmitNormalizedProjection() error = %v", err)
	}
	if projection.Result.Inventory.Authority != directAuthority {
		t.Fatalf("projection nested inventory authority=%q", projection.Result.Inventory.Authority)
	}
	if projection.Envelope["sourceAuthority"] != sourceSetAuthority {
		t.Fatalf("projection sourceAuthority=%#v", projection.Envelope["sourceAuthority"])
	}
	if projection.Inventory["authority"] != directAuthority {
		t.Fatalf("projection direct inventory=%#v", projection.Inventory)
	}

	tampered := cloneMap(output)
	tampered["entrySources"] = []any{}
	if _, err := AdmitNormalizedProjection(tampered, nil, "normalizedTestEvidenceInventory"); err == nil || !strings.Contains(err.Error(), "entrySources must cover every nested inventory entry") {
		t.Fatalf("AdmitNormalizedProjection() error=%v, want source-set coverage failure", err)
	}
}

func TestBuildNormalizedInventoryFailsClosedForWeakInventory(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["requirementRefs"] = []any{}
	entry["ownerInvariantRefs"] = []any{}

	output, exitCode, err := BuildNormalized(input)
	if err != nil {
		t.Fatalf("BuildNormalized() error = %v", err)
	}
	if exitCode == 0 || output["reportKind"] != ReportKind || output["state"] != "failed" {
		t.Fatalf("weak inventory must return failed report, exit=%d output=%#v", exitCode, output)
	}
	if _, ok := output["inventory"]; ok {
		t.Fatalf("failed normalized output must not expose usable inventory: %#v", output)
	}
}

func TestBuildNormalizedInventoryRejectsSourceSetSelectorDrift(t *testing.T) {
	entry := cloneMap(validInventory(t).(map[string]any)["entries"].([]any)[0].(map[string]any))
	entry["selector"] = "internal/command/testevidenceinventory/other_test.go::TestSemantic"
	text := wrappedInventoryTextWithEntries(t, "source.alpha", []map[string]any{entry})
	input := validSourceSetInventory(t).(map[string]any)
	input["sources"].([]any)[0].([]any)[2] = sha256Text(text)
	input["sourceTexts"].([]any)[0].(map[string]any)["text"] = text

	_, _, err := BuildNormalized(input)
	if err == nil || !strings.Contains(err.Error(), "sourcePath must match selector path") {
		t.Fatalf("BuildNormalized() error=%v, want selector/sourcePath drift", err)
	}
}

func TestBuildNormalizedInventoryRejectsDirectSelectorDrift(t *testing.T) {
	input := validInventory(t)
	entry := input.(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["selector"] = "internal/command/testevidenceinventory/other_test.go::TestSemantic"

	_, _, err := BuildNormalized(input)
	if err == nil || !strings.Contains(err.Error(), "sourcePath must match selector path") {
		t.Fatalf("BuildNormalized() error=%v, want direct selector/sourcePath drift", err)
	}
}

func TestBuildRejectsSourceSetDriftAndUnreferencedSourceText(t *testing.T) {
	t.Run("sha drift", func(t *testing.T) {
		input := validSourceSetInventory(t).(map[string]any)
		input["sources"].([]any)[0].([]any)[2] = strings.Repeat("0", 64)

		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "sha256 drift") {
			t.Fatalf("Build() error = %v, want sha256 drift", err)
		}
	})

	t.Run("unreferenced source text", func(t *testing.T) {
		input := validSourceSetInventory(t).(map[string]any)
		sourceTexts := input["sourceTexts"].([]any)
		sourceTexts = append(sourceTexts, map[string]any{
			"path": "docs/contracts/test-inventory/extra.v1.json",
			"text": wrappedInventoryText(t, "source.extra"),
		})
		input["sourceTexts"] = sourceTexts

		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "source text is not referenced by source set") {
			t.Fatalf("Build() error = %v, want unreferenced source text", err)
		}
	})
}

func TestBuildRejectsSourceSetSourceIDMismatch(t *testing.T) {
	input := validSourceSetInventory(t).(map[string]any)
	text := wrappedInventoryText(t, "source.other")
	input["sourceTexts"].([]any)[0].(map[string]any)["text"] = text
	input["sources"].([]any)[0].([]any)[2] = sha256Text(text)

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "sourceId must match source set id") {
		t.Fatalf("Build() error = %v, want sourceId mismatch", err)
	}
}

func TestBuildRejectsDuplicateTestIDsAcrossSourceSetFragments(t *testing.T) {
	first := wrappedInventoryText(t, "source.alpha")
	second := wrappedInventoryText(t, "source.beta")
	input := validSourceSetInventory(t).(map[string]any)
	input["sources"] = []any{
		[]any{"source.alpha", "docs/contracts/test-inventory/alpha.v1.json", sha256Text(first), "test_evidence_inventory_fragment", []any{"Alpha source is fixture-only."}},
		[]any{"source.beta", "docs/contracts/test-inventory/beta.v1.json", sha256Text(second), "test_evidence_inventory_fragment", []any{"Beta source is fixture-only."}},
	}
	input["sourceTexts"] = []any{
		map[string]any{"path": "docs/contracts/test-inventory/alpha.v1.json", "text": first},
		map[string]any{"path": "docs/contracts/test-inventory/beta.v1.json", "text": second},
	}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "testIds must be sorted and unique") {
		t.Fatalf("Build() error = %v, want duplicate testId admission failure", err)
	}
}

func validInventory(t *testing.T) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 1,
  "inventoryId": "proofkit.test.inventory",
  "authority": "caller_owned_inventory",
  "entries": [
    {
      "testId": "test.inventory.semantic",
      "selector": "go test ./internal/command/testevidenceinventory -run TestSemantic",
      "sourcePath": "internal/command/testevidenceinventory/testevidenceinventory_test.go",
      "ownerId": "proofkit.test",
      "evidenceClass": "semantic_falsifier",
      "requirementRefs": ["REQ-PROOFKIT-TEST-001"],
      "ownerInvariantRefs": [],
      "commandRefs": ["proofkit.test.command"],
      "witnessRefs": ["proofkit.test.witness"],
      "falsifier": {
        "falsifierId": "falsifier.inventory.semantic",
        "negativeCaseId": "case.inventory.semantic",
        "wrongImplementationClassId": "wrong.inventory.semantic",
        "dominanceGroup": "inventory.semantic",
        "supersedes": []
      },
      "oracle": {
        "oracleId": "oracle.inventory.semantic",
        "oracleKind": "negative_exit_and_diagnostic",
        "expectedPublicOutcome": "failed report with diagnostic",
        "assertionSummary": "A bad implementation is rejected with a failed report and diagnostic."
      },
      "nonClaims": []
    }
  ],
  "nonClaims": ["Inventory test fixture does not execute native tests."]
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return input
}

func validDiscoveryDraft() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"draftId":       "proofkit.discovery.draft",
		"authority":     discoveryAuthority,
		"repository": map[string]any{
			"repositoryId": "sample_repo",
			"nonClaims":    []any{"Repository fixture does not prove checkout freshness."},
		},
		"runner": map[string]any{
			"runnerId":         "sample.pytest",
			"runnerKind":       "pytest",
			"commandRef":       "sample.pytest.auth",
			"environmentClass": "local_python",
			"nonClaims":        []any{"Runner fixture does not execute pytest."},
		},
		"discoveredTests": []any{
			map[string]any{
				"testId":                   "test.discovery.semantic",
				"sourcePath":               "tests/test_auth.py",
				"selector":                 "tests/test_auth.py::test_rejects_missing_token",
				"title":                    "test_rejects_missing_token",
				"ownerId":                  "sample.auth",
				"candidateRequirementRefs": []any{"REQ-SAMPLE-AUTH-001"},
				"ownerInvariantRefs":       []any{"sample.auth.missing_token"},
				"oracleSignals":            []any{"assertion_present"},
				"selectorSignals":          []any{"raw_css_selector", "structured_selector"},
				"nonClaims":                []any{"Discovered test fixture is candidate-only."},
			},
		},
		"nonClaims": []any{"Discovery draft fixture does not prove inventory completeness."},
	}
}

func firstDiscoveryTest(input map[string]any) map[string]any {
	return input["discoveredTests"].([]any)[0].(map[string]any)
}

func validSourceSetInventory(t *testing.T) any {
	t.Helper()
	text := wrappedInventoryText(t, "source.alpha")
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"inventoryId":   "proofkit.test.inventory.source_set",
		"authority":     "caller_owned_inventory_source_set",
		"sourceColumns": []any{"source_id", "path", "sha256", "role", "non_claims"},
		"sources": []any{
			[]any{
				"source.alpha",
				"docs/contracts/test-inventory/alpha.v1.json",
				sha256Text(text),
				"test_evidence_inventory_fragment",
				[]any{"Alpha source is fixture-only."},
			},
		},
		"sourceTexts": []any{
			map[string]any{
				"path": "docs/contracts/test-inventory/alpha.v1.json",
				"text": text,
			},
		},
		"nonClaims": []any{"Source-set fixture does not execute native tests."},
	}
}

func multiSourceSetInventory(t *testing.T) any {
	t.Helper()
	alphaText := wrappedInventoryTextWithEntries(t, "source.alpha", []map[string]any{
		sourceInventoryEntry(t, "source.alpha", "primary"),
		sourceInventoryEntry(t, "source.alpha", "secondary"),
	})
	betaText := wrappedInventoryTextWithEntries(t, "source.beta", []map[string]any{
		sourceInventoryEntry(t, "source.beta", "primary"),
	})
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"inventoryId":   "proofkit.test.inventory.multi_source_set",
		"authority":     "caller_owned_inventory_source_set",
		"sourceColumns": []any{"source_id", "path", "sha256", "role", "non_claims"},
		"sources": []any{
			[]any{
				"source.alpha",
				"docs/contracts/test-inventory/alpha.v1.json",
				sha256Text(alphaText),
				"test_evidence_inventory_fragment",
				[]any{"Alpha source is fixture-only."},
			},
			[]any{
				"source.beta",
				"docs/contracts/test-inventory/beta.v1.json",
				sha256Text(betaText),
				"test_evidence_inventory_fragment",
				[]any{"Beta source is fixture-only."},
			},
		},
		"sourceTexts": []any{
			map[string]any{
				"path": "docs/contracts/test-inventory/alpha.v1.json",
				"text": alphaText,
			},
			map[string]any{
				"path": "docs/contracts/test-inventory/beta.v1.json",
				"text": betaText,
			},
		},
		"nonClaims": []any{"Source-set fixture does not execute native tests."},
	}
}

func wrappedInventoryText(t *testing.T, sourceID string) string {
	t.Helper()
	return wrappedInventoryTextWithEntries(t, sourceID, []map[string]any{
		validInventory(t).(map[string]any)["entries"].([]any)[0].(map[string]any),
	})
}

func wrappedInventoryTextWithEntries(t *testing.T, sourceID string, entries []map[string]any) string {
	t.Helper()
	input := validInventory(t).(map[string]any)
	input["inventoryId"] = sourceID + ".inventory"
	input["sourceId"] = sourceID
	input["ownerId"] = "proofkit.test"
	rawEntries := make([]any, 0, len(entries))
	for _, entry := range entries {
		rawEntries = append(rawEntries, entry)
	}
	input["entries"] = rawEntries
	encoded, err := json.Marshal(map[string]any{
		"schema":    "proofkit.requirement-test-inventory.v1",
		"inventory": input,
	})
	if err != nil {
		t.Fatalf("marshal wrapped inventory: %v", err)
	}
	return string(encoded)
}

func sourceInventoryEntry(t *testing.T, sourceID string, label string) map[string]any {
	t.Helper()
	token := strings.ReplaceAll(sourceID, ".", "_")
	upper := strings.ToUpper(strings.ReplaceAll(token, "_", "-")) + "-" + strings.ToUpper(label)
	entry := cloneMap(validInventory(t).(map[string]any)["entries"].([]any)[0].(map[string]any))
	entry["testId"] = "test.inventory." + token + "." + label
	entry["requirementRefs"] = []any{"REQ-PROOFKIT-TEST-" + upper}
	entry["commandRefs"] = []any{"proofkit.test.command." + token + "." + label}
	entry["witnessRefs"] = []any{"proofkit.test.witness." + token + "." + label}
	entry["falsifier"] = map[string]any{
		"dominanceGroup":             "inventory." + token + "." + label,
		"falsifierId":                "falsifier.inventory." + token + "." + label,
		"negativeCaseId":             "case.inventory." + token + "." + label,
		"supersedes":                 []any{},
		"wrongImplementationClassId": "wrong.inventory." + token + "." + label,
	}
	entry["oracle"] = map[string]any{
		"assertionSummary":      "A bad " + sourceID + " " + label + " implementation is rejected with a failed report and diagnostic.",
		"expectedPublicOutcome": "failed report with diagnostic",
		"oracleId":              "oracle.inventory." + token + "." + label,
		"oracleKind":            "negative_exit_and_diagnostic",
	}
	return entry
}

func sha256Text(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func cloneMap(input map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range input {
		result[key] = value
	}
	return result
}

func anyStrings(raw any) []string {
	values := raw.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.(string))
	}
	return result
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func stringDiagnostics(record map[string]any, key string) []string {
	for _, raw := range record["diagnostics"].([]any) {
		item := raw.(map[string]any)
		if item["key"] != key {
			continue
		}
		values := item["value"].([]any)
		result := make([]string, 0, len(values))
		for _, value := range values {
			result = append(result, value.(string))
		}
		return result
	}
	return nil
}

func requireDiagnosticClassifications(t *testing.T, record map[string]any, key string, severity string, expected map[string]string) {
	t.Helper()
	raw := diagnosticValue(record, key)
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("%s missing or not array: %#v", key, raw)
	}
	if len(values) != len(expected) {
		t.Fatalf("%s len=%d want %d: %#v", key, len(values), len(expected), values)
	}
	for _, rawItem := range values {
		item, ok := rawItem.(map[string]any)
		if !ok {
			t.Fatalf("%s has non-object item: %#v", key, rawItem)
		}
		diagnostic, ok := item["diagnostic"].(string)
		if !ok {
			t.Fatalf("%s item missing diagnostic: %#v", key, item)
		}
		want, ok := expected[diagnostic]
		if !ok {
			t.Fatalf("%s unexpected diagnostic %q; expected=%v", key, diagnostic, expected)
		}
		if item["classificationId"] != want {
			t.Fatalf("%s diagnostic %q classification=%v want %q", key, diagnostic, item["classificationId"], want)
		}
		if item["severity"] != severity {
			t.Fatalf("%s diagnostic %q severity=%v want %q", key, diagnostic, item["severity"], severity)
		}
	}
}

func requireAgentAction(t *testing.T, record map[string]any, classificationID string, severity string) {
	t.Helper()
	for _, action := range agentActions(record) {
		if action["classificationId"] == classificationID && action["severity"] == severity {
			if action["decisionOwner"] != "consumer_repository" {
				t.Fatalf("agent action %s owner=%#v", classificationID, action["decisionOwner"])
			}
			if action["instruction"] == "" || action["nonClaim"] == "" {
				t.Fatalf("agent action %s missing instruction/nonClaim: %#v", classificationID, action)
			}
			return
		}
	}
	t.Fatalf("missing agent action classification=%s severity=%s in %#v", classificationID, severity, agentActions(record))
}

func agentActions(record map[string]any) []map[string]any {
	raw := diagnosticValue(record, "agentActionPlan")
	values, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(values))
	for _, rawItem := range values {
		item, ok := rawItem.(map[string]any)
		if ok {
			result = append(result, item)
		}
	}
	return result
}

func diagnosticValue(record map[string]any, key string) any {
	for _, raw := range record["diagnostics"].([]any) {
		item := raw.(map[string]any)
		if item["key"] == key {
			return item["value"]
		}
	}
	return nil
}
