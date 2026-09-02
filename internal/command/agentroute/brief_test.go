package agentroute

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestAgentBriefIsBoundedAndFullEnvelopeRemainsAvailable(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.render",
		"goal":          "render_human_view",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{"kind": "proof_binding", "ref": "proofkit/requirement-bindings.json"},
			map[string]any{"kind": "requirement_source", "ref": "docs/specs/example/requirements.v1.json"},
		},
	}
	report, reportExitCode, err := Build(input)
	if err != nil || reportExitCode != 0 {
		t.Fatalf("Build() exit=%d error=%v", reportExitCode, err)
	}
	brief, exitCode, err := buildBriefEnvelope(input)
	if err != nil || exitCode != 0 {
		t.Fatalf("BuildEnvelope() exit=%d error=%v", exitCode, err)
	}
	full, fullExitCode, err := BuildEnvelope(input)
	if err != nil || fullExitCode != 0 {
		t.Fatalf("buildFullEnvelope() exit=%d error=%v", fullExitCode, err)
	}

	if brief["packetKind"] != "proofkit.agent-route.brief" || brief["schemaVersion"] != 1 {
		t.Fatalf("unexpected brief identity: %#v", brief)
	}
	if brief["state"] != "routed" || brief["routeFamily"] != "rendered_views" {
		t.Fatalf("unexpected brief route state: %#v", brief)
	}
	action := brief["nextAction"].(map[string]any)
	if action["commandRef"] != "requirement-source-view" || action["argvState"] != "inline" {
		t.Fatalf("brief did not retain the first canonical action: %#v", action)
	}
	if _, ok := brief["nonClaims"]; ok {
		t.Fatalf("brief duplicated policy prose: %#v", brief)
	}
	if _, ok := brief["routeQuestions"]; ok {
		t.Fatalf("brief duplicated route questions: %#v", brief)
	}
	omissions := brief["omissionSummary"].(map[string]any)
	if omissions["availableAlternativeCommandCount"] != 3 || omissions["sourceOmittedCommandCount"] != 6 {
		t.Fatalf("brief omission accounting drifted: %#v", omissions)
	}
	detail := brief["detailAccess"].(map[string]any)
	wantDigest := independentlyHashStableJSON(t, report)
	if detail["sourceReportDigest"] != wantDigest || detail["requiresOriginalInput"] != true || detail["requiresOriginalLauncherContext"] != true || detail["launcherProfile"] != cliexec.ProfilePath {
		t.Fatalf("brief detail access is not source-bound: %#v", detail)
	}
	outputArgs := detail["outputArgs"].(map[string]any)
	if !slices.Equal(stringsFromAny(outputArgs["full"]), []string{"--agent-envelope", "--agent-envelope-mode", "full"}) || len(outputArgs["report"].([]any)) != 0 {
		t.Fatalf("brief detail access is not executable: %#v", detail)
	}
	if !slices.Equal(stringsFromAny(brief["boundaryPolicyRefs"]), []string{"REQ-PROOFKIT-SPEC-005", "REQ-PROOFKIT-SPEC-026"}) {
		t.Fatalf("brief boundary policy refs are not exact: %#v", brief["boundaryPolicyRefs"])
	}

	briefBytes, err := stablejson.Marshal(brief)
	if err != nil {
		t.Fatal(err)
	}
	fullBytes, err := stablejson.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if len(briefBytes) > maxAgentBriefBytes || len(briefBytes) >= len(fullBytes) {
		t.Fatalf("brief bytes=%d full bytes=%d limit=%d", len(briefBytes), len(fullBytes), maxAgentBriefBytes)
	}
	rebuilt, _, err := buildBriefEnvelope(input)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltBytes, err := stablejson.Marshal(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	if string(briefBytes) != string(rebuiltBytes) {
		t.Fatal("brief projection is not deterministic")
	}
}

func TestAgentBriefClosesEverySelectedCommandInputReference(t *testing.T) {
	t.Parallel()

	brief, exitCode, err := buildBriefEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.typescript-api",
		"goal":          "verify_typescript_public_api",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{"kind": "typescript_public_api_manifest", "ref": "proofkit/typescript-public-api.json"},
			map[string]any{"kind": "typescript_public_api_repo_root", "ref": "."},
		},
	})
	if err != nil || exitCode != 0 {
		t.Fatalf("brief exit=%d error=%v", exitCode, err)
	}
	refs := brief["contextRefs"].([]any)
	if len(refs) != 2 {
		t.Fatalf("context ref count=%d want 2: %#v", len(refs), refs)
	}
	want := []struct {
		role    string
		pointer string
	}{
		{role: "caller_owned_repo_root", pointer: "/nextCommands/0/argv/3"},
		{role: "caller_owned_input", pointer: "/nextCommands/0/argv/5"},
	}
	for index, expectation := range want {
		ref := refs[index].(map[string]any)
		if ref["role"] != expectation.role || ref["sourceReportPointer"] != expectation.pointer {
			t.Fatalf("context ref %d=%#v want role=%s pointer=%s", index, ref, expectation.role, expectation.pointer)
		}
	}
}

func TestAgentBriefNamesCompleteInputBundleBlocker(t *testing.T) {
	t.Parallel()

	brief, exitCode, err := buildBriefEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.context",
		"goal":          "inspect_requirement_context",
		"mode":          "observe",
	})
	if err != nil || exitCode != 1 {
		t.Fatalf("brief exit=%d error=%v", exitCode, err)
	}
	blocker := brief["blockers"].([]any)[0].(map[string]any)
	want := "requirement_context_catalog_and_requirement_context_repo_root_or_requirement_context_slice_input_or_requirement_workspace_input"
	if blocker["subject"] != want {
		t.Fatalf("bundle blocker subject=%v want %s", blocker["subject"], want)
	}
}

func TestBuildEnvelopePreservesBlockedStateWithoutExecutableAction(t *testing.T) {
	t.Parallel()

	brief, exitCode, err := buildBriefEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.blocked",
		"goal":          "inventory_tests",
		"mode":          "observe",
	})
	if err != nil || exitCode != 1 {
		t.Fatalf("BuildEnvelope() exit=%d error=%v", exitCode, err)
	}
	if brief["nextAction"] != nil {
		t.Fatalf("blocked brief exposed executable action: %#v", brief["nextAction"])
	}
	blockers := brief["blockers"].([]any)
	if len(blockers) != 1 || blockers[0].(map[string]any)["kind"] != "missing_input" {
		t.Fatalf("blocked brief lost typed blocker: %#v", blockers)
	}
	if contextRefs := brief["contextRefs"].([]any); len(contextRefs) != 0 {
		t.Fatalf("blocked brief exposed action context: %#v", contextRefs)
	}
}

func TestBuildEnvelopeCompactsOversizedArgvWithoutLosingActionIdentity(t *testing.T) {
	t.Parallel()

	longRef := "docs/specs/" + strings.Repeat("a", 5000) + ".json"
	brief, exitCode, err := buildBriefEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.long-ref",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{"kind": "requirement_source", "ref": longRef},
		},
	})
	if err != nil || exitCode != 0 {
		t.Fatalf("BuildEnvelope() exit=%d error=%v", exitCode, err)
	}
	action := brief["nextAction"].(map[string]any)
	if action["commandRef"] != "requirement-source-admission" || action["commandId"] == "" {
		t.Fatalf("compacted action lost identity: %#v", action)
	}
	if action["argvState"] != "detail_required" {
		t.Fatalf("oversized argv was not deferred to detail access: %#v", action)
	}
	if _, ok := action["argv"]; ok {
		t.Fatalf("compacted action retained oversized argv: %#v", action)
	}
	encoded, err := stablejson.Marshal(brief)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxAgentBriefBytes || strings.Contains(string(encoded), longRef) {
		t.Fatalf("compacted brief bytes=%d leaked oversized ref", len(encoded))
	}
}

func TestAgentBriefCompactsAtDeclaredByteBoundary(t *testing.T) {
	t.Parallel()
	const ownerDeclaredByteLimit = 3072
	if maxAgentBriefBytes != ownerDeclaredByteLimit {
		t.Fatalf("agent brief byte limit=%d want owner-declared %d", maxAgentBriefBytes, ownerDeclaredByteLimit)
	}

	var exactReport map[string]any
	var aboveReport map[string]any
	var aboveBytes int
	for refRunes := 800; refRunes <= 2400; refRunes++ {
		report, exitCode, err := Build(map[string]any{
			"schemaVersion": jsonNumber("1"),
			"routeId":       "consumer.route.boundary",
			"goal":          "validate_requirement_source",
			"mode":          "observe",
			"availableInputs": []any{
				map[string]any{"kind": "requirement_source", "ref": "docs/specs/" + strings.Repeat("a", refRunes) + ".json"},
			},
		})
		if err != nil || exitCode != 0 {
			t.Fatalf("Build() exit=%d error=%v", exitCode, err)
		}
		unbounded, err := projectAgentBrief(report)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := stablejson.Marshal(unbounded)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case len(encoded) == maxAgentBriefBytes:
			exactReport = report
		case len(encoded) > maxAgentBriefBytes && aboveReport == nil:
			aboveReport = report
			aboveBytes = len(encoded)
		}
		if exactReport != nil && aboveReport != nil {
			break
		}
	}
	if exactReport == nil || aboveReport == nil {
		t.Fatalf("failed to construct exact and above-bound briefs: exact=%t above=%t", exactReport != nil, aboveReport != nil)
	}
	exactBrief, err := AgentBrief(exactReport)
	if err != nil {
		t.Fatal(err)
	}
	exactAction := exactBrief["nextAction"].(map[string]any)
	if exactAction["argvState"] != "inline" {
		t.Fatalf("brief at the exact byte limit was compacted: %#v", exactAction)
	}
	if _, retained := exactAction["argv"]; !retained {
		t.Fatal("brief at the exact byte limit lost inline argv")
	}
	exactBytes, err := stablejson.Marshal(exactBrief)
	if err != nil {
		t.Fatal(err)
	}
	if len(exactBytes) != maxAgentBriefBytes {
		t.Fatalf("exact-bound brief bytes=%d want=%d", len(exactBytes), maxAgentBriefBytes)
	}
	brief, err := AgentBrief(aboveReport)
	if err != nil {
		t.Fatal(err)
	}
	action := brief["nextAction"].(map[string]any)
	if action["argvState"] != "detail_required" {
		t.Fatalf("unbounded brief bytes=%d was not compacted at limit=%d: %#v", aboveBytes, maxAgentBriefBytes, action)
	}
	if _, retained := action["argv"]; retained {
		t.Fatal("boundary-compacted brief retained inline argv")
	}
	encoded, err := stablejson.Marshal(brief)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxAgentBriefBytes {
		t.Fatalf("compacted brief bytes=%d exceed limit=%d", len(encoded), maxAgentBriefBytes)
	}
}

func TestAgentBriefPreservesBlockedRouteOmissionsAndUnknownReportBlockers(t *testing.T) {
	t.Parallel()

	blockedInput := map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.blocked-available",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{"kind": "requirement_source", "ref": "docs/specs/example/requirements.v1.json"},
		},
		"observedReports": []any{
			map[string]any{"kind": "requirement_source", "ref": "artifacts/proofkit/source-report.json", "state": "warning"},
		},
	}
	report, reportExitCode, err := Build(blockedInput)
	if err != nil || reportExitCode != 1 {
		t.Fatalf("Build(blocked) exit=%d error=%v", reportExitCode, err)
	}
	brief, briefExitCode, err := buildBriefEnvelope(blockedInput)
	if err != nil || briefExitCode != 1 {
		t.Fatalf("BuildEnvelope(blocked) exit=%d error=%v", briefExitCode, err)
	}
	if report["summary"].(map[string]any)["availableCommandCount"] != 1 || brief["omissionSummary"].(map[string]any)["availableAlternativeCommandCount"] != 1 {
		t.Fatalf("blocked route lost available command accounting: report=%#v brief=%#v", report["summary"], brief["omissionSummary"])
	}

	unknownInput := map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.unknown-observed",
		"goal":          "unknown",
		"mode":          "observe",
		"observedReports": []any{
			map[string]any{"kind": "release", "ref": "artifacts/proofkit/release-report.json", "state": "failed"},
		},
	}
	unknown, exitCode, err := buildBriefEnvelope(unknownInput)
	if err != nil || exitCode != 1 {
		t.Fatalf("BuildEnvelope(unknown) exit=%d error=%v", exitCode, err)
	}
	blockers := unknown["blockers"].([]any)
	if len(blockers) != 2 || blockers[0].(map[string]any)["kind"] != "unknown_goal" {
		t.Fatalf("unknown route did not retain ordered blockers: %#v", blockers)
	}
	observed := blockers[1].(map[string]any)
	if observed["kind"] != "observed_report" || observed["state"] != "failed" || observed["subject"] != "release" || observed["sourceReportPointer"] != "/observedReports/0" {
		t.Fatalf("unknown route observed-report blocker drifted: %#v", observed)
	}
	if unknown["omissionSummary"].(map[string]any)["sourceOmittedCommandCount"] != 0 {
		t.Fatalf("unknown route counted a policy omission as a command: %#v", unknown["omissionSummary"])
	}
}

func TestAgentBriefBindsLauncherContextThatAffectsReportDigest(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.launcher",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{"kind": "requirement_source", "ref": "docs/specs/example/requirements.v1.json"},
		},
	}
	npmRenderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfileNPMOffline, "")
	if err != nil {
		t.Fatal(err)
	}
	pathBrief, _, err := BuildEnvelopeModeWithRenderer(input, cliexec.PathRenderer(), EnvelopeModeBrief)
	if err != nil {
		t.Fatal(err)
	}
	npmBrief, _, err := BuildEnvelopeModeWithRenderer(input, npmRenderer, EnvelopeModeBrief)
	if err != nil {
		t.Fatal(err)
	}
	pathDetail := pathBrief["detailAccess"].(map[string]any)
	npmDetail := npmBrief["detailAccess"].(map[string]any)
	pathReport, _, err := BuildWithRenderer(input, cliexec.PathRenderer())
	if err != nil {
		t.Fatal(err)
	}
	npmReport, _, err := BuildWithRenderer(input, npmRenderer)
	if err != nil {
		t.Fatal(err)
	}
	if pathDetail["launcherProfile"] != cliexec.ProfilePath || npmDetail["launcherProfile"] != cliexec.ProfileNPMOffline {
		t.Fatalf("brief launcher profiles are not exact: path=%#v npm=%#v", pathDetail, npmDetail)
	}
	if pathDetail["sourceReportDigest"] != independentlyHashStableJSON(t, pathReport) || npmDetail["sourceReportDigest"] != independentlyHashStableJSON(t, npmReport) {
		t.Fatalf("launcher-dependent source digests are not independently reproducible: path=%#v npm=%#v", pathDetail, npmDetail)
	}
	if pathDetail["sourceReportDigest"] == npmDetail["sourceReportDigest"] {
		t.Fatal("launcher-dependent route reports unexpectedly share a digest")
	}
}

func TestBuildEnvelopeCapsBlockersAndCountsOmittedDetails(t *testing.T) {
	t.Parallel()

	reports := make([]any, 0, 6)
	for index := 0; index < 6; index++ {
		reports = append(reports, map[string]any{
			"kind":  "requirement_source",
			"ref":   "artifacts/proofkit/source-report-" + string(rune('a'+index)) + ".json",
			"state": "warning",
		})
	}
	brief, exitCode, err := buildBriefEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.many-blockers",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{"kind": "requirement_source", "ref": "docs/specs/example/requirements.v1.json"},
		},
		"observedReports": reports,
	})
	if err != nil || exitCode != 1 {
		t.Fatalf("BuildEnvelope() exit=%d error=%v", exitCode, err)
	}
	if got := len(brief["blockers"].([]any)); got != maxBriefBlockerItems {
		t.Fatalf("blocker count=%d want=%d", got, maxBriefBlockerItems)
	}
	omissions := brief["omissionSummary"].(map[string]any)
	if omissions["omittedBlockerCount"] != 2 {
		t.Fatalf("omitted blocker count drifted: %#v", omissions)
	}
}

func TestBriefBlockerBoundDominatesMapMaterialization(t *testing.T) {
	t.Parallel()

	blockers := make([]any, 0, maxBriefBlockerItems)
	total := 0
	materialized := 0
	for index := 0; index < 10_000; index++ {
		appendBoundedBriefBlocker(&blockers, &total, func() map[string]any {
			materialized++
			return map[string]any{"blockerId": index}
		})
	}
	if len(blockers) != 4 || cap(blockers) != 4 || total != 10_000 || materialized != 4 {
		t.Fatalf("blocker bound did not dominate materialization: len=%d cap=%d total=%d materialized=%d", len(blockers), cap(blockers), total, materialized)
	}
}

func TestBriefBlockerBoundDominatesProductionAllocations(t *testing.T) {
	reportWith := func(count int) map[string]any {
		reports := make([]any, count)
		for index := range reports {
			reports[index] = map[string]any{
				"kind":  "requirement_source",
				"state": "warning",
			}
		}
		return map[string]any{
			"observedReports": reports,
			"state":           "blocked_ambiguous_state",
		}
	}
	measure := func(report map[string]any) float64 {
		var blockers []any
		var omitted int
		allocations := testing.AllocsPerRun(20, func() {
			blockers, omitted = briefBlockers(report, "consumer.route.bounded-work")
		})
		if len(blockers) != maxBriefBlockerItems || omitted != len(report["observedReports"].([]any))-maxBriefBlockerItems {
			t.Fatalf("allocation probe produced invalid blockers: len=%d omitted=%d", len(blockers), omitted)
		}
		return allocations
	}

	boundedAllocations := measure(reportWith(maxBriefBlockerItems))
	largeAllocations := measure(reportWith(10_000))
	const maxInstrumentationAllocationDelta = 32
	if largeAllocations > boundedAllocations+maxInstrumentationAllocationDelta {
		t.Fatalf("omitted blockers caused map allocation growth: bounded=%.2f large=%.2f", boundedAllocations, largeAllocations)
	}
}

func TestBuildEnvelopeModeRejectsUnknownMode(t *testing.T) {
	t.Parallel()

	_, exitCode, err := BuildEnvelopeModeWithRenderer(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.mode",
		"goal":          "unknown",
		"mode":          "observe",
	}, cliexec.PathRenderer(), EnvelopeMode("expanded"))
	if err == nil || exitCode != 1 {
		t.Fatalf("unknown mode exit=%d error=%v", exitCode, err)
	}
}

func buildBriefEnvelope(raw any) (map[string]any, int, error) {
	return BuildEnvelopeModeWithRenderer(raw, cliexec.PathRenderer(), EnvelopeModeBrief)
}

func independentlyHashStableJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
