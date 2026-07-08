package requirementimpactinput

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestBuildComposesInputAndRoutesChangedBlockingRequirement(t *testing.T) {
	input := validComposeInput(t)
	currentSource := input["currentRequirementSources"].([]any)[0].(map[string]any)
	currentSource["requirements"].([]any)[0].(map[string]any)["invariant"] = "Requirement impact input composition must route changed blocking requirement records to caller-owned proof obligations."

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit = %d, want 0", exitCode)
	}
	assertStringArray(t, output["changedRecordIds"], []string{"REQ-PROOFKIT-IMPACT-001"})
	if _, exists := output["unboundProofChangeRationale"]; exists {
		t.Fatalf("composer emitted empty unboundProofChangeRationale: %#v", output)
	}

	impactReport, impactExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(composed) error = %v", err)
	}
	if impactExit != 0 || impactReport["impactState"] != "ok" {
		t.Fatalf("impact.Build(composed) exit = %d report = %#v, want ok", impactExit, impactReport)
	}
	obligations := impactReport["obligations"].([]any)
	if len(obligations) != 1 || obligations[0].(map[string]any)["recordId"] != "REQ-PROOFKIT-IMPACT-001" {
		t.Fatalf("obligations = %#v, want REQ-PROOFKIT-IMPACT-001", obligations)
	}
	assertStringArray(t, impactReport["nonClaims"], []string{
		"Impact reports classify caller-owned changed paths and proof records only.",
		"Impact reports do not decide the consuming repository fallback policy for unbound or unknown proof changes.",
		"Impact reports do not run git, scan repositories, execute witnesses, authenticate receipts, approve merge, or prove proof freshness.",
		"Requirement impact input composition is caller-owned route input and does not execute native witnesses.",
		"Requirement impact input composition treats proof-like paths as policy hints, not proof evidence.",
	})
}

func TestBuildFailsDownstreamWhenChangedBlockingRequirementHasNoBinding(t *testing.T) {
	input := validComposeInput(t)
	currentSource := input["currentRequirementSources"].([]any)[0].(map[string]any)
	currentSource["requirements"].([]any)[0].(map[string]any)["invariant"] = "Requirement impact input composition must fail closed when a changed active blocking requirement has no current binding."
	currentContract := input["currentCompactProofContract"].(map[string]any)
	currentContract["bindings"] = currentContract["bindings"].([]any)[1:]

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit = %d, want composition admission success with downstream failure input", exitCode)
	}
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(composed) error = %v", err)
	}
	if reportExit == 0 || report["impactState"] != "failed" {
		t.Fatalf("impact report = %#v exit = %d, want failed", report, reportExit)
	}
	assertContainsFailure(t, report, "current active blocking requirement has no current proof binding: REQ-PROOFKIT-IMPACT-001")
}

func TestBuildFailsDownstreamWhenUnchangedCurrentBlockingRequirementHasNoBinding(t *testing.T) {
	input := validComposeInput(t)
	currentContract := input["currentCompactProofContract"].(map[string]any)
	currentContract["bindings"] = currentContract["bindings"].([]any)[1:]

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit = %d, want composition admission success with downstream failure input", exitCode)
	}
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(composed) error = %v", err)
	}
	if reportExit == 0 {
		t.Fatalf("impact report unexpectedly passed: %#v", report)
	}
	assertContainsFailure(t, report, "current active blocking requirement has no current proof binding: REQ-PROOFKIT-IMPACT-001")
}

func TestBuildRejectsPartialBaselineSnapshots(t *testing.T) {
	input := validComposeInput(t)
	input["baseCompactProofContract"] = nil

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "baseRequirementSources and baseCompactProofContract must both be present or both be null") {
		t.Fatalf("Build() error = %v, want partial baseline rejection", err)
	}

	input = validComposeInput(t)
	input["baseRequirementSources"] = nil

	_, _, err = Build(input)
	if err == nil || !strings.Contains(err.Error(), "baseRequirementSources and baseCompactProofContract must both be present or both be null") {
		t.Fatalf("Build() error = %v, want partial baseline rejection", err)
	}
}

func TestBuildAcceptsFullNullNewAdoptionBaseline(t *testing.T) {
	input := validComposeInput(t)
	input["baseRequirementSources"] = nil
	input["baseCompactProofContract"] = nil

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit = %d, want new-adoption composition success", exitCode)
	}
	assertStringArray(t, output["changedRecordIds"], []string{"REQ-PROOFKIT-IMPACT-001", "REQ-PROOFKIT-IMPACT-002"})
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(new adoption) error = %v", err)
	}
	if reportExit != 0 || len(report["obligations"].([]any)) != 2 {
		t.Fatalf("new adoption impact report = %#v exit = %d, want two obligations", report, reportExit)
	}
}

func TestBuildFailsDownstreamForRemovedRequirementAndRemovedBinding(t *testing.T) {
	input := validComposeInput(t)
	currentSource := input["currentRequirementSources"].([]any)[0].(map[string]any)
	currentSource["requirements"] = currentSource["requirements"].([]any)[1:]

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() removed requirement error = %v", err)
	}
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(removed requirement) error = %v", err)
	}
	if reportExit == 0 {
		t.Fatalf("removed requirement report unexpectedly passed: %#v", report)
	}
	assertContainsFailure(t, report, "removed requirement record: REQ-PROOFKIT-IMPACT-001")
	assertContainsFailure(t, report, "current compact proof binding references unknown current requirement: REQ-PROOFKIT-IMPACT-001")

	input = validComposeInput(t)
	currentContract := input["currentCompactProofContract"].(map[string]any)
	currentContract["bindings"] = currentContract["bindings"].([]any)[1:]
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"docs/contracts/proofkit-impact.json"}}}

	output, _, err = Build(input)
	if err != nil {
		t.Fatalf("Build() removed binding error = %v", err)
	}
	report, reportExit, err = impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(removed binding) error = %v", err)
	}
	if reportExit == 0 {
		t.Fatalf("removed binding report unexpectedly passed: %#v", report)
	}
	assertContainsFailure(t, report, "removed proof binding for active blocking requirement: REQ-PROOFKIT-IMPACT-001")
}

func TestBuildRoutesFullCompactBindingDrift(t *testing.T) {
	input := validComposeInput(t)
	currentContract := input["currentCompactProofContract"].(map[string]any)
	binding := currentContract["bindings"].([]any)[0].([]any)
	binding[4] = "proofkit.impact_one_changed"
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"docs/contracts/proofkit-impact.json"}}}

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	assertStringArray(t, output["changedBindingRecordIds"], []string{"REQ-PROOFKIT-IMPACT-001"})
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(binding drift) error = %v", err)
	}
	if reportExit != 0 {
		t.Fatalf("binding drift impact report = %#v exit = %d, want pass", report, reportExit)
	}
	assertObligationHasReason(t, report, "REQ-PROOFKIT-IMPACT-001", "proof_binding_changed")
}

func TestBuildRoutesAddedCurrentBinding(t *testing.T) {
	input := validComposeInput(t)
	currentSource := input["currentRequirementSources"].([]any)[0].(map[string]any)
	currentSource["requirements"] = append(currentSource["requirements"].([]any), requirement("REQ-PROOFKIT-IMPACT-004", "Requirement impact input composition routes added current proof bindings when proof source evidence changed.", "blocking"))
	currentContract := input["currentCompactProofContract"].(map[string]any)
	currentContract["bindings"] = append(currentContract["bindings"].([]any), binding("REQ-PROOFKIT-IMPACT-004", "proofkit.impact.surface::scenario_added", "proofkit.impact_added", "internal/command/requirementimpactinput/added_test.go::positive_added", "internal/command/requirementimpactinput/added_test.go::negative_added"))
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"docs/contracts/proofkit-impact.json"}}}

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	assertStringArray(t, output["changedBindingRecordIds"], []string{"REQ-PROOFKIT-IMPACT-004"})
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(added binding) error = %v", err)
	}
	if reportExit != 0 {
		t.Fatalf("added binding impact report = %#v exit = %d, want pass", report, reportExit)
	}
	assertObligationHasReason(t, report, "REQ-PROOFKIT-IMPACT-004", "proof_binding_changed")
}

func TestBuildDoesNotCreateObligationsForAdvisoryRequirementChanges(t *testing.T) {
	input := validComposeInput(t)
	currentSource := input["currentRequirementSources"].([]any)[0].(map[string]any)
	currentSource["requirements"].([]any)[2].(map[string]any)["invariant"] = "Requirement impact input composition preserves advisory deltas without creating blocking obligations."

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	assertStringArray(t, output["changedRecordIds"], []string{})
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(advisory) error = %v", err)
	}
	if reportExit != 0 || len(report["obligations"].([]any)) != 0 {
		t.Fatalf("advisory impact report = %#v exit = %d, want no obligations", report, reportExit)
	}
}

func TestBuildFlattensMultipleRequirementSourcesDeterministically(t *testing.T) {
	first := validComposeInput(t)
	firstRequirements := first["currentRequirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)
	firstSource := requirementSource([]any{firstRequirements[0]})
	setSourceIdentity(firstSource, "proofkit.impact.source_a", "docs/specs/proofkit-impact-a")
	secondSource := requirementSource([]any{firstRequirements[1], firstRequirements[2]})
	setSourceIdentity(secondSource, "proofkit.impact.source_b", "docs/specs/proofkit-impact-b")
	first["baseRequirementSources"] = []any{cloneAny(t, firstSource), cloneAny(t, secondSource)}
	first["currentRequirementSources"] = []any{cloneAny(t, firstSource), cloneAny(t, secondSource)}
	singleOutput, _, err := Build(validComposeInput(t))
	if err != nil {
		t.Fatalf("Build(single source) error = %v", err)
	}
	multiOutput, _, err := Build(first)
	if err != nil {
		t.Fatalf("Build(multi source) error = %v", err)
	}
	singleBytes, err := stablejson.Marshal(singleOutput)
	if err != nil {
		t.Fatalf("stablejson single: %v", err)
	}
	multiBytes, err := stablejson.Marshal(multiOutput)
	if err != nil {
		t.Fatalf("stablejson multi: %v", err)
	}
	if !bytes.Equal(singleBytes, multiBytes) {
		t.Fatalf("multi-source output drifted from equivalent single-source output:\nsingle=%s\nmulti=%s", singleBytes, multiBytes)
	}
}

func TestBuildRejectsDuplicateRequirementIDsAcrossSources(t *testing.T) {
	input := validComposeInput(t)
	currentSources := input["currentRequirementSources"].([]any)
	input["currentRequirementSources"] = append(currentSources, cloneAny(t, currentSources[0]))

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "duplicate requirementId across currentRequirementSources: REQ-PROOFKIT-IMPACT-001") {
		t.Fatalf("Build() error = %v, want duplicate current requirement rejection", err)
	}
}

func TestBuildRejectsFailedChangedPathAdmission(t *testing.T) {
	input := validComposeInput(t)
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"../outside"}}}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "requires passed changed-path source admission") {
		t.Fatalf("Build() error = %v, want failed changed-path admission", err)
	}
}

func TestBuildRejectsAmbiguousCurrentBindingRequirementOwnership(t *testing.T) {
	input := validComposeInput(t)
	currentContract := input["currentCompactProofContract"].(map[string]any)
	bindings := currentContract["bindings"].([]any)
	duplicate := cloneAny(t, bindings[0]).([]any)
	duplicate[2] = "proofkit.impact.surface::scenario_duplicate"
	bindings = append(bindings, duplicate)
	currentContract["bindings"] = bindings

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "multiple bindings for requirementId: REQ-PROOFKIT-IMPACT-001") {
		t.Fatalf("Build() error = %v, want duplicate current requirement binding rejection", err)
	}
}

func TestBuildFailsClosedWhenProofBindingPayloadChangesWithoutSourcePath(t *testing.T) {
	input := validComposeInput(t)
	currentContract := input["currentCompactProofContract"].(map[string]any)
	binding := currentContract["bindings"].([]any)[0].([]any)
	binding[10] = []any{"go test ./internal/command/impact"}

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(composed) error = %v", err)
	}
	if reportExit == 0 {
		t.Fatalf("impact report unexpectedly passed: %#v", report)
	}
	assertContainsFailure(t, report, "proof binding payload changed without changed proof-binding source path evidence")

	input = validComposeInput(t)
	currentContract = input["currentCompactProofContract"].(map[string]any)
	binding = currentContract["bindings"].([]any)[0].([]any)
	binding[10] = []any{"go test ./internal/command/impact"}
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"docs/contracts/proofkit-impact.json"}}}

	output, _, err = Build(input)
	if err != nil {
		t.Fatalf("Build() with proof source path error = %v", err)
	}
	assertStringArray(t, output["changedBindingRecordIds"], []string{"REQ-PROOFKIT-IMPACT-001"})
}

func TestBuildDerivesWitnessCoverageAndProofLikeFailures(t *testing.T) {
	input := validComposeInput(t)
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"internal/command/requirementimpactinput/shared_test.go"}}}

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() witness coverage error = %v", err)
	}
	coverage := output["changedWitnessPathCoverage"].([]any)
	if len(coverage) != 1 {
		t.Fatalf("changedWitnessPathCoverage = %#v, want one shared path", coverage)
	}
	assertStringArray(t, coverage[0].(map[string]any)["recordIds"], []string{"REQ-PROOFKIT-IMPACT-001", "REQ-PROOFKIT-IMPACT-002"})
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(witness coverage) error = %v", err)
	}
	if reportExit != 0 {
		t.Fatalf("impact report = %#v exit = %d, want witness coverage to parent proof path", report, reportExit)
	}

	input = validComposeInput(t)
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"internal/command/requirementimpactinput/unbound_test.go"}}}
	output, _, err = Build(input)
	if err != nil {
		t.Fatalf("Build() proof-like path error = %v", err)
	}
	report, reportExit, err = impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(proof-like path) error = %v", err)
	}
	if reportExit == 0 {
		t.Fatalf("impact report unexpectedly passed: %#v", report)
	}
	assertContainsFailure(t, report, "proof changes without parent record need a rationale")

	input["unboundProofChangeRationale"] = "Caller-owned impact review accepts this proof-only fixture edit."
	output, _, err = Build(input)
	if err != nil {
		t.Fatalf("Build() proof-like path with rationale error = %v", err)
	}
	report, reportExit, err = impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(proof-like path with rationale) error = %v", err)
	}
	if reportExit != 0 {
		t.Fatalf("impact report = %#v exit = %d, want rationale to satisfy unbound proof change", report, reportExit)
	}

	input = validComposeInput(t)
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"internal/command/requirementimpactinput/unbound_test.go"}}}
	input["proofLikePathPolicy"] = map[string]any{
		"ignoredProofLikePaths": []any{"internal/command/requirementimpactinput/unbound_test.go"},
		"nonClaims":             []any{"Requirement impact input composition treats proof-like paths as policy hints, not proof evidence."},
		"proofLikePathPatterns": []any{"internal/command/requirementimpactinput/**"},
	}
	output, _, err = Build(input)
	if err != nil {
		t.Fatalf("Build() ignored proof-like path error = %v", err)
	}
	report, reportExit, err = impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(ignored proof-like path) error = %v", err)
	}
	if reportExit != 0 {
		t.Fatalf("ignored proof-like path report = %#v exit = %d, want pass", report, reportExit)
	}
}

func TestBuildProjectsGeneratedArtifactPolicyFailures(t *testing.T) {
	input := validComposeInput(t)
	input["generatedArtifactPolicyState"] = map[string]any{
		"source":                  "generated_artifact_verifier",
		"state":                   "incomplete",
		"uncoveredGeneratedPaths": []any{"docs/generated/report.md"},
	}

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(generated policy) error = %v", err)
	}
	if reportExit == 0 {
		t.Fatalf("impact report unexpectedly passed: %#v", report)
	}
	assertContainsFailure(t, report, "generated artifact policy is not complete: incomplete")
	assertContainsFailure(t, report, "uncovered generated artifact path: docs/generated/report.md")
}

func TestBuildPreservesGeneratedMirrorRulesForDownstreamImpact(t *testing.T) {
	input := validComposeInput(t)
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"docs/generated/report.md"}}}

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() generated mirror error = %v", err)
	}
	report, reportExit, err := impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(generated mirror) error = %v", err)
	}
	if reportExit == 0 {
		t.Fatalf("generated mirror report unexpectedly passed: %#v", report)
	}
	assertContainsFailure(t, report, "changed generated mirror without source change: docs/generated/report.md")

	input = validComposeInput(t)
	input["changedPathSources"] = []any{map[string]any{"sourceId": "git_diff", "paths": []any{"docs/generated/report.md", "docs/specs/proofkit-impact/requirements.v1.json"}}}
	output, _, err = Build(input)
	if err != nil {
		t.Fatalf("Build() generated mirror with source error = %v", err)
	}
	report, reportExit, err = impact.Build(output)
	if err != nil {
		t.Fatalf("impact.Build(generated mirror with source) error = %v", err)
	}
	if reportExit != 0 {
		t.Fatalf("generated mirror with source report = %#v exit = %d, want pass", report, reportExit)
	}
}

func TestBuildOutputIsDeterministicForEquivalentAdmittedInputs(t *testing.T) {
	first := validComposeInput(t)
	first["changedPathSources"] = []any{
		map[string]any{"sourceId": "source_a", "paths": []any{"docs/specs/proofkit-impact/requirements.v1.json"}},
		map[string]any{"sourceId": "source_b", "paths": []any{"internal/command/requirementimpactinput/shared_test.go"}},
	}
	second := cloneAny(t, first).(map[string]any)
	secondSources := second["changedPathSources"].([]any)
	second["changedPathSources"] = []any{secondSources[1], secondSources[0]}
	for _, key := range []string{"baseCompactProofContract", "currentCompactProofContract"} {
		contract := second[key].(map[string]any)
		bindings := contract["bindings"].([]any)
		contract["bindings"] = []any{bindings[1], bindings[0]}
	}

	firstOutput, _, err := Build(first)
	if err != nil {
		t.Fatalf("Build(first) error = %v", err)
	}
	secondOutput, _, err := Build(second)
	if err != nil {
		t.Fatalf("Build(second) error = %v", err)
	}
	firstBytes, err := stablejson.Marshal(firstOutput)
	if err != nil {
		t.Fatalf("stablejson first: %v", err)
	}
	secondBytes, err := stablejson.Marshal(secondOutput)
	if err != nil {
		t.Fatalf("stablejson second: %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("Build() output is not deterministic:\nfirst=%s\nsecond=%s", firstBytes, secondBytes)
	}
}

func TestBuildMarksObligationPreconditionedFromLocalEnvironmentPolicy(t *testing.T) {
	input := validComposeInput(t)
	currentSource := input["currentRequirementSources"].([]any)[0].(map[string]any)
	currentSource["requirements"].([]any)[0].(map[string]any)["invariant"] = "Requirement impact input composition marks obligations preconditioned when local environment classes do not satisfy required classes."
	input["localEnvironmentPolicy"] = map[string]any{"localEnvironmentClasses": []any{}}

	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	obligations := output["obligationCatalog"].([]any)
	if len(obligations) != 1 || obligations[0].(map[string]any)["preconditioned"] != true {
		t.Fatalf("obligationCatalog = %#v, want preconditioned obligation", obligations)
	}
}

func validComposeInput(t *testing.T) map[string]any {
	t.Helper()
	source := requirementSource([]any{
		requirement("REQ-PROOFKIT-IMPACT-001", "Requirement impact input composition must route active blocking requirement deltas through explicit proof obligations.", "blocking"),
		requirement("REQ-PROOFKIT-IMPACT-002", "Requirement impact input composition must parent changed witness paths to every referenced requirement.", "blocking"),
		requirement("REQ-PROOFKIT-IMPACT-003", "Requirement impact input composition may preserve advisory context without creating merge obligations.", "advisory"),
	})
	contract := compactContract()
	return map[string]any{
		"schemaVersion":                json.Number("1"),
		"composerInputId":              "proofkit.impact_input.fixture",
		"baseRef":                      "main",
		"baseCommit":                   "base-sha",
		"headRef":                      "feature/impact-input",
		"headCommit":                   nil,
		"changedPathSources":           []any{map[string]any{"sourceId": "git_diff", "paths": []any{"docs/specs/proofkit-impact/requirements.v1.json"}}},
		"baseRequirementSources":       []any{cloneAny(t, source)},
		"currentRequirementSources":    []any{cloneAny(t, source)},
		"baseCompactProofContract":     cloneAny(t, contract),
		"currentCompactProofContract":  cloneAny(t, contract),
		"proofBindingSourcePaths":      []any{"docs/contracts/proofkit-impact.json"},
		"localEnvironmentPolicy":       map[string]any{"localEnvironmentClasses": []any{"local-go"}},
		"proofLikePathPolicy":          map[string]any{"ignoredProofLikePaths": []any{}, "nonClaims": []any{"Requirement impact input composition treats proof-like paths as policy hints, not proof evidence."}, "proofLikePathPatterns": []any{"internal/command/requirementimpactinput/**"}},
		"generatedArtifactPolicyState": map[string]any{"source": "generated_artifact_verifier", "state": "complete", "uncoveredGeneratedPaths": []any{}},
		"generatedArtifactRules":       []any{map[string]any{"generatedPath": "docs/generated/report.md", "sourcePathPatterns": []any{"docs/specs/proofkit-impact/**"}}},
		"preexistingFailures":          []any{},
		"nonClaims":                    []any{"Requirement impact input composition is caller-owned route input and does not execute native witnesses."},
	}
}

func requirementSource(requirements []any) map[string]any {
	return map[string]any{
		"schemaVersion":    json.Number("1"),
		"sourceId":         "proofkit.impact.source",
		"specPackagePath":  "docs/specs/proofkit-impact",
		"overviewPath":     "docs/specs/proofkit-impact/overview.md",
		"requirementsPath": "docs/specs/proofkit-impact/requirements.v1.json",
		"requirements":     requirements,
		"nonClaims":        []any{"Impact fixture source records do not own product semantics."},
	}
}

func setSourceIdentity(source map[string]any, sourceID string, specPackagePath string) {
	source["sourceId"] = sourceID
	source["specPackagePath"] = specPackagePath
	source["overviewPath"] = specPackagePath + "/overview.md"
	source["requirementsPath"] = specPackagePath + "/requirements.v1.json"
}

func requirement(id string, invariant string, claimLevel string) map[string]any {
	proofRefs := []any{}
	if claimLevel == "blocking" {
		proofRefs = []any{"docs/contracts/proofkit-impact.json"}
	}
	return map[string]any{
		"requirementId":    id,
		"ownerId":          "proofkit.impact_input",
		"invariant":        invariant,
		"claimLevel":       claimLevel,
		"riskClass":        "medium",
		"proofBindingRefs": proofRefs,
		"nonClaimRefs":     []any{},
		"nonClaims":        []any{},
		"lifecycle":        map[string]any{"state": "active", "evidenceRefs": []any{}, "replacementRequirementIds": []any{}},
		"deferral":         nil,
		"updatePolicy":     map[string]any{"requiresImpactDeclaration": true, "requiresProofBindingReview": claimLevel == "blocking", "reviewOwnerId": "proofkit.impact_input"},
	}
}

func compactContract() map[string]any {
	return map[string]any{
		"schema_version":        json.Number("1"),
		"authority_state":       compactproofcontract.AuthorityState,
		"contract_kind":         compactproofcontract.ContractKind,
		"contract_id":           "proofkit.impact.contract",
		"normalization_profile": compactproofcontract.NormalizationProfile,
		"non_claims":            []any{"Impact fixture compact proof contract does not execute witnesses."},
		"surface_columns":       stringsToAny(compactproofcontract.SurfaceColumns),
		"binding_columns":       stringsToAny(compactproofcontract.BindingColumns),
		"witness_columns":       stringsToAny(compactproofcontract.WitnessColumns),
		"surfaces":              []any{[]any{"proofkit.impact.surface", []any{"local-go"}, []any{}}},
		"bindings": []any{
			binding("REQ-PROOFKIT-IMPACT-001", "proofkit.impact.surface::scenario_one", "proofkit.impact_one", "internal/command/requirementimpactinput/shared_test.go::positive_one", "internal/command/requirementimpactinput/negative_test.go::negative_one"),
			binding("REQ-PROOFKIT-IMPACT-002", "proofkit.impact.surface::scenario_two", "proofkit.impact_two", "internal/command/requirementimpactinput/shared_test.go::positive_two", "internal/command/requirementimpactinput/shared_test.go::negative_two"),
		},
	}
}

func binding(requirementID string, scenarioID string, ownedInvariant string, positiveSelector string, negativeSelector string) []any {
	return []any{
		requirementID,
		"proofkit.impact.surface",
		scenarioID,
		"contract",
		ownedInvariant,
		"witness_backed",
		"blocking",
		[]any{"local-go"},
		witness(positiveSelector, 0),
		witness(negativeSelector, 1),
		[]any{"go test ./internal/command/requirementimpactinput"},
		"no_known_advisory_gap",
	}
}

func witness(selector string, order int) []any {
	return []any{
		selector,
		[]any{"local-go"},
		[]any{"go test ./internal/command/requirementimpactinput"},
		json.Number(strconv.Itoa(order)),
	}
}

func cloneAny(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return decoded
}

func assertStringArray(t *testing.T, raw any, expected []string) {
	t.Helper()
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("value = %#v, want []any", raw)
	}
	if len(values) != len(expected) {
		t.Fatalf("values = %#v, want %#v", values, expected)
	}
	for index, want := range expected {
		got, ok := values[index].(string)
		if !ok || got != want {
			t.Fatalf("values = %#v, want %#v", values, expected)
		}
	}
}

func assertContainsFailure(t *testing.T, report map[string]any, expected string) {
	t.Helper()
	for _, raw := range report["failures"].([]any) {
		if strings.Contains(raw.(string), expected) {
			return
		}
	}
	t.Fatalf("failures = %#v, want substring %q", report["failures"], expected)
}

func assertObligationHasReason(t *testing.T, report map[string]any, recordID string, reason string) {
	t.Helper()
	for _, raw := range report["obligations"].([]any) {
		obligation := raw.(map[string]any)
		if obligation["recordId"] != recordID {
			continue
		}
		for _, rawReason := range obligation["changeReasons"].([]any) {
			if rawReason == reason {
				return
			}
		}
		t.Fatalf("obligation for %s lacks reason %s: %#v", recordID, reason, obligation)
	}
	t.Fatalf("report lacks obligation for %s: %#v", recordID, report["obligations"])
}
