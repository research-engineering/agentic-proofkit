package requirementauthoringplan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildComposesCandidateSourceAcceptedByAdmissionAndTransition(t *testing.T) {
	output, exitCode, err := Build(validInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || output["state"] != "passed" {
		t.Fatalf("Build() exit=%d state=%v output=%#v", exitCode, output["state"], output)
	}
	if output["schemaVersion"] != 2 {
		t.Fatalf("Build() schemaVersion=%#v, want versioned output schema 2", output["schemaVersion"])
	}
	preview, ok := output["nonAuthoritativeAdmissionPreview"].(map[string]any)
	if !ok {
		t.Fatalf("passed authoring plan must expose wrapped candidate-only preview: %#v", output["nonAuthoritativeAdmissionPreview"])
	}
	if preview["authority"] != "candidate_only" || preview["ownerReviewRequired"] != true || preview["candidateOnly"] != true {
		t.Fatalf("preview lost candidate-only metadata: %#v", preview)
	}
	expectedResult, err := requirementsourceadmission.Evaluate(expectedNextSource())
	if err != nil || expectedResult.ExitCode != 0 {
		t.Fatalf("admit expected next source: exit=%d err=%v", expectedResult.ExitCode, err)
	}
	assertStableJSONEqual(t, "candidate source preview", requirementsourceadmission.SourceValue(expectedResult.Source), preview["requirementSourcePreview"])
	assertOutputContains(t, output, "Requirement authoring plans do not infer requirement meaning")
	assertOutputContains(t, output, "proofkit.requirement-authoring-plan.review-candidates")
	assertOutputContains(t, output, "run_admitted_validation")
	refs, ok := output["authoringRefs"].([]any)
	if !ok || len(refs) != 2 {
		t.Fatalf("authoring refs were not projected: %#v", output["authoringRefs"])
	}
	assertStableJSONEqual(t, "authoring ref projection", validInput()["authoringRefs"], refs)
}

func TestBuildPreservesDigestBoundAuthoringRefIdentity(t *testing.T) {
	first := validInput()
	second := validInput()
	secondRef := second["authoringRefs"].([]any)[0].(map[string]any)
	secondRef["digest"] = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	secondRef["summary"] = "The revised design proposes the same candidate from different source bytes."

	firstOutput, firstExit, firstErr := Build(first)
	secondOutput, secondExit, secondErr := Build(second)
	if firstErr != nil || secondErr != nil || firstExit != 0 || secondExit != 0 {
		t.Fatalf("Build() first=(%d,%v) second=(%d,%v)", firstExit, firstErr, secondExit, secondErr)
	}
	assertStableJSONEqual(t, "first complete authoring ref projection", first["authoringRefs"], firstOutput["authoringRefs"])
	assertStableJSONEqual(t, "second complete authoring ref projection", second["authoringRefs"], secondOutput["authoringRefs"])
	firstRefs, err := stablejson.Marshal(firstOutput["authoringRefs"])
	if err != nil {
		t.Fatalf("marshal first authoring refs: %v", err)
	}
	secondRefs, err := stablejson.Marshal(secondOutput["authoringRefs"])
	if err != nil {
		t.Fatalf("marshal second authoring refs: %v", err)
	}
	if string(firstRefs) == string(secondRefs) {
		t.Fatal("digest- and summary-distinct authoring refs projected identically")
	}
}

func TestAdmitInputUsesCanonicalRequirementSourceProjection(t *testing.T) {
	raw := validInput()
	admitted, err := admitInput(raw)
	if err != nil {
		t.Fatalf("admitInput() error = %v", err)
	}
	assertStableJSONEqual(t, "canonical current requirement source", requirementsourceadmission.SourceValue(admitted.CurrentRequirementState), admitted.CurrentRequirementValue)
	raw["currentRequirementSource"].(map[string]any)["sourceId"] = "proofkit.test.mutated"
	if admitted.CurrentRequirementValue["sourceId"] == "proofkit.test.mutated" {
		t.Fatal("admitted current requirement source retained caller alias")
	}
}

func TestBuildRejectsInvalidCurrentRequirementSourceBeforeComposition(t *testing.T) {
	input := validInput()
	current := input["currentRequirementSource"].(map[string]any)
	current["overviewPath"] = "docs/specs/proofkit-authoring-test/not-overview.md"

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "currentRequirementSource must pass requirement-source-admission") {
		t.Fatalf("Build() error=%v, want invalid current source failure", err)
	}
}

func TestBuildRejectsCandidateMissingRequiredAuthoringFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "empty source refs",
			mutate: func(input map[string]any) {
				firstUpdate(input)["sourceRefIds"] = []any{}
			},
			want: "sourceRefIds must be non-empty",
		},
		{
			name: "unknown source refs",
			mutate: func(input map[string]any) {
				firstUpdate(input)["sourceRefIds"] = []any{"proofkit.test.unknown-ref"}
			},
			want: "unknown authoring ref",
		},
		{
			name: "empty owner questions",
			mutate: func(input map[string]any) {
				firstUpdate(input)["ownerQuestions"] = []any{}
			},
			want: "ownerQuestions must be non-empty",
		},
		{
			name: "empty declared obligations",
			mutate: func(input map[string]any) {
				firstUpdate(input)["declaredProofObligations"] = []any{}
			},
			want: "proofObligations must be a non-empty array",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validInput()
			item.mutate(input)
			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildRejectsCandidateSourceAdmissionFailure(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.083389748775835400553445979904052979137934295186556847066581462858159571590041")
	input := validInput()
	candidate := firstUpdate(input)["candidateRequirement"].(map[string]any)
	candidate["proofBindingRefs"] = []any{}

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || output["state"] != "failed" || output["nonAuthoritativeAdmissionPreview"] != nil {
		t.Fatalf("Build() accepted invalid candidate source: exit=%d output=%#v", exitCode, output)
	}
	assertOutputContains(t, output, "candidate next source must pass requirement-source-admission")
}

func TestBuildRejectsSecretShapedCandidateBeforeCompositionWithoutEcho(t *testing.T) {
	input := validInput()
	sentinel := "sk-proj-aaaaaaaaaaa"
	candidate := firstUpdate(input)["candidateRequirement"].(map[string]any)
	candidate["invariant"] = "Sentinel " + sentinel + " must be rejected without echo."

	output, exitCode, err := Build(input)
	if err == nil || output != nil || exitCode != 1 {
		t.Fatalf("Build() accepted secret-shaped candidate: exit=%d output=%#v", exitCode, output)
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("admission error leaked secret-shaped candidate payload: %s", err)
	}
}

func TestBuildRejectsLifecycleTransitionWithoutNewEvidence(t *testing.T) {
	input := validInput()
	update := firstUpdate(input)
	update["operation"] = "deprecate"
	update["requirementId"] = "REQ-PROOFKIT-AUTHORING-000"
	update["candidateRequirement"] = deprecatedExistingRequirement([]any{})

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || output["state"] != "failed" {
		t.Fatalf("Build() accepted lifecycle transition without evidence: exit=%d output=%#v", exitCode, output)
	}
	if output["nonAuthoritativeAdmissionPreview"] != nil {
		t.Fatalf("failed transition must not expose candidate source preview: %#v", output["nonAuthoritativeAdmissionPreview"])
	}
	assertOutputContains(t, output, "candidate transition must pass requirement-source-transition")
}

func TestBuildRejectsOperationTargetDrift(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "add existing",
			mutate: func(input map[string]any) {
				firstUpdate(input)["operation"] = "add"
				firstUpdate(input)["requirementId"] = "REQ-PROOFKIT-AUTHORING-000"
				firstUpdate(input)["candidateRequirement"] = activeExistingRequirement()
			},
			want: "add candidate must target a new requirement id",
		},
		{
			name: "modify missing",
			mutate: func(input map[string]any) {
				firstUpdate(input)["operation"] = "modify"
			},
			want: "modify candidate must target an existing requirement id",
		},
		{
			name: "modify wrong lifecycle",
			mutate: func(input map[string]any) {
				firstUpdate(input)["operation"] = "modify"
				firstUpdate(input)["requirementId"] = "REQ-PROOFKIT-AUTHORING-000"
				firstUpdate(input)["candidateRequirement"] = deprecatedExistingRequirement([]any{"docs/evidence/authoring.md"})
			},
			want: "modify candidate must keep active lifecycle",
		},
		{
			name: "deprecate missing",
			mutate: func(input map[string]any) {
				firstUpdate(input)["operation"] = "deprecate"
				firstUpdate(input)["candidateRequirement"] = deprecatedCandidateRequirement([]any{"docs/evidence/authoring.md"})
			},
			want: "deprecate candidate must target an existing requirement id",
		},
		{
			name: "deprecate wrong lifecycle",
			mutate: func(input map[string]any) {
				firstUpdate(input)["operation"] = "deprecate"
				firstUpdate(input)["requirementId"] = "REQ-PROOFKIT-AUTHORING-000"
				firstUpdate(input)["candidateRequirement"] = activeExistingRequirement()
			},
			want: "deprecate candidate must set deprecated lifecycle",
		},
		{
			name: "supersede missing",
			mutate: func(input map[string]any) {
				firstUpdate(input)["operation"] = "supersede"
				candidate := candidateRequirement()
				candidate["claimLevel"] = "advisory"
				candidate["lifecycle"].(map[string]any)["state"] = "superseded"
				candidate["lifecycle"].(map[string]any)["evidenceRefs"] = []any{"docs/evidence/authoring.md"}
				candidate["lifecycle"].(map[string]any)["replacementRequirementIds"] = []any{"REQ-PROOFKIT-AUTHORING-000"}
				firstUpdate(input)["candidateRequirement"] = candidate
			},
			want: "supersede candidate must target an existing requirement id",
		},
		{
			name: "supersede wrong lifecycle",
			mutate: func(input map[string]any) {
				firstUpdate(input)["operation"] = "supersede"
				firstUpdate(input)["requirementId"] = "REQ-PROOFKIT-AUTHORING-000"
				firstUpdate(input)["candidateRequirement"] = activeExistingRequirement()
			},
			want: "supersede candidate must set superseded lifecycle",
		},
		{
			name: "add wrong lifecycle",
			mutate: func(input map[string]any) {
				firstUpdate(input)["candidateRequirement"] = deprecatedCandidateRequirement([]any{"docs/evidence/authoring.md"})
			},
			want: "add candidate must start active",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validInput()
			item.mutate(input)
			output, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if exitCode == 0 || output["state"] != "failed" {
				t.Fatalf("Build() accepted operation drift: exit=%d output=%#v", exitCode, output)
			}
			if output["nonAuthoritativeAdmissionPreview"] != nil {
				t.Fatalf("composition failure must not expose candidate source preview: %#v", output["nonAuthoritativeAdmissionPreview"])
			}
			assertOutputContains(t, output, item.want)
		})
	}
}

func TestBuildRejectsDuplicateCandidateIDsAndTargetRequirementIDs(t *testing.T) {
	input := validInput()
	input["candidateUpdates"] = append(input["candidateUpdates"].([]any), firstUpdate(input))
	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "candidate ids must be sorted and unique") {
		t.Fatalf("Build() error=%v, want duplicate candidate id failure", err)
	}

	input = validInput()
	duplicate := cloneMap(firstUpdate(input))
	duplicate["candidateId"] = "proofkit.test.authoring-candidate-b"
	input["candidateUpdates"] = []any{firstUpdate(input), duplicate}
	_, _, err = Build(input)
	if err == nil || !strings.Contains(err.Error(), "candidate requirement ids must be sorted and unique") {
		t.Fatalf("Build() error=%v, want duplicate requirement id failure", err)
	}
}

func TestBuildDoesNotReadAuthoringRefPaths(t *testing.T) {
	input := validInput()
	ref := input["authoringRefs"].([]any)[0].(map[string]any)
	ref["path"] = "docs/designs/this-file-does-not-exist.md"

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || output["state"] != "passed" {
		t.Fatalf("nonexistent authoring ref path should be label-only: exit=%d output=%#v", exitCode, output)
	}
}

func TestBuildRejectsUnsafeAuthoringRefPathAndMalformedDigest(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		digest any
		want   string
	}{
		{name: "parent path", path: "../design.md", digest: validDigest(), want: "must not escape the repository root"},
		{name: "absolute path", path: "/tmp/design.md", digest: validDigest(), want: "must be a repository-relative POSIX path"},
		{name: "git metadata", path: ".git/config", digest: validDigest(), want: "must not target repository metadata"},
		{name: "bad digest", path: "docs/designs/test-feature.md", digest: "sha256:not-hex", want: "must be sha256"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validInput()
			ref := input["authoringRefs"].([]any)[0].(map[string]any)
			ref["path"] = item.path
			ref["digest"] = item.digest
			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func validInput() map[string]any {
	return map[string]any{
		"schemaVersion":            json.Number("1"),
		"authoringPlanId":          "proofkit.test.requirement-authoring-plan",
		"mode":                     "pull_request_design",
		"currentRequirementSource": currentRequirementSource(),
		"authoringRefs": []any{
			map[string]any{
				"refId":     "proofkit.test.design-doc",
				"kind":      "design_doc",
				"path":      "docs/designs/test-feature.md",
				"digest":    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"summary":   "The design proposes a durable authoring invariant.",
				"nonClaims": []any{"This ref does not prove implementation correctness."},
			},
			map[string]any{
				"refId":     "proofkit.test.test-summary",
				"kind":      "test_summary",
				"path":      "artifacts/test-summary.json",
				"digest":    nil,
				"summary":   "The test summary identifies candidate validation context.",
				"nonClaims": []any{"This ref does not prove witness execution."},
			},
		},
		"candidateUpdates": []any{
			map[string]any{
				"candidateId":   "proofkit.test.authoring-candidate",
				"operation":     "add",
				"requirementId": "REQ-PROOFKIT-AUTHORING-001",
				"sourceRefIds":  []any{"proofkit.test.design-doc"},
				"rationale":     "The design introduced a durable invariant that needs proof routing.",
				"ownerQuestions": []any{
					"Should this candidate become stable repository truth?",
				},
				"declaredProofObligations": []any{
					map[string]any{
						"obligationId": "proofkit.test.authoring-proof-binding",
						"kind":         "proof_binding",
						"ownerId":      "proofkit.test",
						"description":  "Bind the candidate requirement to a semantic falsifier before merge.",
						"blocking":     true,
						"evidenceRefs": []any{"proofkit/requirement-bindings.json"},
					},
				},
				"candidateRequirement": candidateRequirement(),
			},
		},
		"nonClaims": []any{"Caller non-claim keeps this fixture advisory."},
	}
}

func currentRequirementSource() map[string]any {
	return map[string]any{
		"schemaVersion":    json.Number("1"),
		"sourceId":         "proofkit.test.authoring.requirements",
		"specPackagePath":  "docs/specs/proofkit-authoring-test",
		"overviewPath":     "docs/specs/proofkit-authoring-test/overview.md",
		"requirementsPath": "docs/specs/proofkit-authoring-test/requirements.v1.json",
		"nonClaims":        []any{"Current authoring fixture source is test-only."},
		"requirements": []any{
			activeExistingRequirement(),
		},
	}
}

func activeExistingRequirement() map[string]any {
	return map[string]any{
		"requirementId": "REQ-PROOFKIT-AUTHORING-000",
		"ownerId":       "proofkit.test",
		"invariant":     "Existing authoring fixture requirement must remain admissible.",
		"claimLevel":    "blocking",
		"riskClass":     "medium",
		"proofBindingRefs": []any{
			"proofkit/requirement-bindings.json",
		},
		"nonClaimRefs": []any{},
		"nonClaims":    []any{"This fixture requirement does not execute witnesses."},
		"lifecycle": map[string]any{
			"state":                     "active",
			"replacementRequirementIds": []any{},
			"evidenceRefs":              []any{},
		},
		"deferral": nil,
		"updatePolicy": map[string]any{
			"reviewOwnerId":              "proofkit.test",
			"requiresImpactDeclaration":  true,
			"requiresProofBindingReview": true,
		},
	}
}

func deprecatedExistingRequirement(evidenceRefs []any) map[string]any {
	requirement := activeExistingRequirement()
	requirement["claimLevel"] = "advisory"
	requirement["lifecycle"].(map[string]any)["state"] = "deprecated"
	requirement["lifecycle"].(map[string]any)["evidenceRefs"] = evidenceRefs
	return requirement
}

func deprecatedCandidateRequirement(evidenceRefs []any) map[string]any {
	requirement := candidateRequirement()
	requirement["claimLevel"] = "advisory"
	requirement["lifecycle"].(map[string]any)["state"] = "deprecated"
	requirement["lifecycle"].(map[string]any)["evidenceRefs"] = evidenceRefs
	return requirement
}

func candidateRequirement() map[string]any {
	return map[string]any{
		"requirementId": "REQ-PROOFKIT-AUTHORING-001",
		"ownerId":       "proofkit.test",
		"invariant":     "Requirement authoring plans must keep candidate records advisory until owner materialization.",
		"claimLevel":    "blocking",
		"riskClass":     "high",
		"proofBindingRefs": []any{
			"proofkit/requirement-bindings.json",
		},
		"nonClaimRefs": []any{},
		"nonClaims":    []any{"This candidate does not approve file materialization."},
		"lifecycle": map[string]any{
			"state":                     "active",
			"replacementRequirementIds": []any{},
			"evidenceRefs":              []any{},
		},
		"deferral": nil,
		"updatePolicy": map[string]any{
			"reviewOwnerId":              "proofkit.test",
			"requiresImpactDeclaration":  true,
			"requiresProofBindingReview": true,
		},
	}
}

func expectedNextSource() map[string]any {
	source := currentRequirementSource()
	source["requirements"] = []any{
		activeExistingRequirement(),
		candidateRequirement(),
	}
	return source
}

func firstUpdate(input map[string]any) map[string]any {
	return input["candidateUpdates"].([]any)[0].(map[string]any)
}

func validDigest() string {
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func cloneMap(value map[string]any) map[string]any {
	out := map[string]any{}
	for key, item := range value {
		out[key] = item
	}
	return out
}

func assertStableJSONEqual(t *testing.T, label string, want any, got any) {
	t.Helper()
	wantJSON, err := stablejson.Marshal(want)
	if err != nil {
		t.Fatalf("marshal expected %s: %v", label, err)
	}
	gotJSON, err := stablejson.Marshal(got)
	if err != nil {
		t.Fatalf("marshal actual %s: %v", label, err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("%s drifted\nwant=%s\ngot =%s", label, wantJSON, gotJSON)
	}
}

func assertOutputContains(t *testing.T, output map[string]any, want string) {
	t.Helper()
	encoded, _ := json.Marshal(output)
	if !strings.Contains(string(encoded), want) {
		t.Fatalf("output missing %q: %s", want, encoded)
	}
}
