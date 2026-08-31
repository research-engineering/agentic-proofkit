package changeworkflowplan

import (
	"strings"
	"testing"
)

var expectedWorkflowActionProfiles = map[string]actionProfile{
	"author": {
		CandidateAction:        "Author only the active-stage artifact under the consuming repository's semantic owner and bind the result to a caller-owned artifact reference and digest.",
		ExpectedNextCheckpoint: "ready_for_review",
		StopCondition:          "Stop after the artifact and digest are ready for independent review.",
	},
	"implement": {
		CandidateAction:        "Implement only the accepted owner-scoped plan, preserving its non-claims and adding its native positive and negative proof paths.",
		ExpectedNextCheckpoint: "ready_for_review",
		StopCondition:          "Stop after the implementation artifact and digest are ready for independent review.",
	},
	"verify": {
		CandidateAction:        "Run the consuming repository's positive controls and independent near-miss falsifiers against the exact caller-declared subject.",
		ExpectedNextCheckpoint: "ready_for_review",
		StopCondition:          "Stop after bounded verification evidence and its subject digest are ready for independent review.",
	},
	"open_pull_request": {
		CandidateAction:        "Open a pull request only under consuming-repository policy for the exact reviewed head and expose its native checks without claiming merge authority.",
		ExpectedNextCheckpoint: "ready_for_review",
		StopCondition:          "Stop after the pull-request artifact and exact head digest are ready for independent review.",
	},
	"closeout": {
		CandidateAction:        "Assemble bounded closeout evidence for the exact reviewed subject without merging, releasing, rolling out, or declaring production readiness.",
		ExpectedNextCheckpoint: "ready_for_review",
		StopCondition:          "Stop after the closeout artifact and digest are ready for independent review.",
	},
	"review": {
		CandidateAction:        "Independently attempt to falsify the active-stage artifact under its declared owner, bounds, non-claims, and exact subject digest.",
		ExpectedNextCheckpoint: "review_findings_or_review_passed",
		StopCondition:          "Stop with review_findings bound to every admitted finding, or review_passed bound to the unchanged assessed subject digest.",
	},
	"repair": {
		CandidateAction:        "Repair every referenced finding under the same semantic owner, produce a new subject digest, and do not emit a pass claim.",
		ExpectedNextCheckpoint: "ready_for_review",
		StopCondition:          "Stop when the repaired artifact and new digest are ready for another independent review.",
	},
	"accept_stage": {
		CandidateAction:        "Apply only the reported successorStateDelta to the prior snapshot, preserve all context fields byte-for-byte, and submit the merged snapshot for ordinary admission.",
		ExpectedNextCheckpoint: "successor_state_delta",
		StopCondition:          "Stop after constructing the merged immutable snapshot; do not infer execution, approval, merge, or release from stage acceptance.",
	},
}

func TestWorkflowPromptPredicates(t *testing.T) {
	t.Run("caller_not_styled", func(t *testing.T) {
		input := initialInput()
		input["contextRefs"] = []any{contextValue("ctx.value", "artifact", testDigest, nil)}
		input["requiredContextRefIds"] = []any{"ctx.value"}
		result, err := Project(input)
		if err != nil {
			t.Fatal(err)
		}
		if containsANSI(canonical(t, result.Plan)) || containsANSI(result.Text) || containsANSI(canonical(t, result.AgentEnvelope)) {
			t.Fatal("caller projection contains ANSI styling")
		}
	})
	t.Run("candidate_action", func(t *testing.T) {
		for index := range workflowCatalog.Stages {
			for _, state := range []string{"not_started", "ready_for_review", "review_findings", "review_passed"} {
				plan := requireBuild(t, inputForStage(index, state))
				prompt := plan["prompt"].(map[string]any)
				if len(prompt) != 9 {
					t.Fatalf("prompt has %d fields", len(prompt))
				}
				profile, exists := expectedWorkflowActionProfiles[plan["action"].(string)]
				if !exists || prompt["candidateAction"] != profile.CandidateAction || prompt["expectedNextCheckpoint"] != profile.ExpectedNextCheckpoint {
					t.Fatal("candidate action drifted from action owner")
				}
			}
		}
	})
	t.Run("coordinates", func(t *testing.T) {
		plan := requireBuild(t, reviewInput("review_findings"))
		coordinates := plan["prompt"].(map[string]any)["coordinates"].(map[string]any)
		want := []string{"activeStageId", "checkpointState", "findingRefs", "governingAuthorityRefId", "retainedArtifactPaths", "retainedContextRefIds", "subjectDigest", "subjectRefId"}
		got := make([]string, 0, len(coordinates))
		for _, key := range want {
			if _, exists := coordinates[key]; !exists {
				t.Fatalf("missing coordinate %s", key)
			}
			got = append(got, key)
		}
		if len(got) != len(coordinates) {
			t.Fatalf("unexpected coordinate set: %v", coordinates)
		}
	})
	t.Run("expected_checkpoint", func(t *testing.T) {
		if len(workflowCatalog.ActionProfiles) != len(expectedWorkflowActionProfiles) {
			t.Fatalf("action profile count=%d want %d", len(workflowCatalog.ActionProfiles), len(expectedWorkflowActionProfiles))
		}
		for action, expected := range expectedWorkflowActionProfiles {
			profile, exists := workflowCatalog.ActionProfiles[action]
			if !exists || profile != expected {
				t.Fatalf("action profile %s=%#v want %#v", action, profile, expected)
			}
		}
	})
	t.Run("missing_governing_authority_stop", func(t *testing.T) {
		input := initialInput()
		input["contextRefs"] = []any{contextValue("ctx.authority", "authority", testDigest, nil)}
		input["requiredContextRefIds"] = []any{"ctx.authority"}
		plan := requireBuild(t, input)
		prompt := plan["prompt"].(map[string]any)
		if !strings.Contains(prompt["stopCondition"].(string), missingOwnerStop) {
			t.Fatal("retained non-governing authority did not block mutation")
		}
	})
	t.Run("missing_witness", func(t *testing.T) {
		plan := requireBuild(t, initialInput())
		proof := plan["prompt"].(map[string]any)["proofCommandOrMissingWitness"].(map[string]any)
		if proof["state"] != missingConsumerWitness || len(proof) != 1 {
			t.Fatalf("unexpected proof state: %v", proof)
		}
	})
	t.Run("nonclaim", func(t *testing.T) {
		plan := requireBuild(t, initialInput())
		value := plan["prompt"].(map[string]any)["nonClaim"].(string)
		for _, denied := range []string{"execution", "merge approval", "production readiness"} {
			if !strings.Contains(value, denied) {
				t.Fatalf("prompt does not deny %s", denied)
			}
		}
	})
	t.Run("observed_fact", func(t *testing.T) {
		plan := requireBuild(t, initialInput())
		fact := plan["prompt"].(map[string]any)["observedFact"].(map[string]any)
		want := []string{"activeStageId", "checkpointState", "completedStageIds", "governingAuthorityRefId", "omittedContextRefIds", "retainedContextRefIds"}
		if len(fact) != len(want) {
			t.Fatalf("observed fact has unexpected fields: %v", fact)
		}
		for _, key := range want {
			if _, exists := fact[key]; !exists {
				t.Fatalf("observed fact lacks %s", key)
			}
		}
	})
	t.Run("owner_target", func(t *testing.T) {
		missing := requireBuild(t, initialInput())["prompt"].(map[string]any)
		if missing["ownerOrEscalationTarget"] != missingAuthorityTarget {
			t.Fatal("missing owner target is not closed")
		}
		present := requireBuild(t, reviewInput("ready_for_review"))["prompt"].(map[string]any)
		if present["ownerOrEscalationTarget"] != "ctx.authority" {
			t.Fatal("governing owner target was not projected")
		}
	})
	t.Run("stop_condition", func(t *testing.T) {
		for action, profile := range expectedWorkflowActionProfiles {
			if !strings.HasPrefix(profile.StopCondition, "Stop ") || strings.Contains(strings.ToLower(profile.StopCondition), "wait") {
				t.Fatalf("action %s has a non-terminal stop condition", action)
			}
		}
	})
	t.Run("typed_display_admission", func(t *testing.T) {
		for _, unsafePath := range []string{
			"evidence/unsafe\u2028path.json",
			"evidence/unsafe\u2066path.json",
			"evidence/unsafe\x1bpath.json",
			"evidence/" + string([]byte{0xff}) + ".json",
		} {
			input := initialInput()
			ref := contextValue("ctx.path", "artifact", testDigest, nil)
			ref["artifactPath"] = unsafePath
			input["contextRefs"] = []any{ref}
			requireReject(t, input)
		}
	})
	t.Run("uncertainty", func(t *testing.T) {
		plan := requireBuild(t, initialInput())
		if plan["prompt"].(map[string]any)["uncertainty"] != promptUncertainty {
			t.Fatal("prompt uncertainty drifted")
		}
	})
	t.Run("unsafe_no_echo", func(t *testing.T) {
		secret := "api_key=caller-sensitive-value"
		input := initialInput()
		ref := contextValue("ctx.path", "artifact", testDigest, nil)
		ref["artifactPath"] = "evidence/" + secret + ".json"
		input["contextRefs"] = []any{ref}
		err := requireReject(t, input)
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "caller-sensitive-value") {
			t.Fatal("rejection echoed caller-owned secret-shaped text")
		}
	})
}
