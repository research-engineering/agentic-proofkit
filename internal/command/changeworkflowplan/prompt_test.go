package changeworkflowplan

import (
	"strings"
	"testing"
)

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
		for index := range stageTable {
			for _, state := range []string{"not_started", "ready_for_review", "review_findings", "review_passed"} {
				plan := requireBuild(t, inputForStage(index, state))
				prompt := plan["prompt"].(map[string]any)
				if len(prompt) != 9 {
					t.Fatalf("prompt has %d fields", len(prompt))
				}
				profile := promptProfiles[plan["action"].(string)]
				if prompt["candidateAction"] != profile.CandidateAction {
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
		for action, profile := range promptProfiles {
			if profile.ExpectedNextCheckpoint == "" {
				t.Fatalf("action %s has no expected checkpoint", action)
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
		for action, profile := range promptProfiles {
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
