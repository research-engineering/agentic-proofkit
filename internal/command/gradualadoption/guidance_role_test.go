package gradualadoption

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestGuidanceOwnerRouteEvidenceUsesSourceRoleNotCoincidentText(t *testing.T) {
	const collision = "proofkit.agent.context.command-input.001"
	for _, item := range []struct {
		name       string
		inputPath  string
		candidates int
	}{
		{"retained command context", "inputs/witness.json", 0},
		{"unavailable command context", "inputs/line\nbreak.json", 0},
		{"bounded catalogs", "inputs/witness.json", agentenvelope.MaxContextRefs + 4},
	} {
		t.Run(item.name, func(t *testing.T) {
			input := validGuidanceInput()
			owner := input["ownerRoute"].(map[string]any)
			owner["specPaths"] = []any{collision}
			owner["proofBindingPaths"] = []any{collision}
			input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
			if item.candidates > 0 {
				modernization := guidanceInputWithCandidateBoundary("observe")["modernization"].(map[string]any)
				template := modernization["candidateBoundaries"].([]any)[0]
				candidates := []any{}
				for index := 0; index < item.candidates; index++ {
					candidate := invocationJSON(t, template).(map[string]any)
					candidate["boundaryId"] = fmt.Sprintf("candidate.boundary.%03d", index)
					candidates = append(candidates, candidate)
				}
				modernization["candidateBoundaries"] = candidates
				input["modernization"] = modernization
			}
			result, err := buildGuidance(input, GuidanceOptions{})
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("guidance exit=%d err=%v", result.ExitCode, err)
			}
			// Fault injection tests projection admission independently of input admission.
			result.preparedCommands[0].inputRef = item.inputPath
			result.Guidance["commands"] = []any{result.preparedCommands[0].DisplayCommand()}
			envelope := guidanceEnvelope(result)
			contexts := guidanceRoleCatalog(t, envelope)
			route := envelopeActionByPhase(t, envelope, "route")
			want := map[string]guidanceRoleTarget{
				"proofkit.agent.context.evidence.001":      {"path", "evidence", "artifacts/proofkit/source.json"},
				"proofkit.agent.context.proof-binding.001": {"path", "proof_binding", collision},
				"proofkit.agent.context.spec.001":          {"path", "spec_source", collision},
			}
			if item.candidates > 0 {
				for id := range want {
					if _, exists := contexts[id]; !exists {
						delete(want, id)
					}
				}
			}
			assertGuidanceRoleRefs(t, contexts, route["evidenceRefs"], want)
			if item.inputPath != "inputs/witness.json" || item.candidates > 0 {
				if _, exists := contexts[collision]; exists {
					t.Fatal("unavailable unrelated command context was not omitted")
				}
				if len(envelope["commands"].([]any)) != 0 || len(envelope["omitted"].([]any)) == 0 {
					t.Fatal("generated command did not follow its exact unavailable input context")
				}
			}
			assertGuidanceLocalEvidenceClosure(t, envelope)
			if got, want := envelope["costContract"].(map[string]any)["referenceClosurePreserved"], item.inputPath == "inputs/witness.json"; got != want {
				t.Fatalf("closure=%v want %v for input provenance", got, want)
			}
			if len(contexts) > 48 {
				t.Fatal("hard context bound changed")
			}
			if err := schemacheck.Validate(GuidanceEnvelopeStructure(), envelope); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGuidanceActionAndQuestionEvidenceKeepSourceProvenance(t *testing.T) {
	input := guidanceInputWithCandidateBoundary("observe")
	agent := input["agentGuidance"].(map[string]any)
	agent["commands"] = []any{}
	agent["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
	agent["requiredNextActions"] = []any{"Resolve caller-owned proof gaps."}
	agent["proofBindingsMissing"] = []any{"proofkit.agent.context.command-input.001"}
	agent["blockedPreconditions"] = []any{"proofkit.agent.context.source-failure.001", "proofkit.agent.context.source-failure.001-near"}
	source := input["sourceReport"].(map[string]any)
	source["state"] = "warning"
	source["ruleResults"] = []any{
		map[string]any{"ruleId": "proofkit.agent.context.spec.001", "status": "failed", "message": "Caller failure."},
		map[string]any{"ruleId": "proofkit.agent.command.001", "status": "warning", "message": "Caller warning."},
	}
	candidate := firstCandidate(input)
	candidate["boundaryId"] = "proofkit.agent.command.001"
	candidate["affectedPaths"] = []any{"proofkit.agent.context.command-input.001"}
	candidate["requirementRefs"] = []any{"proofkit.agent.context.source-warning.001"}
	candidate["blockedPreconditions"] = []any{"proofkit.agent.context.spec.001"}
	envelope, exit, err := BuildGuidanceEnvelope(input, GuidanceOptions{})
	if err != nil || exit != 0 {
		t.Fatalf("guidance exit=%d err=%v", exit, err)
	}
	contexts := guidanceRoleCatalog(t, envelope)
	assertGuidanceRoleRefs(t, contexts, envelopeActionByPhase(t, envelope, "bind")["evidenceRefs"], map[string]guidanceRoleTarget{
		"proofkit.agent.context.missing-proof-binding.001": {"rule", "rule_reference", "proofkit.agent.context.command-input.001"},
	})
	assertGuidanceRoleRefs(t, contexts, envelopeActionByPhase(t, envelope, "verify")["evidenceRefs"], map[string]guidanceRoleTarget{
		"proofkit.agent.context.source-failure.001":       {"rule", "rule_reference", "proofkit.agent.context.spec.001"},
		"proofkit.agent.context.source-warning.001":       {"rule", "rule_reference", "proofkit.agent.command.001"},
		"proofkit.agent.context.blocked-precondition.001": {"rule", "supporting", "proofkit.agent.context.source-failure.001"},
		"proofkit.agent.context.blocked-precondition.002": {"rule", "supporting", "proofkit.agent.context.source-failure.001-near"},
	})
	candidateWant := map[string]guidanceRoleTarget{
		"proofkit.agent.context.candidate-boundary.001":                         {"candidate-boundary", "candidate_boundary", "proofkit.agent.command.001"},
		"proofkit.agent.context.candidate-boundary.001.affectedPaths.001":       {"path", "owner_surface", "proofkit.agent.context.command-input.001"},
		"proofkit.agent.context.proof-binding.001":                              {"path", "proof_binding", "docs/contracts/requirement-proof-bindings.v1.json"},
		"proofkit.agent.context.candidate-boundary.001.nativeWitnessRefs.001":   {"path", "evidence", "test/auth-webhook.test.ts"},
		"proofkit.agent.context.candidate-boundary.001.contractWitnessRefs.001": {"path", "evidence", "docs/contracts/auth-webhook.json"},
		"proofkit.agent.context.candidate-boundary.001.migrationRefs.001":       {"path", "owner_surface", "docs/plans/auth-boundary.md"},
		"proofkit.agent.context.candidate-boundary.001.requirement.001":         {"rule", "rule_reference", "proofkit.agent.context.source-warning.001"},
		"proofkit.agent.context.candidate-boundary.001.precondition.001":        {"rule", "supporting", "proofkit.agent.context.spec.001"},
	}
	assertGuidanceRoleRefs(t, contexts, envelopeActionByPhase(t, envelope, "modernize-boundary")["evidenceRefs"], candidateWant)
	for index, raw := range envelope["blockedPreconditions"].([]any) {
		assertGuidanceRoleRefs(t, contexts, raw.(map[string]any)["evidenceRefs"], map[string]guidanceRoleTarget{
			fmt.Sprintf("proofkit.agent.context.blocked-precondition.%03d", index+1): {"rule", "supporting", agent["blockedPreconditions"].([]any)[index].(string)},
		})
	}
	for _, raw := range envelope["clarificationQuestions"].([]any) {
		question := raw.(map[string]any)
		switch question["expectedAnswerKind"] {
		case "missing_witness":
			assertGuidanceRoleRefs(t, contexts, question["evidenceRefs"], map[string]guidanceRoleTarget{
				"proofkit.agent.context.missing-proof-binding.001": {"rule", "rule_reference", "proofkit.agent.context.command-input.001"},
			})
		case "blocked_external_input":
			id := "proofkit.agent.context.blocked-precondition.001"
			ref := "proofkit.agent.context.source-failure.001"
			if strings.HasSuffix(question["questionId"].(string), ".002") {
				id, ref = "proofkit.agent.context.blocked-precondition.002", ref+"-near"
			}
			assertGuidanceRoleRefs(t, contexts, question["evidenceRefs"], map[string]guidanceRoleTarget{id: {"rule", "supporting", ref}})
		case "owner_boundary_decision":
			assertGuidanceRoleRefs(t, contexts, question["evidenceRefs"], candidateWant)
		}
	}
	assertGuidanceLocalEvidenceClosure(t, envelope)
	if envelope["costContract"].(map[string]any)["referenceClosurePreserved"] != true {
		t.Fatal("admitted source roles lost local reference closure")
	}
	if err := schemacheck.Validate(GuidanceEnvelopeStructure(), envelope); err != nil {
		t.Fatal(err)
	}
}

func TestGuidancePreconditionTextCannotAcquirePathAdmission(t *testing.T) {
	for _, precondition := range []string{"api_key=synthetic-fixture", "inputs/task-validation.json", "inputs/line\u202ebreak.json"} {
		input := validGuidanceInput()
		agent := input["agentGuidance"].(map[string]any)
		agent["blockedPreconditions"] = []any{precondition}
		agent["requiredNextActions"] = []any{"Resolve caller-owned preconditions."}
		envelope, _, err := BuildGuidanceEnvelope(input, GuidanceOptions{})
		if err != nil {
			t.Fatal("precondition scalar changed collected failure behavior")
		}
		contexts := guidanceRoleCatalog(t, envelope)
		if _, exists := contexts["proofkit.agent.context.blocked-precondition.001"]; exists {
			t.Fatal("unsafe scalar obtained structural path preservation through a precondition role")
		}
		assertGuidanceLocalEvidenceClosure(t, envelope)
		assertNoBootstrapDisclosure(t, envelope, err, []string{"synthetic-fixture"})
	}
}

func TestGuidanceOwnershipQuestionKeepsOwnerAndSourceIdentityScopesDistinct(t *testing.T) {
	for _, owner := range []string{
		"proofkit.agent.command.001", "proofkit.agent.context.command-input.001",
		"proofkit.agent.context.source-failure.001", "proofkit.agent.context.blocked-precondition.001",
		"proofkit.agent.context.spec.001", "proofkit.agent.context.spec.001-near",
	} {
		for _, explicitScopes := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/scopes=%t", owner, explicitScopes), func(t *testing.T) {
				input := validGuidanceInput()
				input["ownerRoute"].(map[string]any)["primaryOwner"] = owner
				source := input["sourceReport"].(map[string]any)
				source["reportId"] = owner
				agent := input["agentGuidance"].(map[string]any)
				agent["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
				verifyWant := map[string]guidanceRoleTarget{}
				bindWant := map[string]guidanceRoleTarget{}
				if explicitScopes {
					source["state"] = "warning"
					source["ruleResults"] = []any{
						map[string]any{"ruleId": owner, "status": "failed", "message": "Caller failure."},
						map[string]any{"ruleId": owner + "-warning", "status": "warning", "message": "Caller warning."},
					}
					agent["proofBindingsMissing"] = []any{owner}
					agent["blockedPreconditions"] = []any{owner}
					agent["requiredNextActions"] = []any{"Resolve caller-owned proof gaps."}
					verifyWant["proofkit.agent.context.source-failure.001"] = guidanceRoleTarget{"rule", "rule_reference", owner}
					verifyWant["proofkit.agent.context.source-warning.001"] = guidanceRoleTarget{"rule", "rule_reference", owner + "-warning"}
					verifyWant["proofkit.agent.context.blocked-precondition.001"] = guidanceRoleTarget{"rule", "supporting", owner}
					bindWant["proofkit.agent.context.missing-proof-binding.001"] = guidanceRoleTarget{"rule", "rule_reference", owner}
				}
				envelope, code, err := BuildGuidanceEnvelope(input, GuidanceOptions{})
				if err != nil || code != 0 {
					t.Fatalf("guidance exit=%d err=%v", code, err)
				}
				contexts := guidanceRoleCatalog(t, envelope)
				wantCount := 5
				if explicitScopes {
					wantCount = 9
				}
				if len(contexts) != wantCount {
					t.Fatal("owner or report identity created an undeclared context scope")
				}
				found := false
				for _, raw := range envelope["routeQuestions"].([]any) {
					question := raw.(map[string]any)
					if question["questionId"] == "proofkit.agent.question.who-owns-it" {
						found = true
						assertGuidanceRoleRefs(t, contexts, question["evidenceRefs"], map[string]guidanceRoleTarget{
							"proofkit.agent.context.owner.001": {"owner", "owner_surface", owner},
						})
					}
				}
				if !found {
					t.Fatal("ownership question is missing")
				}
				assertGuidanceRoleRefs(t, contexts, envelopeActionByPhase(t, envelope, "verify")["evidenceRefs"], verifyWant)
				assertGuidanceRoleRefs(t, contexts, envelopeActionByPhase(t, envelope, "bind")["evidenceRefs"], bindWant)
				assertGuidanceLocalEvidenceClosure(t, envelope)
				if envelope["costContract"].(map[string]any)["referenceClosurePreserved"] != true {
					t.Fatal("owner or source identity collision degraded admitted reference closure")
				}
			})
		}
	}
}

type guidanceRoleTarget struct{ kind, role, ref string }

func guidanceRoleCatalog(t *testing.T, envelope map[string]any) map[string]guidanceRoleTarget {
	t.Helper()
	contexts := map[string]guidanceRoleTarget{}
	for _, raw := range envelope["contextRefs"].([]any) {
		context := raw.(map[string]any)
		if context["owner"] != "consumer_repository" {
			t.Fatal("caller text changed the fixed context authority")
		}
		id := context["refId"].(string)
		if _, exists := contexts[id]; exists {
			t.Fatal("duplicate context identity")
		}
		contexts[id] = guidanceRoleTarget{context["kind"].(string), context["role"].(string), context["ref"].(string)}
	}
	return contexts
}

func assertGuidanceRoleRefs(t *testing.T, contexts map[string]guidanceRoleTarget, raw any, want map[string]guidanceRoleTarget) {
	t.Helper()
	got := map[string]guidanceRoleTarget{}
	for _, rawID := range raw.([]any) {
		id := rawID.(string)
		target, exists := contexts[id]
		if !exists {
			t.Fatalf("evidence %q is not a retained context ID", id)
		}
		if _, duplicate := got[id]; duplicate {
			t.Fatalf("duplicate evidence %q", id)
		}
		got[id] = target
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence role/ref mismatch: got %#v want %#v", got, want)
	}
}

func assertGuidanceLocalEvidenceClosure(t *testing.T, envelope map[string]any) {
	t.Helper()
	contexts := guidanceRoleCatalog(t, envelope)
	commands := map[string]bool{}
	for _, raw := range envelope["commands"].([]any) {
		commands[raw.(map[string]any)["commandId"].(string)] = true
	}
	for _, key := range []string{"actionPlan", "blockedPreconditions", "clarificationQuestions"} {
		for _, raw := range envelope[key].([]any) {
			for _, ref := range raw.(map[string]any)["evidenceRefs"].([]any) {
				if _, exists := contexts[ref.(string)]; !exists {
					t.Fatalf("%s retained unresolved or external evidence %q", key, ref)
				}
			}
		}
	}
	for _, raw := range envelope["routeQuestions"].([]any) {
		for _, ref := range raw.(map[string]any)["evidenceRefs"].([]any) {
			if _, context := contexts[ref.(string)]; !context && !commands[ref.(string)] {
				t.Fatalf("route question retained unresolved local evidence %q", ref)
			}
		}
	}
	for _, raw := range envelope["actionPlan"].([]any) {
		for _, id := range raw.(map[string]any)["commandIds"].([]any) {
			if !commands[id.(string)] {
				t.Fatalf("action retained unresolved command %q", id)
			}
		}
	}
}
