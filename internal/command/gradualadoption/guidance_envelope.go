package gradualadoption

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func guidanceEnvelope(result guidanceResult) map[string]any {
	commandRefs := []map[string]any{}
	commandIDByText := map[string]string{}
	preparedByText := map[string]PreparedCommand{}
	callerByText := stringSet(result.callerCommands)
	callerFallbackIDs := []string{}
	for _, command := range result.preparedCommands {
		preparedByText[command.DisplayCommand()] = command
	}
	contextRefs := []map[string]any{}
	operandBindings := []agentenvelope.OperandBinding{}
	for index, command := range stringArrayFromMap(result.Guidance, "commands") {
		commandID := fmt.Sprintf("proofkit.agent.command.%03d", index+1)
		commandIDByText[command] = commandID
		ref := map[string]any{
			"command":   command,
			"commandId": commandID,
			"nonClaim":  "Proofkit reports this command but does not execute it or prove it passed.",
			"owner":     "consumer_repository",
			"purpose":   "Caller-owned native witness command reported for agent routing.",
		}
		if prepared, ok := preparedByText[command]; ok {
			ref["purpose"] = "Prepared Proofkit planning or inspection operation, not a native witness."
			if _, callerOwned := callerByText[command]; callerOwned {
				callerFallbackIDs = append(callerFallbackIDs, commandID)
				ref["purpose"] = "Prepared Proofkit planning or inspection operation, also independently reported as a caller-owned native witness command."
			}
			argv := prepared.Argv()
			ref["argv"] = admit.StringSliceToAny(argv)
			contextID := fmt.Sprintf("proofkit.agent.context.command-input.%03d", index+1)
			contextRefs = append(contextRefs, map[string]any{
				"kind": "path", "ref": prepared.InputRef(), "refId": contextID,
				"role": "command_registry", "owner": "consumer_repository",
				"purpose":  "Prepared Proofkit command input.",
				"nonClaim": "This input route does not prove materialization or command execution.",
			})
			operandBindings = append(operandBindings, agentenvelope.OperandBinding{CommandID: commandID, ArgvIndex: len(argv) - 1, ContextRefID: contextID})
		}
		commandRefs = append(commandRefs, ref)
	}
	ownerRoute := result.Guidance["ownerRoute"].(map[string]any)
	routeContexts := pathContextRefs(stringArrayFromMap(ownerRoute, "evidencePaths"), "evidence", "evidence", "Caller-owned evidence artifact route.")
	routeContexts = append(routeContexts, pathContextRefs(stringArrayFromMap(ownerRoute, "proofBindingPaths"), "proof-binding", "proof_binding", "Caller-owned requirement-to-witness binding route.")...)
	routeContexts = append(routeContexts, pathContextRefs(stringArrayFromMap(ownerRoute, "specPaths"), "spec", "spec_source", "Caller-owned specification route.")...)
	ownerContexts := []map[string]any{}
	if owner := ownerRoute["primaryOwner"].(string); owner != "" {
		ownerContexts = append(ownerContexts, map[string]any{
			"kind": "owner", "ref": owner, "refId": "proofkit.agent.context.owner.001",
			"role": "owner_surface", "owner": "consumer_repository",
			"purpose":  "Caller-declared primary owner of this route.",
			"nonClaim": "An owner declaration does not prove accountability or grant approval.",
		})
	}
	missingContexts := ruleContextRefs(stringArrayFromMap(result.Guidance, "proofBindingsMissing"), "missing-proof-binding", "Caller-reported missing proof binding obligation.")
	preconditionContexts := preconditionContextRefs(stringArrayFromMap(result.Guidance, "blockedPreconditions"), "blocked-precondition")
	witnessContexts := ruleContextRefs(stringArrayFromMap(result.Guidance, "sourceFailedRuleIds"), "source-failure", "Source report failure rule requiring caller-owned inspection.")
	witnessContexts = append(witnessContexts, ruleContextRefs(stringArrayFromMap(result.Guidance, "sourceWarningRuleIds"), "source-warning", "Source report warning rule requiring caller-owned inspection.")...)
	witnessContexts = append(witnessContexts, preconditionContexts...)
	contextRefs = append(contextRefs, routeContexts...)
	contextRefs = append(contextRefs, ownerContexts...)
	contextRefs = append(contextRefs, missingContexts...)
	contextRefs = append(contextRefs, witnessContexts...)
	candidateContexts, candidateRefs := candidateBoundaryContextRefs(anyArrayFromMap(result.Guidance, "candidateBoundaries"), contextRefs)
	contextRefs = append(contextRefs, candidateContexts...)
	// Each step owns its source fields. Raw text cannot select another role's ID.
	actionEvidence := map[string][]string{
		"proofkit.agent.route-owner":                  envelopeMapValues(routeContexts, "refId"),
		"proofkit.agent.bind-requirements":            envelopeMapValues(missingContexts, "refId"),
		"proofkit.agent.run-native-witnesses":         envelopeMapValues(witnessContexts, "refId"),
		"proofkit.agent.promote-enforcement":          {},
		"proofkit.agent.resolve-candidate-boundaries": {},
	}
	for _, refs := range candidateRefs {
		actionEvidence["proofkit.agent.resolve-candidate-boundaries"] = append(actionEvidence["proofkit.agent.resolve-candidate-boundaries"], refs...)
	}
	actionPlan := []map[string]any{}
	for _, rawAction := range result.Guidance["agentActionPlan"].([]any) {
		action := rawAction.(map[string]any)
		commandIDs := []string{}
		for _, command := range stringArrayFromMap(action, "commands") {
			commandID, ok := commandIDByText[command]
			if ok {
				commandIDs = append(commandIDs, commandID)
			}
		}
		actionPlan = append(actionPlan, map[string]any{
			"commandIds":   admit.StringSliceToAny(commandIDs),
			"evidenceRefs": admit.StringSliceToAny(uniqueStrings(actionEvidence[action["stepId"].(string)])),
			"instruction":  action["instruction"],
			"nonClaims":    action["nonClaims"],
			"owner":        action["owner"],
			"phase":        action["phase"],
			"rationale":    envelopeActionRationale(action["phase"].(string)),
			"stepId":       action["stepId"],
		})
	}
	blocked := []map[string]any{}
	for index, precondition := range stringArrayFromMap(result.Guidance, "blockedPreconditions") {
		blocked = append(blocked, map[string]any{
			"description":    precondition,
			"evidenceRefs":   []any{preconditionContexts[index]["refId"]},
			"nonClaim":       "Blocked preconditions are caller-owned and are not resolved by proofkit.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("proofkit.agent.blocked-precondition.%03d", index+1),
		})
	}
	contextRefIDs := envelopeMapValues(contextRefs, "refId")
	commandIDs := envelopeMapValues(commandRefs, "commandId")
	return agentenvelope.Build(agentenvelope.Input{
		CallerDisplayFallbackCommandIDs: callerFallbackIDs,
		CommandDisplayField:             "command",
		EnvelopeID:                      fmt.Sprintf("%s.agent-envelope", result.Record.ReportID),
		Renderer:                        result.renderer,
		OperandBindings:                 operandBindings,
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Source report identity does not prove native witness execution, freshness, or caller approval.",
			"reportId":    result.Record.ReportID,
			"reportKind":  result.Record.ReportKind,
			"stableHash":  nil,
			"state":       result.Record.State,
		},
		Bounds: map[string]any{
			"escalation":      "Caller must run a wider caller-owned proof plan when these refs do not cover the changed repository scope.",
			"fanout":          "bounded",
			"maxActionItems":  len(actionPlan),
			"maxCommandRefs":  len(commandRefs),
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": 0,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Bounds cover generated envelope item counts only; they do not prove tokenizer-specific budget or proof completeness.",
			"omittedCount":    0,
		},
		ContextRefs: contextRefs,
		RouteQuestions: []map[string]any{
			{"evidenceRefs": admit.StringSliceToAny(contextRefIDs), "nonClaim": "This question routes context only; it does not decide repository truth.", "question": "what changed", "questionId": "proofkit.agent.question.what-changed"},
			{"evidenceRefs": map[bool][]any{true: admit.StringSliceToAny(commandIDs), false: admit.StringSliceToAny(contextRefIDs)}[len(commandIDs) > 0], "nonClaim": "Command references distinguish caller-reported witnesses from prepared Proofkit planning or inspection operations; neither is pass evidence.", "question": "what proves it", "questionId": "proofkit.agent.question.what-proves-it"},
			{"evidenceRefs": admit.StringSliceToAny(envelopeMapValues(ownerContexts, "refId")), "nonClaim": "Ownership remains in the consuming repository; caller-provided owner names do not select local reference identities.", "question": "who owns it", "questionId": "proofkit.agent.question.who-owns-it"},
		},
		ClarificationQuestion: guidanceClarifications(result.Guidance, envelopeMapValues(missingContexts, "refId"), envelopeMapValues(preconditionContexts, "refId"), candidateRefs),
		ActionPlan:            actionPlan,
		Commands:              commandRefs,
		BlockedPreconditions:  blocked,
		Omitted:               []map[string]any{},
		ReceiptRefs:           []map[string]any{},
		NonClaims:             stringArrayFromMap(result.Guidance, "nonClaims"),
	})
}

func candidateBoundaryContextRefs(candidates []any, existing []map[string]any) ([]map[string]any, [][]string) {
	refs := []map[string]any{}
	byCandidate := make([][]string, 0, len(candidates))
	type pathRoute struct{ role, ref string }
	pathIDs := map[pathRoute]string{}
	for _, context := range existing {
		if context["kind"] == "path" {
			pathIDs[pathRoute{context["role"].(string), context["ref"].(string)}] = context["refId"].(string)
		}
	}
	for index, raw := range candidates {
		candidate := raw.(map[string]any)
		prefix := fmt.Sprintf("candidate-boundary.%03d", index+1)
		boundaryID := "proofkit.agent.context." + prefix
		refs = append(refs, map[string]any{
			"kind":     "candidate-boundary",
			"nonClaim": candidateBoundaryNonClaim,
			"owner":    "consumer_repository",
			"purpose":  "Advisory candidate semantic boundary requiring owner admission.",
			"ref":      candidate["boundaryId"],
			"refId":    boundaryID,
			"role":     "candidate_boundary",
		})
		candidateRefs := []string{boundaryID}
		for _, field := range []struct{ key, role string }{
			{"affectedPaths", "owner_surface"},
			{"proofBindingRefs", "proof_binding"},
			{"nativeWitnessRefs", "evidence"},
			{"contractWitnessRefs", "evidence"},
			{"migrationRefs", "owner_surface"},
		} {
			paths := pathContextRefs(stringArrayFromMap(candidate, field.key), prefix+"."+field.key, field.role, "Caller-owned advisory candidate "+field.key+" route; owner admission remains required.")
			for _, path := range paths {
				key := pathRoute{field.role, path["ref"].(string)}
				id := pathIDs[key]
				if id == "" {
					refs = append(refs, path)
					id = path["refId"].(string)
					pathIDs[key] = id
				}
				candidateRefs = append(candidateRefs, id)
			}
		}
		rules := ruleContextRefs(stringArrayFromMap(candidate, "requirementRefs"), prefix+".requirement", "Advisory candidate requirement route; this does not admit repository semantics.")
		preconditions := preconditionContextRefs(stringArrayFromMap(candidate, "blockedPreconditions"), prefix+".precondition")
		refs = append(refs, rules...)
		refs = append(refs, preconditions...)
		candidateRefs = append(candidateRefs, envelopeMapValues(rules, "refId")...)
		candidateRefs = append(candidateRefs, envelopeMapValues(preconditions, "refId")...)
		byCandidate = append(byCandidate, uniqueStrings(candidateRefs))
	}
	return refs, byCandidate
}

func preconditionContextRefs(preconditions []string, prefix string) []map[string]any {
	refs := ruleContextRefs(preconditions, prefix, "Caller-reported blocked precondition requiring independent caller-owned resolution.")
	for _, ref := range refs {
		ref["role"] = "supporting"
		ref["nonClaim"] = "This precondition reference does not prove satisfaction, freshness, or caller approval."
	}
	return refs
}

func pathContextRefs(paths []string, prefix string, role string, purpose string) []map[string]any {
	refs := make([]map[string]any, 0, len(paths))
	for index, path := range paths {
		refs = append(refs, map[string]any{
			"kind":     "path",
			"nonClaim": "Context refs route agent loading only and do not prove freshness or correctness.",
			"owner":    "consumer_repository",
			"purpose":  purpose,
			"ref":      path,
			"refId":    fmt.Sprintf("proofkit.agent.context.%s.%03d", prefix, index+1),
			"role":     role,
		})
	}
	return refs
}

func ruleContextRefs(ruleIDs []string, prefix string, purpose string) []map[string]any {
	refs := make([]map[string]any, 0, len(ruleIDs))
	for index, ruleID := range ruleIDs {
		refs = append(refs, map[string]any{
			"kind":     "rule",
			"nonClaim": "Rule refs route caller-owned inspection only and do not prove remediation.",
			"owner":    "consumer_repository",
			"purpose":  purpose,
			"ref":      ruleID,
			"refId":    fmt.Sprintf("proofkit.agent.context.%s.%03d", prefix, index+1),
			"role":     "rule_reference",
		})
	}
	return refs
}

func guidanceClarifications(guidance map[string]any, missingRefs []string, preconditionRefs []string, candidateRefs [][]string) []map[string]any {
	questions := []map[string]any{}
	mode := guidance["guidanceMode"].(string)
	blocking := adoptionmode.IsEnforcing(mode)
	for index, binding := range stringArrayFromMap(guidance, "proofBindingsMissing") {
		questions = append(questions, map[string]any{
			"askWhen":            "A requirement or source failure has no caller-owned proof binding route.",
			"blocking":           blocking,
			"evidenceRefs":       []any{missingRefs[index]},
			"expectedAnswerKind": "missing_witness",
			"nonClaim":           "The question does not create or approve a proof binding.",
			"owner":              "consumer_repository",
			"question":           fmt.Sprintf("Which caller-owned witness should bind %s?", binding),
			"questionId":         fmt.Sprintf("proofkit.agent.clarify.missing-proof-binding.%03d", index+1),
		})
	}
	for index, precondition := range stringArrayFromMap(guidance, "blockedPreconditions") {
		questions = append(questions, map[string]any{
			"askWhen":            "A caller-owned external precondition blocks reliable proof routing.",
			"blocking":           true,
			"evidenceRefs":       []any{preconditionRefs[index]},
			"expectedAnswerKind": "blocked_external_input",
			"nonClaim":           "The question does not prove that the external precondition is satisfied.",
			"owner":              "consumer_repository",
			"question":           fmt.Sprintf("What caller-owned evidence resolves this blocked precondition: %s?", precondition),
			"questionId":         fmt.Sprintf("proofkit.agent.clarify.blocked-precondition.%03d", index+1),
		})
	}
	for candidateIndex, raw := range anyArrayFromMap(guidance, "candidateBoundaries") {
		candidate := raw.(map[string]any)
		for questionIndex, question := range stringArrayFromMap(candidate, "ownerQuestions") {
			questions = append(questions, map[string]any{
				"askWhen":            "A candidate boundary is advisory and cannot be promoted without owner review.",
				"blocking":           true,
				"evidenceRefs":       admit.StringSliceToAny(candidateRefs[candidateIndex]),
				"expectedAnswerKind": "owner_boundary_decision",
				"nonClaim":           "The question does not admit candidate boundaries as repository semantics.",
				"owner":              "consumer_repository",
				"question":           question,
				"questionId":         fmt.Sprintf("proofkit.agent.clarify.candidate-boundary.%03d.%03d", candidateIndex+1, questionIndex+1),
			})
		}
	}
	return questions
}
