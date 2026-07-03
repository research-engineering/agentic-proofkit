package adoptiondoctor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func AgentEnvelope(result Result) map[string]any {
	reportValue := result.Record.JSONValue()
	actions := actionPlan(result)
	commands := commandRefs(result.Input.OwnerRoutes)
	context := contextRefs(result.Input.OwnerRoutes, result.Input.CandidateBoundaries, result.Input.StaleAuthority.AuthoritySurfaces)
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID:            result.Input.DoctorID + ".agent-envelope",
		ActionPlan:            actions,
		BlockedPreconditions:  blockedPreconditionRefs(result.Input.BlockedPreconditions),
		ClarificationQuestion: clarificationQuestions(result),
		Commands:              commands,
		ContextRefs:           context,
		NonClaims: []string{
			"Adoption doctor agent envelopes do not approve edits, enforcement, merge, or proof-owner retirement.",
			"Adoption doctor agent envelopes expose bounded selectors only and do not expand full repository graphs.",
		},
		RouteQuestions: []map[string]any{
			routeQuestion("proofkit.adoption-doctor.question.owner-route", "Which owner route owns the touched requirement or candidate boundary?", result.Input.DoctorID),
			routeQuestion("proofkit.adoption-doctor.question.proof-binding", "Which proof binding and native witness prove the candidate requirement?", result.Input.DoctorID),
			routeQuestion("proofkit.adoption-doctor.question.retirement", "Which old proof owner can be retired only after parity and owner approval?", result.Input.DoctorID),
		},
		SourceReport: reportValue,
		Bounds: map[string]any{
			"escalation":      "If the adoption doctor omits routes or gaps, load the caller-owned source reports and run the consumer repository full gate.",
			"fanout":          "bounded",
			"maxActionItems":  len(actions),
			"maxCommandRefs":  len(commands),
			"maxContextRefs":  len(context),
			"maxOmittedItems": 0,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Bounds are item-count guidance and do not prove tokenizer-specific costs.",
			"omittedCount":    0,
		},
	})
}

func commandRefs(routes []ownerRoute) []map[string]any {
	commands := []map[string]any{}
	for _, route := range routes {
		for index, command := range route.Commands {
			commands = append(commands, map[string]any{
				"command":   command,
				"commandId": fmt.Sprintf("%s.command.%03d", route.RouteID, index+1),
				"nonClaim":  "Command refs are display-only; the consuming repository owns execution and receipt admission.",
				"owner":     route.Owner,
			})
		}
	}
	sort.Slice(commands, func(left int, right int) bool {
		return commands[left]["commandId"].(string) < commands[right]["commandId"].(string)
	})
	return commands
}

func contextRefs(routes []ownerRoute, candidates []candidateBoundary, surfaces []authoritySurface) []map[string]any {
	refs := []map[string]any{}
	for _, route := range routes {
		for _, path := range append(append([]string{}, route.SpecPaths...), append(route.ProofBindingPaths, route.NativeWitnessRefs...)...) {
			refs = append(refs, contextRef(route.RouteID+"."+path, path, route.Owner, "owner_route"))
		}
	}
	for _, candidate := range candidates {
		for _, path := range candidate.AffectedPaths {
			refs = append(refs, contextRef(candidate.BoundaryID+"."+path, path, candidate.CandidateOwner, "candidate_boundary"))
		}
	}
	for _, surface := range surfaces {
		refs = append(refs, contextRef(surface.SurfaceID+"."+surface.Path, surface.Path, surface.Owner, "stale_authority_surface"))
	}
	sort.Slice(refs, func(left int, right int) bool {
		return refs[left]["refId"].(string) < refs[right]["refId"].(string)
	})
	return refs
}

func contextRef(id string, path string, owner string, kind string) map[string]any {
	return map[string]any{
		"kind":     kind,
		"nonClaim": "Context refs are selectors only; they do not prove file freshness or semantic correctness.",
		"owner":    owner,
		"path":     path,
		"refId":    id,
	}
}

func blockedPreconditionRefs(preconditions []precondition) []map[string]any {
	out := make([]map[string]any, 0, len(preconditions))
	for _, item := range preconditions {
		out = append(out, map[string]any{
			"description":    item.Reason,
			"evidenceRefs":   admit.StringSliceToAny(item.EvidenceRefs),
			"nonClaim":       item.NonClaim,
			"owner":          item.Owner,
			"preconditionId": item.PreconditionID,
		})
	}
	return out
}

func actionPlan(result Result) []map[string]any {
	if len(result.Gaps) == 0 {
		return []map[string]any{{
			"candidateAction": "Keep the caller-owned routes under review and run the consumer repository proof gate before promotion.",
			"commandIds":      []any{},
			"evidenceRefs":    []any{result.Input.DoctorID},
			"instruction":     "No adoption gaps were reported by the caller-provided facts.",
			"missingWitness":  "",
			"nonClaims": []any{
				"Adoption doctor action steps do not approve edits, proof freshness, merge, or enforcement.",
			},
			"observedFact": "Caller-provided adoption facts contain no missing owner routes, advisory candidate boundaries, failed child reports, or blocked preconditions.",
			"owner":        "consumer_repository",
			"phase":        "promote",
			"proofCommand": "consumer_repository_full_gate",
			"rationale":    "Promotion remains caller-owned even when Proofkit reports no adoption gaps.",
			"selectors": map[string]any{
				"evidenceRefs": []any{result.Input.DoctorID},
				"ruleRefs":     []any{},
			},
			"stepId":      "proofkit.adoption-doctor.no-gaps",
			"uncertainty": "Proofkit did not execute native witnesses or authenticate receipts.",
		}}
	}
	actions := make([]map[string]any, 0, len(result.Gaps))
	for _, item := range result.Gaps {
		actions = append(actions, actionForGap(result.Input, item))
	}
	return actions
}

func actionForGap(input Input, item gap) map[string]any {
	route, hasRoute := routeForGap(input.OwnerRoutes, item)
	candidate, hasCandidate := candidateForGap(input.CandidateBoundaries, item)
	observedFacts := observedFactsForGap(item, candidate, hasCandidate)
	uncertainties := uncertaintiesForGap(item, candidate, hasCandidate)
	selector := selectorsForGap(item, route, hasRoute, candidate, hasCandidate)
	return map[string]any{
		"candidateAction": candidateAction(item),
		"commandIds":      commandIDsForRoute(route, hasRoute),
		"evidenceRefs":    admit.StringSliceToAny(item.EvidenceRefs),
		"instruction":     actionInstruction(item),
		"missingWitness":  missingWitness(item, route, hasRoute, candidate, hasCandidate),
		"nonClaims": []any{
			"Adoption doctor action steps do not approve edits, proof freshness, merge, or enforcement.",
			"Observed facts, uncertainties, selectors, and commands are caller-provided or mechanically projected from caller-provided records.",
		},
		"observedFact":   firstText(observedFacts, item.Message),
		"observedFacts":  admit.StringSliceToAny(observedFacts),
		"owner":          item.Owner,
		"ownerQuestions": ownerQuestionsForGap(candidate, hasCandidate),
		"phase":          item.Phase,
		"proofCommand":   proofCommandForRoute(route, hasRoute),
		"rationale":      item.Message,
		"selectors":      selector,
		"stepId":         "proofkit.adoption-doctor." + item.GapID,
		"uncertainties":  admit.StringSliceToAny(uncertainties),
		"uncertainty":    firstText(uncertainties, item.Message),
	}
}

func routeForGap(routes []ownerRoute, item gap) (ownerRoute, bool) {
	for _, route := range routes {
		if strings.HasPrefix(item.GapID, route.RouteID+".") {
			return route, true
		}
	}
	return ownerRoute{}, false
}

func candidateForGap(candidates []candidateBoundary, item gap) (candidateBoundary, bool) {
	for _, candidate := range candidates {
		if strings.HasPrefix(item.GapID, candidate.BoundaryID+".") {
			return candidate, true
		}
	}
	return candidateBoundary{}, false
}

func observedFactsForGap(item gap, candidate candidateBoundary, hasCandidate bool) []string {
	if hasCandidate && len(candidate.ObservedFacts) > 0 {
		return candidate.ObservedFacts
	}
	return []string{item.Message}
}

func uncertaintiesForGap(item gap, candidate candidateBoundary, hasCandidate bool) []string {
	if hasCandidate && len(candidate.Uncertainties) > 0 {
		return candidate.Uncertainties
	}
	return []string{item.Message}
}

func selectorsForGap(item gap, route ownerRoute, hasRoute bool, candidate candidateBoundary, hasCandidate bool) map[string]any {
	selector := map[string]any{
		"evidenceRefs": admit.StringSliceToAny(item.EvidenceRefs),
		"ruleRefs":     admit.StringSliceToAny(item.RuleRefs),
	}
	if hasRoute {
		selector["nativeWitnessRefs"] = admit.StringSliceToAny(route.NativeWitnessRefs)
		selector["ownerRouteId"] = route.RouteID
		selector["proofBindingPaths"] = admit.StringSliceToAny(route.ProofBindingPaths)
		selector["specPaths"] = admit.StringSliceToAny(route.SpecPaths)
	}
	if hasCandidate {
		selector["affectedPaths"] = admit.StringSliceToAny(candidate.AffectedPaths)
		selector["candidateBoundaryId"] = candidate.BoundaryID
		selector["contractWitnessRefs"] = admit.StringSliceToAny(candidate.ContractWitnessRefs)
		selector["nativeWitnessRefs"] = admit.StringSliceToAny(candidate.NativeWitnessRefs)
		selector["proofBindingRefs"] = admit.StringSliceToAny(candidate.ProofBindingRefs)
	}
	return selector
}

func commandIDsForRoute(route ownerRoute, ok bool) []any {
	if !ok || len(route.Commands) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(route.Commands))
	for index := range route.Commands {
		out = append(out, fmt.Sprintf("%s.command.%03d", route.RouteID, index+1))
	}
	return out
}

func proofCommandForRoute(route ownerRoute, ok bool) string {
	if ok && len(route.Commands) > 0 {
		return route.Commands[0]
	}
	return "missing_command_route"
}

func missingWitness(item gap, route ownerRoute, hasRoute bool, candidate candidateBoundary, hasCandidate bool) string {
	if item.Kind == "missing_owner_route" {
		return "missing_owner_route"
	}
	if item.Kind == "missing_native_witness" {
		return "missing_native_witness"
	}
	if item.Kind == "missing_proof_binding" {
		return "missing_proof_binding"
	}
	if hasRoute && len(route.NativeWitnessRefs) == 0 {
		return "missing_native_witness"
	}
	if hasCandidate && len(candidate.NativeWitnessRefs) == 0 && len(candidate.ContractWitnessRefs) == 0 {
		return "candidate_witness_not_admitted"
	}
	return ""
}

func ownerQuestionsForGap(candidate candidateBoundary, ok bool) []any {
	if !ok {
		return []any{}
	}
	return admit.StringSliceToAny(candidate.OwnerQuestions)
}

func candidateAction(item gap) string {
	switch item.Kind {
	case "candidate_boundary_not_admitted":
		return "Ask the consuming repository owner whether the candidate boundary should become an admitted semantic owner before creating stable requirements."
	case "missing_owner_route":
		return "Create or select the caller-owned owner route before treating adoption facts as enforceable."
	case "missing_proof_binding":
		return "Create or repair the proof binding only after the requirement owner admits the semantic boundary."
	case "missing_native_witness":
		return "Add or route a native witness before treating the requirement as enforceable."
	case "missing_command_route":
		return "Add a caller-owned command route for the native witness before collecting receipts."
	case "blocked_precondition", "child_report_blocked":
		return "Resolve the blocked caller-owned precondition before promotion."
	case "child_report_failed", "child_report_skipped", "child_report_warning":
		return "Repair, rerun, or explicitly downgrade the non-passing caller-owned child report before promotion."
	case "stale_authority_current_vocabulary":
		return "Replace obsolete current authority vocabulary with the admitted package and proof-owner terms before enforcement."
	case "stale_authority_retired_scope":
		return "Move obsolete vocabulary into an admitted historical scope or remove it from current adoption authority surfaces."
	default:
		return "Review the caller-owned adoption gap before enforcement."
	}
}

func actionInstruction(item gap) string {
	switch item.Phase {
	case "route":
		return "Load the caller-owned selectors for this adoption gap and identify the owner route."
	case "modernize-boundary":
		return "Resolve the candidate boundary by owner decision before creating stable requirement records."
	case "bind":
		return "Create or repair stable requirement records and proof bindings for owner-admitted behavior only."
	case "verify":
		return "Run caller-owned native witnesses and collect admitted receipts outside Proofkit."
	case "parity":
		return "Compare old and new proof surfaces before retiring old infrastructure."
	case "retirement-review":
		return "Retire old proof owners only after parity, owner approval, and post-retirement validation exist."
	case "retire-stale-authority":
		return "Repair caller-owned stale authority vocabulary facts before treating the consumer adoption state as current."
	case "promote":
		return "Promote enforcement only after gaps are closed and merge policy accepts the resulting evidence."
	default:
		return "Review the caller-owned adoption gap before enforcement."
	}
}

func firstText(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return values[0]
}

func clarificationQuestions(result Result) []map[string]any {
	if len(result.Gaps) == 0 {
		return []map[string]any{}
	}
	return []map[string]any{
		{
			"askWhen":            "The consuming repository has candidate boundaries or missing proof routes.",
			"blocking":           adoptionmode.IsEnforcing(result.Input.Mode),
			"evidenceRefs":       []any{result.Input.DoctorID},
			"expectedAnswerKind": "owner_decision",
			"nonClaim":           "This question does not admit the owner decision.",
			"owner":              "consumer_repository",
			"question":           "Which candidate boundaries are stable semantic owners and which proof bindings must be created before enforcement?",
			"questionId":         "proofkit.adoption-doctor.clarify-owner-boundary",
		},
	}
}

func routeQuestion(id string, question string, evidenceRef string) map[string]any {
	return map[string]any{
		"evidenceRefs": []any{evidenceRef},
		"nonClaim":     "Route questions do not approve the resulting owner decision.",
		"question":     question,
		"questionId":   id,
	}
}
