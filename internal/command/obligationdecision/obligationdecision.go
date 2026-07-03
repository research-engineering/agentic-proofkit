package obligationdecision

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.obligation-decision"

var decisionStates = proofvocab.ObligationDecisionStates()
var decisionStateSet = proofvocab.ObligationDecisionStateSet()
var decisionClasses = proofvocab.ObligationClassSet()

var boundaryNonClaims = []string{
	"Obligation decision reports do not approve merge, release, rollout, or production readiness.",
	"Obligation decision reports do not authenticate producers.",
	"Obligation decision reports do not compute receipt freshness.",
	"Obligation decision reports do not execute proofs.",
	"Obligation decision reports do not infer changed scope or live availability.",
	"Obligation decision reports do not own requirement meaning or proof-route adequacy.",
}

var satisfiableBlockingStates = map[string]struct{}{
	"not_applicable": {},
	"satisfied":      {},
}

type obligationInput struct {
	CandidateStates []string
	EvidenceRefs    []string
	NonClaims       []string
	ObligationClass string
	ObligationID    string
	Owner           string
	ProofRouteRef   string
	Reason          string
	RequirementID   string
}

type obligationDecision struct {
	obligationInput
	BlocksProofSatisfaction bool
	DecisionRank            int
	DecisionState           string
}

type Result struct {
	BlockingUnsatisfiedObligationIDs []string
	Decisions                        []obligationDecision
	ExitCode                         int
	Report                           report.Record
}

type admittedInput struct {
	DecisionID  string
	NonClaims   []string
	Obligations []obligationInput
}

func Build(raw any) (Result, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Result{}, err
	}
	decisions := make([]obligationDecision, 0, len(input.Obligations))
	for _, obligation := range input.Obligations {
		decisions = append(decisions, decide(obligation))
	}
	sort.Slice(decisions, func(left int, right int) bool {
		return decisions[left].ObligationID < decisions[right].ObligationID
	})
	blockingUnsatisfied := []string{}
	for _, decision := range decisions {
		if decision.BlocksProofSatisfaction {
			blockingUnsatisfied = append(blockingUnsatisfied, decision.ObligationID)
		}
	}
	state := "passed"
	exitCode := 0
	if len(blockingUnsatisfied) > 0 {
		state = "failed"
		exitCode = 1
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.DecisionID,
		State:         state,
		Summary: map[string]any{
			"advisoryObligationCount":  countClass(decisions, "advisory"),
			"blockingObligationCount":  countClass(decisions, "blocking"),
			"blockingUnsatisfiedCount": len(blockingUnsatisfied),
			"deferredObligationCount":  countClass(decisions, "deferred"),
			"obligationCount":          len(decisions),
			"stateCounts":              stateCounts(decisions),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "blockingUnsatisfiedObligationIds", Value: admit.StringSliceToAny(blockingUnsatisfied)},
			{Key: "decisions", Value: decisionsJSON(decisions)},
		},
		RuleResults: decisionRuleResults(decisions),
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
	return Result{
		BlockingUnsatisfiedObligationIDs: blockingUnsatisfied,
		Decisions:                        decisions,
		ExitCode:                         exitCode,
		Report:                           record,
	}, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("obligation decision input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"decisionId", "nonClaims", "obligations", "schemaVersion"}, "obligation decision input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("obligation decision schemaVersion must be 1")
	}
	decisionID, err := admit.RuleID(record["decisionId"], "obligation decision decisionId")
	if err != nil {
		return admittedInput{}, err
	}
	obligations, err := obligations(record["obligations"])
	if err != nil {
		return admittedInput{}, err
	}
	inputNonClaims, err := textArray(record["nonClaims"], "obligation decision nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(append(append([]string{}, boundaryNonClaims...), inputNonClaims...), "obligation decision nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{DecisionID: decisionID, NonClaims: nonClaims, Obligations: obligations}, nil
}

func obligations(raw any) ([]obligationInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("obligation decision obligations must be a non-empty array")
	}
	result := make([]obligationInput, 0, len(values))
	for _, value := range values {
		obligation, err := admitObligation(value)
		if err != nil {
			return nil, err
		}
		result = append(result, obligation)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ObligationID < result[right].ObligationID
	})
	ids := make([]string, 0, len(result))
	for _, obligation := range result {
		ids = append(ids, obligation.ObligationID)
	}
	if _, err := preserveSortedUnique(ids, "obligation decision obligation ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitObligation(raw any) (obligationInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return obligationInput{}, fmt.Errorf("obligation decision obligation must be an object")
	}
	if err := admit.KnownKeys(record, []string{"candidateStates", "evidenceRefs", "nonClaims", "obligationClass", "obligationId", "owner", "proofRouteRef", "reason", "requirementId"}, "obligation decision obligation"); err != nil {
		return obligationInput{}, err
	}
	obligationID, err := admit.RuleID(record["obligationId"], "obligation decision obligationId")
	if err != nil {
		return obligationInput{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "obligation decision requirementId")
	if err != nil {
		return obligationInput{}, err
	}
	proofRouteRef, err := admit.RuleID(record["proofRouteRef"], "obligation decision proofRouteRef")
	if err != nil {
		return obligationInput{}, err
	}
	obligationClass, err := admit.Enum(record["obligationClass"], decisionClasses, "obligation decision obligationClass")
	if err != nil {
		return obligationInput{}, err
	}
	candidateStates, err := candidateStates(record["candidateStates"])
	if err != nil {
		return obligationInput{}, err
	}
	evidenceTexts, err := textArray(record["evidenceRefs"], "obligation decision evidenceRefs", false)
	if err != nil {
		return obligationInput{}, err
	}
	evidenceRefs, err := sortedPaths(evidenceTexts, "obligation decision evidenceRefs")
	if err != nil {
		return obligationInput{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], "obligation decision owner")
	if err != nil {
		return obligationInput{}, err
	}
	reason, err := admit.NonEmptyText(record["reason"], "obligation decision reason")
	if err != nil {
		return obligationInput{}, err
	}
	nonClaimTexts, err := textArray(record["nonClaims"], "obligation decision obligation nonClaims", false)
	if err != nil {
		return obligationInput{}, err
	}
	nonClaims, err := sortedText(nonClaimTexts, "obligation decision obligation nonClaims", false)
	if err != nil {
		return obligationInput{}, err
	}
	return obligationInput{
		CandidateStates: candidateStates,
		EvidenceRefs:    evidenceRefs,
		NonClaims:       nonClaims,
		ObligationClass: obligationClass,
		ObligationID:    obligationID,
		Owner:           owner,
		ProofRouteRef:   proofRouteRef,
		Reason:          reason,
		RequirementID:   requirementID,
	}, nil
}

func candidateStates(raw any) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("obligation decision candidateStates must be a non-empty array")
	}
	states := make([]string, 0, len(values))
	for _, value := range values {
		state, err := admit.Enum(value, decisionStateSet, "obligation decision candidate state")
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	sort.Slice(states, func(left int, right int) bool {
		return stateRank(states[left]) < stateRank(states[right])
	})
	for index := 1; index < len(states); index++ {
		if states[index-1] == states[index] {
			return nil, fmt.Errorf("obligation decision candidate states must be sorted and unique")
		}
	}
	return states, nil
}

func decide(input obligationInput) obligationDecision {
	decisionState := "satisfied"
	if len(input.CandidateStates) > 0 {
		decisionState = input.CandidateStates[0]
	}
	_, satisfiable := satisfiableBlockingStates[decisionState]
	blocks := input.ObligationClass == "blocking" && !satisfiable
	return obligationDecision{
		obligationInput:         input,
		BlocksProofSatisfaction: blocks,
		DecisionRank:            stateRank(decisionState),
		DecisionState:           decisionState,
	}
}

func decisionsJSON(decisions []obligationDecision) []any {
	result := make([]any, 0, len(decisions))
	for _, decision := range decisions {
		result = append(result, map[string]any{
			"blocksProofSatisfaction": decision.BlocksProofSatisfaction,
			"candidateStates":         admit.StringSliceToAny(decision.CandidateStates),
			"decisionRank":            decision.DecisionRank,
			"decisionState":           decision.DecisionState,
			"evidenceRefs":            admit.StringSliceToAny(decision.EvidenceRefs),
			"nonClaims":               admit.StringSliceToAny(decision.NonClaims),
			"obligationClass":         decision.ObligationClass,
			"obligationId":            decision.ObligationID,
			"owner":                   decision.Owner,
			"proofRouteRef":           decision.ProofRouteRef,
			"reason":                  decision.Reason,
			"requirementId":           decision.RequirementID,
		})
	}
	return result
}

func decisionRuleResults(decisions []obligationDecision) []report.RuleResult {
	results := make([]report.RuleResult, 0, len(decisions))
	for _, decision := range decisions {
		message := fmt.Sprintf("obligation %s selected %s", decision.ObligationID, decision.DecisionState)
		if decision.BlocksProofSatisfaction {
			message = fmt.Sprintf("blocking obligation %s selected %s", decision.ObligationID, decision.DecisionState)
		}
		results = append(results, report.RuleResult{
			RuleID:  fmt.Sprintf("proofkit.obligation-decision.%s", decision.ObligationID),
			Status:  ruleStatus(decision),
			Message: message,
			Diagnostics: []report.Diagnostic{
				{
					Key: "decision",
					Value: map[string]any{
						"blocksProofSatisfaction": decision.BlocksProofSatisfaction,
						"candidateStates":         admit.StringSliceToAny(decision.CandidateStates),
						"decisionRank":            decision.DecisionRank,
						"decisionState":           decision.DecisionState,
						"obligationClass":         decision.ObligationClass,
						"proofRouteRef":           decision.ProofRouteRef,
						"requirementId":           decision.RequirementID,
					},
				},
			},
		})
	}
	return results
}

func ruleStatus(decision obligationDecision) string {
	if decision.BlocksProofSatisfaction {
		return "failed"
	}
	if decision.DecisionState == "satisfied" || decision.DecisionState == "not_applicable" {
		return "passed"
	}
	if decision.DecisionState == "advisory_skipped" || decision.DecisionState == "deferred_admitted" || decision.DecisionState == "unavailable_live" {
		return "skipped"
	}
	return "warning"
}

func stateCounts(decisions []obligationDecision) map[string]any {
	counts := map[string]any{}
	for _, state := range decisionStates {
		counts[state] = 0
	}
	for _, decision := range decisions {
		counts[decision.DecisionState] = counts[decision.DecisionState].(int) + 1
	}
	return counts
}

func countClass(decisions []obligationDecision, class string) int {
	count := 0
	for _, decision := range decisions {
		if decision.ObligationClass == class {
			count++
		}
	}
	return count
}

func stateRank(state string) int {
	return proofvocab.ObligationDecisionStateRank(state)
}

func sortedPaths(values []string, context string) ([]string, error) {
	paths := make([]string, 0, len(values))
	for _, value := range values {
		pathValue, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		paths = append(paths, pathValue)
	}
	return sortedText(paths, context, false)
}

func textArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a string array", context)
		}
		result = append(result, text)
	}
	if !allowEmpty && len(result) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	return result, nil
}

func sortedText(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	for index, value := range values {
		trimmed, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		values[index] = trimmed
	}
	sort.Strings(values)
	return preserveSortedUnique(values, context, allowEmpty)
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}
