package proofobligationalgebra

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.proof-obligation-algebra"

var obligationKinds = map[string]struct{}{
	"all_of":       {},
	"any_of":       {},
	"atomic":       {},
	"conditional":  {},
	"deferred":     {},
	"waived_until": {},
}

var orderedObligationKinds = []string{
	"atomic",
	"all_of",
	"any_of",
	"conditional",
	"deferred",
	"waived_until",
}

var proofBearingKinds = map[string]struct{}{
	"all_of":      {},
	"any_of":      {},
	"atomic":      {},
	"conditional": {},
}

var boundaryNonClaims = []string{
	"Proof obligation algebra reports do not approve merge, release, rollout, or production readiness.",
	"Proof obligation algebra reports do not authenticate producers or receipts.",
	"Proof obligation algebra reports do not compute freshness or proof satisfaction.",
	"Proof obligation algebra reports do not execute witnesses or commands.",
	"Proof obligation algebra reports do not own requirement meaning, proof adequacy, or consumer policy.",
}

type obligationInput struct {
	ChildObligationIDs []string
	ConditionRefs      []string
	DelegationRefs     []string
	EvidenceRefs       []string
	ExpiryRef          *string
	NonClaims          []string
	ObligationID       string
	ObligationKind     string
	Owner              string
	ProofRouteRefs     []string
	Rationale          string
	RequirementID      string
	ReviewConditionRef *string
}

type obligation struct {
	obligationInput
	GraphDepth                   int
	ProofBearing                 bool
	StructuralFindings           []string
	TransitiveChildObligationIDs []string
}

type admittedInput struct {
	AlgebraID   string
	NonClaims   []string
	Obligations []obligationInput
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	byID := map[string]obligationInput{}
	childSet := map[string]struct{}{}
	for _, item := range input.Obligations {
		byID[item.ObligationID] = item
		for _, childID := range item.ChildObligationIDs {
			childSet[childID] = struct{}{}
		}
	}
	obligations := make([]obligation, 0, len(input.Obligations))
	for _, item := range input.Obligations {
		obligations = append(obligations, evaluate(item, byID))
	}
	failedObligationIDs := []string{}
	rootObligationIDs := []string{}
	nonProofBearingObligationIDs := []string{}
	for _, item := range obligations {
		if len(item.StructuralFindings) > 0 {
			failedObligationIDs = append(failedObligationIDs, item.ObligationID)
		}
		if _, ok := childSet[item.ObligationID]; !ok {
			rootObligationIDs = append(rootObligationIDs, item.ObligationID)
		}
		if !item.ProofBearing {
			nonProofBearingObligationIDs = append(nonProofBearingObligationIDs, item.ObligationID)
		}
	}
	sort.Strings(rootObligationIDs)
	state := "passed"
	if len(failedObligationIDs) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.AlgebraID,
		State:         state,
		Summary: map[string]any{
			"crossRequirementDelegationCount": countCrossRequirementDelegations(obligations, byID),
			"failedObligationCount":           len(failedObligationIDs),
			"kindCounts":                      kindCounts(obligations),
			"nonProofBearingObligationCount":  len(nonProofBearingObligationIDs),
			"obligationCount":                 len(obligations),
			"proofBearingObligationCount":     len(obligations) - len(nonProofBearingObligationIDs),
			"rootObligationCount":             len(rootObligationIDs),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failedObligationIds", Value: admit.StringSliceToAny(failedObligationIDs)},
			{Key: "nonProofBearingObligationIds", Value: admit.StringSliceToAny(nonProofBearingObligationIDs)},
			{Key: "obligations", Value: obligationsJSON(obligations)},
			{Key: "rootObligationIds", Value: admit.StringSliceToAny(rootObligationIDs)},
		},
		RuleResults: ruleResults(obligations),
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("proof obligation algebra input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"algebraId", "nonClaims", "obligations", "schemaVersion"}, "proof obligation algebra input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("proof obligation algebra schemaVersion must be 1")
	}
	algebraID, err := admit.RuleID(record["algebraId"], "proof obligation algebra algebraId")
	if err != nil {
		return admittedInput{}, err
	}
	obligations, err := obligationArray(record["obligations"])
	if err != nil {
		return admittedInput{}, err
	}
	inputNonClaims, err := textArray(record["nonClaims"], "proof obligation algebra nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(append(append([]string{}, boundaryNonClaims...), inputNonClaims...), "proof obligation algebra nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		AlgebraID:   algebraID,
		NonClaims:   nonClaims,
		Obligations: obligations,
	}, nil
}

func obligationArray(raw any) ([]obligationInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("proof obligation algebra obligations must be a non-empty array")
	}
	obligations := make([]obligationInput, 0, len(values))
	for _, value := range values {
		item, err := admitObligation(value)
		if err != nil {
			return nil, err
		}
		obligations = append(obligations, item)
	}
	sort.Slice(obligations, func(left int, right int) bool {
		return obligations[left].ObligationID < obligations[right].ObligationID
	})
	ids := make([]string, 0, len(obligations))
	for _, item := range obligations {
		ids = append(ids, item.ObligationID)
	}
	if _, err := preserveSortedUnique(ids, "proof obligation ids", false); err != nil {
		return nil, err
	}
	return obligations, nil
}

func admitObligation(raw any) (obligationInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return obligationInput{}, fmt.Errorf("proof obligation must be an object")
	}
	if err := admit.KnownKeys(record, []string{"childObligationIds", "conditionRefs", "delegationRefs", "evidenceRefs", "expiryRef", "nonClaims", "obligationId", "obligationKind", "owner", "proofRouteRefs", "rationale", "requirementId", "reviewConditionRef"}, "proof obligation"); err != nil {
		return obligationInput{}, err
	}
	obligationID, err := admit.RuleID(record["obligationId"], "proof obligation obligationId")
	if err != nil {
		return obligationInput{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "proof obligation requirementId")
	if err != nil {
		return obligationInput{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], "proof obligation owner")
	if err != nil {
		return obligationInput{}, err
	}
	kind, err := admit.Enum(record["obligationKind"], obligationKinds, "proof obligation obligationKind")
	if err != nil {
		return obligationInput{}, err
	}
	proofRouteRefs, err := sortedRuleIDs(record["proofRouteRefs"], "proof obligation proofRouteRefs", true)
	if err != nil {
		return obligationInput{}, err
	}
	childObligationIDs, err := sortedRuleIDs(record["childObligationIds"], "proof obligation childObligationIds", true)
	if err != nil {
		return obligationInput{}, err
	}
	conditionRefs, err := sortedRuleIDs(record["conditionRefs"], "proof obligation conditionRefs", true)
	if err != nil {
		return obligationInput{}, err
	}
	delegationRefs, err := sortedRuleIDs(record["delegationRefs"], "proof obligation delegationRefs", true)
	if err != nil {
		return obligationInput{}, err
	}
	evidenceRefs, err := sortedPaths(record["evidenceRefs"], "proof obligation evidenceRefs")
	if err != nil {
		return obligationInput{}, err
	}
	expiryRef, err := nullableText(record["expiryRef"], "proof obligation expiryRef")
	if err != nil {
		return obligationInput{}, err
	}
	reviewConditionRef, err := nullableText(record["reviewConditionRef"], "proof obligation reviewConditionRef")
	if err != nil {
		return obligationInput{}, err
	}
	rationale, err := admit.NonEmptyText(record["rationale"], "proof obligation rationale")
	if err != nil {
		return obligationInput{}, err
	}
	nonClaimsRaw, err := textArray(record["nonClaims"], "proof obligation nonClaims", false)
	if err != nil {
		return obligationInput{}, err
	}
	nonClaims, err := sortedText(nonClaimsRaw, "proof obligation nonClaims", false)
	if err != nil {
		return obligationInput{}, err
	}
	return obligationInput{
		ChildObligationIDs: childObligationIDs,
		ConditionRefs:      conditionRefs,
		DelegationRefs:     delegationRefs,
		EvidenceRefs:       evidenceRefs,
		ExpiryRef:          expiryRef,
		NonClaims:          nonClaims,
		ObligationID:       obligationID,
		ObligationKind:     kind,
		Owner:              owner,
		ProofRouteRefs:     proofRouteRefs,
		Rationale:          rationale,
		RequirementID:      requirementID,
		ReviewConditionRef: reviewConditionRef,
	}, nil
}

func evaluate(item obligationInput, byID map[string]obligationInput) obligation {
	findings := []string{}
	findings = append(findings, kindFindings(item)...)
	findings = append(findings, childReferenceFindings(item, byID)...)
	findings = append(findings, cycleFindings(item, byID)...)
	findings = append(findings, crossRequirementFindings(item, byID)...)
	findings = append(findings, nonProofBearingChildFindings(item, byID)...)
	sort.Strings(findings)
	_, proofBearing := proofBearingKinds[item.ObligationKind]
	return obligation{
		obligationInput:              item,
		GraphDepth:                   graphDepth(item.ObligationID, byID, map[string]struct{}{}),
		ProofBearing:                 proofBearing,
		StructuralFindings:           findings,
		TransitiveChildObligationIDs: transitiveChildIDs(item.ObligationID, byID, map[string]struct{}{}),
	}
}

func kindFindings(item obligationInput) []string {
	findings := []string{}
	if item.ObligationKind == "atomic" {
		requireNonEmpty(item.ProofRouteRefs, "atomic obligations must declare proofRouteRefs", &findings)
		requireEmpty(item.ChildObligationIDs, "atomic obligations must not declare childObligationIds", &findings)
		requireEmpty(item.ConditionRefs, "atomic obligations must not declare conditionRefs", &findings)
		requireEmpty(item.DelegationRefs, "atomic obligations must not declare delegationRefs", &findings)
		requireNull(item.ExpiryRef, "atomic obligations must not declare expiryRef", &findings)
		requireNull(item.ReviewConditionRef, "atomic obligations must not declare reviewConditionRef", &findings)
		return findings
	}
	if item.ObligationKind == "all_of" || item.ObligationKind == "any_of" {
		requireMinimum(item.ChildObligationIDs, 2, fmt.Sprintf("%s obligations must declare at least two childObligationIds", item.ObligationKind), &findings)
		requireEmpty(item.ProofRouteRefs, fmt.Sprintf("%s obligations must not declare proofRouteRefs", item.ObligationKind), &findings)
		requireEmpty(item.ConditionRefs, fmt.Sprintf("%s obligations must not declare conditionRefs", item.ObligationKind), &findings)
		requireNull(item.ExpiryRef, fmt.Sprintf("%s obligations must not declare expiryRef", item.ObligationKind), &findings)
		requireNull(item.ReviewConditionRef, fmt.Sprintf("%s obligations must not declare reviewConditionRef", item.ObligationKind), &findings)
		return findings
	}
	if item.ObligationKind == "conditional" {
		requireNonEmpty(item.ChildObligationIDs, "conditional obligations must declare childObligationIds", &findings)
		requireNonEmpty(item.ConditionRefs, "conditional obligations must declare conditionRefs", &findings)
		requireEmpty(item.ProofRouteRefs, "conditional obligations must not declare proofRouteRefs", &findings)
		requireNull(item.ExpiryRef, "conditional obligations must not declare expiryRef", &findings)
		requireNull(item.ReviewConditionRef, "conditional obligations must not declare reviewConditionRef", &findings)
		return findings
	}
	requireEmpty(item.ProofRouteRefs, fmt.Sprintf("%s obligations must not declare proofRouteRefs", item.ObligationKind), &findings)
	requireEmpty(item.ChildObligationIDs, fmt.Sprintf("%s obligations must not declare childObligationIds", item.ObligationKind), &findings)
	requireEmpty(item.ConditionRefs, fmt.Sprintf("%s obligations must not declare conditionRefs", item.ObligationKind), &findings)
	requireEmpty(item.DelegationRefs, fmt.Sprintf("%s obligations must not declare delegationRefs", item.ObligationKind), &findings)
	requireNonEmpty(item.EvidenceRefs, fmt.Sprintf("%s obligations must declare evidenceRefs", item.ObligationKind), &findings)
	requireNonNull(item.ExpiryRef, fmt.Sprintf("%s obligations must declare expiryRef", item.ObligationKind), &findings)
	requireNonNull(item.ReviewConditionRef, fmt.Sprintf("%s obligations must declare reviewConditionRef", item.ObligationKind), &findings)
	return findings
}

func childReferenceFindings(item obligationInput, byID map[string]obligationInput) []string {
	findings := []string{}
	for _, childID := range item.ChildObligationIDs {
		if _, ok := byID[childID]; !ok {
			findings = append(findings, fmt.Sprintf("child obligation %s is not declared", childID))
		}
	}
	return findings
}

func cycleFindings(item obligationInput, byID map[string]obligationInput) []string {
	if hasCycle(item.ObligationID, item.ObligationID, byID, map[string]struct{}{}) {
		return []string{fmt.Sprintf("obligation graph contains a cycle through %s", item.ObligationID)}
	}
	return []string{}
}

func crossRequirementFindings(item obligationInput, byID map[string]obligationInput) []string {
	findings := []string{}
	for _, childID := range item.ChildObligationIDs {
		child, ok := byID[childID]
		if ok && child.RequirementID != item.RequirementID && len(item.DelegationRefs) == 0 {
			findings = append(findings, fmt.Sprintf("child obligation %s crosses requirement scope without delegationRefs", child.ObligationID))
		}
	}
	return findings
}

func nonProofBearingChildFindings(item obligationInput, byID map[string]obligationInput) []string {
	if _, proofBearing := proofBearingKinds[item.ObligationKind]; !proofBearing {
		return []string{}
	}
	findings := []string{}
	for _, childID := range item.ChildObligationIDs {
		child, ok := byID[childID]
		if !ok {
			continue
		}
		if _, proofBearing := proofBearingKinds[child.ObligationKind]; !proofBearing {
			findings = append(findings, fmt.Sprintf("child obligation %s is %s and cannot count as proof", child.ObligationID, child.ObligationKind))
		}
	}
	return findings
}

func hasCycle(rootID string, currentID string, byID map[string]obligationInput, visited map[string]struct{}) bool {
	current, ok := byID[currentID]
	if !ok {
		return false
	}
	for _, childID := range current.ChildObligationIDs {
		if childID == rootID {
			return true
		}
		if _, seen := visited[childID]; seen {
			continue
		}
		visited[childID] = struct{}{}
		if hasCycle(rootID, childID, byID, visited) {
			return true
		}
	}
	return false
}

func graphDepth(obligationID string, byID map[string]obligationInput, visited map[string]struct{}) int {
	item, ok := byID[obligationID]
	if !ok || len(item.ChildObligationIDs) == 0 {
		return 0
	}
	if _, seen := visited[obligationID]; seen {
		return 0
	}
	visited[obligationID] = struct{}{}
	maxDepth := 0
	for _, childID := range item.ChildObligationIDs {
		childVisited := copySet(visited)
		depth := graphDepth(childID, byID, childVisited)
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	return 1 + maxDepth
}

func transitiveChildIDs(obligationID string, byID map[string]obligationInput, visited map[string]struct{}) []string {
	item, ok := byID[obligationID]
	if !ok {
		return []string{}
	}
	if _, seen := visited[obligationID]; seen {
		return []string{}
	}
	visited[obligationID] = struct{}{}
	ids := map[string]struct{}{}
	for _, childID := range item.ChildObligationIDs {
		ids[childID] = struct{}{}
		for _, nestedID := range transitiveChildIDs(childID, byID, copySet(visited)) {
			ids[nestedID] = struct{}{}
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func copySet(input map[string]struct{}) map[string]struct{} {
	output := map[string]struct{}{}
	for key := range input {
		output[key] = struct{}{}
	}
	return output
}

func obligationsJSON(obligations []obligation) []any {
	result := make([]any, 0, len(obligations))
	for _, item := range obligations {
		result = append(result, obligationJSON(item))
	}
	return result
}

func obligationJSON(item obligation) map[string]any {
	return map[string]any{
		"childObligationIds":           admit.StringSliceToAny(item.ChildObligationIDs),
		"conditionRefs":                admit.StringSliceToAny(item.ConditionRefs),
		"delegationRefs":               admit.StringSliceToAny(item.DelegationRefs),
		"evidenceRefs":                 admit.StringSliceToAny(item.EvidenceRefs),
		"expiryRef":                    nullableStringJSON(item.ExpiryRef),
		"graphDepth":                   item.GraphDepth,
		"nonClaims":                    admit.StringSliceToAny(item.NonClaims),
		"obligationId":                 item.ObligationID,
		"obligationKind":               item.ObligationKind,
		"owner":                        item.Owner,
		"proofBearing":                 item.ProofBearing,
		"proofRouteRefs":               admit.StringSliceToAny(item.ProofRouteRefs),
		"rationale":                    item.Rationale,
		"requirementId":                item.RequirementID,
		"reviewConditionRef":           nullableStringJSON(item.ReviewConditionRef),
		"structuralFindings":           admit.StringSliceToAny(item.StructuralFindings),
		"transitiveChildObligationIds": admit.StringSliceToAny(item.TransitiveChildObligationIDs),
	}
}

func nullableStringJSON(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func ruleResults(obligations []obligation) []report.RuleResult {
	results := make([]report.RuleResult, 0, len(obligations))
	for _, item := range obligations {
		status := "passed"
		if len(item.StructuralFindings) > 0 {
			status = "failed"
		} else if !item.ProofBearing {
			status = "skipped"
		}
		message := fmt.Sprintf("obligation %s has admitted %s shape", item.ObligationID, item.ObligationKind)
		if len(item.StructuralFindings) > 0 {
			message = fmt.Sprintf("obligation %s has invalid %s shape", item.ObligationID, item.ObligationKind)
		}
		results = append(results, report.RuleResult{
			RuleID:  fmt.Sprintf("proofkit.proof-obligation-algebra.%s", item.ObligationID),
			Status:  status,
			Message: message,
			Diagnostics: []report.Diagnostic{
				{Key: "obligation", Value: obligationJSON(item)},
			},
		})
	}
	return results
}

func kindCounts(obligations []obligation) map[string]any {
	counts := map[string]any{}
	typedCounts := map[string]int{}
	for _, kind := range orderedObligationKinds {
		typedCounts[kind] = 0
	}
	for _, item := range obligations {
		typedCounts[item.ObligationKind]++
	}
	for _, kind := range orderedObligationKinds {
		counts[kind] = typedCounts[kind]
	}
	return counts
}

func countCrossRequirementDelegations(obligations []obligation, byID map[string]obligationInput) int {
	count := 0
	for _, item := range obligations {
		hasCrossRequirementDelegation := false
		for _, childID := range item.ChildObligationIDs {
			child, ok := byID[childID]
			if ok && child.RequirementID != item.RequirementID && len(item.DelegationRefs) > 0 {
				hasCrossRequirementDelegation = true
			}
		}
		if hasCrossRequirementDelegation {
			count++
		}
	}
	return count
}

func requireEmpty(values []string, message string, findings *[]string) {
	if len(values) > 0 {
		*findings = append(*findings, message)
	}
}

func requireNonEmpty(values []string, message string, findings *[]string) {
	if len(values) == 0 {
		*findings = append(*findings, message)
	}
}

func requireMinimum(values []string, minimum int, message string, findings *[]string) {
	if len(values) < minimum {
		*findings = append(*findings, message)
	}
}

func requireNull(value *string, message string, findings *[]string) {
	if value != nil {
		*findings = append(*findings, message)
	}
}

func requireNonNull(value *string, message string, findings *[]string) {
	if value == nil {
		*findings = append(*findings, message)
	}
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := textArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	ruleIDs := make([]string, 0, len(values))
	for _, value := range values {
		ruleID, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	return preserveSortedUnique(ruleIDs, context, allowEmpty)
}

func sortedPaths(raw any, context string) ([]string, error) {
	values, err := textArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(values))
	for _, value := range values {
		pathValue, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		paths = append(paths, pathValue)
	}
	return sortedText(paths, context, true)
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

func nullableText(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func sortedText(values []string, context string, allowEmpty bool) ([]string, error) {
	if len(values) == 0 && !allowEmpty {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, text)
	}
	sort.Strings(normalized)
	return preserveSortedUnique(normalized, context, allowEmpty)
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	if len(values) == 0 && !allowEmpty {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	for index := 0; index < len(values); index++ {
		if values[index] != sorted[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
		if index > 0 && values[index-1] == values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}
