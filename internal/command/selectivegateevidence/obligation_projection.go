package selectivegateevidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/receiptcurrentnessscope"
	"github.com/research-engineering/agentic-proofkit/internal/command/receipttrustclass"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

type currentnessProjectionDiagnostic struct {
	CurrentnessCheckRefs [][]string
	DecisionStates       []string
	EvidenceRefs         []string
	ReceiptID            string
	RequirementID        string
	ProofRouteRef        string
	ScopeCheckRefs       [][]string
}

type trustProjectionDiagnostic struct {
	ArtifactRefs   []string
	DecisionStates []string
	EvidenceRefs   []string
	ProducerRef    string
	ProofRouteRef  string
	ProvenanceRef  *string
	ReceiptID      string
	ReceiptStatus  string
	RequirementID  string
}

func ProjectObligationDecision(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("selective evidence obligation projection input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandRoutes", "decisionId", "evidence", "nonClaims", "receiptCurrentnessScopeAdmission", "receiptTrustClassAdmission", "schemaVersion"}, "selective evidence obligation projection input"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return nil, fmt.Errorf("selective evidence obligation projection schemaVersion must be 1")
	}
	decisionID, err := admit.RuleID(record["decisionId"], "selective evidence obligation projection decisionId")
	if err != nil {
		return nil, err
	}
	evidenceInput, err := admitEvidenceInput(record["evidence"])
	if err != nil {
		return nil, err
	}
	evidence, err := buildEvidence(evidenceInput)
	if err != nil {
		return nil, err
	}
	plan := evidenceInput.Plan
	unsupported := unsupportedProjectionFailures(plan, evidenceInput.PreexistingFailures, evidence.ProducerAdmissionFailures, evidence.UnexpectedReceipts)
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("selective evidence obligation projection requires explicit obligation decisions for unscoped failures: %s", strings.Join(unsupported, "; "))
	}
	routeRecords, err := arrayOfRecords(record["commandRoutes"], "selective evidence obligation projection commandRoutes")
	if err != nil {
		return nil, err
	}
	expectedKeys := map[string]struct{}{}
	for _, command := range plan.RequiredCommands {
		expectedKeys[keyString(commandKeyFromCommand(command))] = struct{}{}
	}
	routes := map[string]map[string]any{}
	routesByObligation := map[string]map[string]any{}
	routeKeys := []string{}
	for _, routeRecord := range routeRecords {
		route, key, err := admitRoute(routeRecord)
		if err != nil {
			return nil, err
		}
		if _, ok := expectedKeys[key]; !ok {
			return nil, fmt.Errorf("selective evidence obligation projection route does not match a planned command: %s", describeKey(parseKey(key)))
		}
		if _, ok := routes[key]; ok {
			return nil, fmt.Errorf("selective evidence obligation projection command route keys must be sorted and unique")
		}
		routes[key] = route
		obligationID := route["obligationId"].(string)
		if _, ok := routesByObligation[obligationID]; ok {
			return nil, fmt.Errorf("selective evidence obligation projection obligationId values must be unique")
		}
		routesByObligation[obligationID] = route
		routeKeys = append(routeKeys, key)
	}
	sort.Strings(routeKeys)
	receiptGroups := groupReceipts(evidenceInput.Receipts)
	currentnessDiagnostics, err := currentnessDiagnosticsByObligation(record["receiptCurrentnessScopeAdmission"], routesByObligation, receiptGroups)
	if err != nil {
		return nil, err
	}
	trustDiagnostics, err := trustDiagnosticsByObligation(record["receiptTrustClassAdmission"], routesByObligation, receiptGroups)
	if err != nil {
		return nil, err
	}
	obligations := []any{}
	for _, command := range plan.RequiredCommands {
		key := keyString(commandKeyFromCommand(command))
		route := routes[key]
		if route == nil {
			return nil, fmt.Errorf("selective evidence obligation projection missing route for command: %s", describeKey(commandKeyFromCommand(command)))
		}
		receipts := receiptGroups[key]
		evidenceRefs := []string{}
		if routeRefs, ok := route["evidenceRefs"].([]string); ok {
			evidenceRefs = append(evidenceRefs, routeRefs...)
		}
		for _, receipt := range receipts {
			evidenceRefs = append(evidenceRefs, receipt.EvidenceRef)
			evidenceRefs = append(evidenceRefs, receipt.ArtifactRefs...)
		}
		currentness := currentnessDiagnostics[route["obligationId"].(string)]
		if currentness != nil {
			evidenceRefs = append(evidenceRefs, currentness.EvidenceRefs...)
			for _, refs := range currentness.CurrentnessCheckRefs {
				evidenceRefs = append(evidenceRefs, refs...)
			}
			for _, refs := range currentness.ScopeCheckRefs {
				evidenceRefs = append(evidenceRefs, refs...)
			}
		}
		trust := trustDiagnostics[route["obligationId"].(string)]
		if trust != nil {
			evidenceRefs = append(evidenceRefs, trust.EvidenceRefs...)
			evidenceRefs = append(evidenceRefs, trust.ArtifactRefs...)
			if trust.ProvenanceRef != nil {
				evidenceRefs = append(evidenceRefs, *trust.ProvenanceRef)
			}
		}
		evidenceRefs, err = uniqueSortedPaths(evidenceRefs, fmt.Sprintf("selective evidence obligation projection %s evidenceRefs", route["obligationId"]))
		if err != nil {
			return nil, err
		}
		obligations = append(obligations, map[string]any{
			"candidateStates": admit.StringSliceToAny(decisionStates(append(append(selectiveEvidenceStates(receipts), currentnessStates(currentness)...), trustStates(trust)...))),
			"evidenceRefs":    admit.StringSliceToAny(evidenceRefs),
			"nonClaims":       admit.StringSliceToAny(route["nonClaims"].([]string)),
			"obligationClass": route["obligationClass"],
			"obligationId":    route["obligationId"],
			"owner":           route["owner"],
			"proofRouteRef":   route["proofRouteRef"],
			"reason":          route["reason"],
			"requirementId":   route["requirementId"],
		})
	}
	nonClaims, err := sortedTextFromAny(record["nonClaims"], "selective evidence obligation projection nonClaims", false)
	if err != nil {
		return nil, err
	}
	baseNonClaims := []string{
		"Selective evidence obligation projection consumes caller-provided receipt currentness-scope diagnostics only when supplied.",
		"Selective evidence obligation projection consumes caller-provided receipt trust-class diagnostics only when supplied.",
		"Selective evidence obligation projection does not approve merge, release, rollout, or production readiness.",
		"Selective evidence obligation projection does not authenticate producers.",
		"Selective evidence obligation projection does not compute receipt freshness.",
		"Selective evidence obligation projection does not execute commands.",
		"Selective evidence obligation projection does not infer changed scope or live availability.",
		"Selective evidence obligation projection does not own proof-class risk policy or receipt trust policy.",
		"Selective evidence obligation projection maps only command-scoped selective evidence facts.",
	}
	nonClaims = append(baseNonClaims, nonClaims...)
	sort.Strings(nonClaims)
	nonClaims = dedupeStrings(nonClaims)
	return map[string]any{
		"decisionId":    decisionID,
		"nonClaims":     admit.StringSliceToAny(nonClaims),
		"obligations":   obligations,
		"schemaVersion": json.Number("1"),
	}, nil
}

func unsupportedProjectionFailures(plan plan, preexisting []string, producerFailures []string, unexpected []receiptSummary) []string {
	result := []string{}
	for _, failure := range preexisting {
		result = append(result, "preexisting failure: "+failure)
	}
	for _, failure := range plan.Failures {
		result = append(result, "plan failure: "+failure)
	}
	if plan.PlanState == "fail_closed" {
		result = append(result, "plan state is fail_closed")
	}
	for _, receipt := range unexpected {
		result = append(result, "unexpected receipt: "+describeKey(receipt.commandKey))
	}
	for _, failure := range producerFailures {
		result = append(result, "producer admission failure: "+failure)
	}
	sort.Strings(result)
	return result
}

func admitRoute(record map[string]any) (map[string]any, string, error) {
	if err := admit.KnownKeys(record, []string{"command", "commandId", "evidenceRefs", "nonClaims", "obligationClass", "obligationId", "owner", "proofRouteRef", "reason", "requirementId", "sourcePath"}, "selective evidence obligation projection command route"); err != nil {
		return nil, "", err
	}
	commandID, err := admit.RuleID(record["commandId"], "selective evidence obligation projection commandId")
	if err != nil {
		return nil, "", err
	}
	commandText, err := admit.DisplayOnlyCommandText(record["command"], "selective evidence obligation projection command")
	if err != nil {
		return nil, "", err
	}
	sourcePath, err := nullableSourcePath(record["sourcePath"], "selective evidence obligation projection sourcePath")
	if err != nil {
		return nil, "", err
	}
	obligationID, err := admit.RuleID(record["obligationId"], "selective evidence obligation projection obligationId")
	if err != nil {
		return nil, "", err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "selective evidence obligation projection requirementId")
	if err != nil {
		return nil, "", err
	}
	routeRef, err := admit.RuleID(record["proofRouteRef"], "selective evidence obligation projection proofRouteRef")
	if err != nil {
		return nil, "", err
	}
	class, err := admit.Enum(record["obligationClass"], obligationClassSet, "selective evidence obligation projection obligationClass")
	if err != nil {
		return nil, "", err
	}
	owner, err := admit.NonEmptyText(record["owner"], "selective evidence obligation projection owner")
	if err != nil {
		return nil, "", err
	}
	reason, err := admit.NonEmptyText(record["reason"], "selective evidence obligation projection reason")
	if err != nil {
		return nil, "", err
	}
	evidenceRefs, err := sortedPathsFromAny(record["evidenceRefs"], "selective evidence obligation projection evidenceRefs", false)
	if err != nil {
		return nil, "", err
	}
	nonClaims, err := sortedTextFromAny(record["nonClaims"], "selective evidence obligation projection nonClaims", false)
	if err != nil {
		return nil, "", err
	}
	key := keyString(commandKey{ID: commandID, Command: commandText, SourcePath: sourcePath})
	return map[string]any{"commandId": commandID, "command": commandText, "sourcePath": nullableString(sourcePath), "obligationId": obligationID, "requirementId": requirementID, "proofRouteRef": routeRef, "obligationClass": class, "owner": owner, "reason": reason, "evidenceRefs": evidenceRefs, "nonClaims": nonClaims}, key, nil
}

func currentnessDiagnosticsByObligation(raw any, routes map[string]map[string]any, receiptGroups map[string][]receiptSummary) (map[string]*currentnessProjectionDiagnostic, error) {
	if raw == nil {
		return map[string]*currentnessProjectionDiagnostic{}, nil
	}
	_, _, diagnostics, err := receiptcurrentnessscope.ProjectionDiagnostics(raw)
	if err != nil {
		return nil, err
	}
	result := map[string]*currentnessProjectionDiagnostic{}
	for _, diagnostic := range diagnostics {
		obligationID := diagnostic.ObligationID
		route := routes[obligationID]
		if route == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt currentness-scope diagnostic is unscoped: %s", obligationID)
		}
		receipt, err := exactlyOneReceiptForRoute(route, receiptGroups, "receipt currentness-scope diagnostic", obligationID)
		if err != nil {
			return nil, err
		}
		if err := validateDiagnosticRouteBinding(diagnostic.RequirementID, diagnostic.ProofRouteRef, route, "receipt currentness-scope", obligationID); err != nil {
			return nil, err
		}
		if receipt.ProducerReceiptID == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt currentness-scope diagnostic requires producerReceiptId for obligation: %s", obligationID)
		}
		if *receipt.ProducerReceiptID != diagnostic.ReceiptID {
			return nil, fmt.Errorf("selective evidence obligation projection receipt currentness-scope receiptId mismatch for obligation: %s", obligationID)
		}
		result[obligationID] = currentnessProjectionFromDiagnostic(diagnostic)
	}
	missing := missingDiagnosticObligationIDs(routes, receiptGroups, result)
	if len(missing) > 0 {
		return nil, fmt.Errorf("selective evidence obligation projection missing receipt currentness-scope diagnostics for obligations: %s", strings.Join(missing, ", "))
	}
	return result, nil
}

func trustDiagnosticsByObligation(raw any, routes map[string]map[string]any, receiptGroups map[string][]receiptSummary) (map[string]*trustProjectionDiagnostic, error) {
	if raw == nil {
		return map[string]*trustProjectionDiagnostic{}, nil
	}
	_, _, diagnostics, err := receipttrustclass.ProjectionDiagnostics(raw)
	if err != nil {
		return nil, err
	}
	result := map[string]*trustProjectionDiagnostic{}
	for _, diagnostic := range diagnostics {
		obligationID := diagnostic.ObligationID
		route := routes[obligationID]
		if route == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class diagnostic is unscoped: %s", obligationID)
		}
		receipt, err := exactlyOneReceiptForRoute(route, receiptGroups, "receipt trust-class diagnostic", obligationID)
		if err != nil {
			return nil, err
		}
		if err := validateDiagnosticRouteBinding(diagnostic.RequirementID, diagnostic.ProofRouteRef, route, "receipt trust-class", obligationID); err != nil {
			return nil, err
		}
		if receipt.ProducerReceiptID == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class diagnostic requires producerReceiptId for obligation: %s", obligationID)
		}
		if *receipt.ProducerReceiptID != diagnostic.ReceiptID {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class receiptId mismatch for obligation: %s", obligationID)
		}
		if receipt.Status != diagnostic.ReceiptStatus {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class receiptStatus mismatch for obligation: %s", obligationID)
		}
		result[obligationID] = trustProjectionFromDiagnostic(diagnostic)
	}
	missing := missingDiagnosticObligationIDs(routes, receiptGroups, result)
	if len(missing) > 0 {
		return nil, fmt.Errorf("selective evidence obligation projection missing receipt trust-class diagnostics for obligations: %s", strings.Join(missing, ", "))
	}
	return result, nil
}

func currentnessProjectionFromDiagnostic(diagnostic receiptcurrentnessscope.ProjectionDiagnostic) *currentnessProjectionDiagnostic {
	return &currentnessProjectionDiagnostic{
		CurrentnessCheckRefs: copyNestedStrings(diagnostic.CurrentnessCheckRefs),
		DecisionStates:       append([]string{}, diagnostic.DecisionCandidateStates...),
		EvidenceRefs:         append([]string{}, diagnostic.EvidenceRefs...),
		ReceiptID:            diagnostic.ReceiptID,
		RequirementID:        diagnostic.RequirementID,
		ProofRouteRef:        diagnostic.ProofRouteRef,
		ScopeCheckRefs:       copyNestedStrings(diagnostic.ScopeCheckRefs),
	}
}

func trustProjectionFromDiagnostic(diagnostic receipttrustclass.ProjectionDiagnostic) *trustProjectionDiagnostic {
	var provenanceRef *string
	if diagnostic.ProvenanceRef != nil {
		value := *diagnostic.ProvenanceRef
		provenanceRef = &value
	}
	return &trustProjectionDiagnostic{
		ArtifactRefs:   append([]string{}, diagnostic.ArtifactRefs...),
		DecisionStates: append([]string{}, diagnostic.DecisionCandidateStates...),
		EvidenceRefs:   append([]string{}, diagnostic.EvidenceRefs...),
		ProofRouteRef:  diagnostic.ProofRouteRef,
		ProvenanceRef:  provenanceRef,
		ReceiptID:      diagnostic.ReceiptID,
		ReceiptStatus:  diagnostic.ReceiptStatus,
		RequirementID:  diagnostic.RequirementID,
	}
}

func validateDiagnosticRouteBinding(requirementID string, proofRouteRef string, route map[string]any, label string, obligationID string) error {
	if route["requirementId"] != requirementID {
		return fmt.Errorf("selective evidence obligation projection %s requirementId mismatch for obligation: %s", label, obligationID)
	}
	if route["proofRouteRef"] != proofRouteRef {
		return fmt.Errorf("selective evidence obligation projection %s proofRouteRef mismatch for obligation: %s", label, obligationID)
	}
	return nil
}

func copyNestedStrings(values [][]string) [][]string {
	result := make([][]string, 0, len(values))
	for _, value := range values {
		result = append(result, append([]string{}, value...))
	}
	return result
}

func exactlyOneReceiptForRoute(route map[string]any, receiptGroups map[string][]receiptSummary, label string, obligationID string) (receiptSummary, error) {
	key := routeKey(route)
	receipts := receiptGroups[keyString(key)]
	if len(receipts) != 1 {
		return receiptSummary{}, fmt.Errorf("selective evidence obligation projection %s is not anchorable to exactly one selective receipt: %s", label, obligationID)
	}
	return receipts[0], nil
}

func missingDiagnosticObligationIDs[T any](routes map[string]map[string]any, receiptGroups map[string][]receiptSummary, diagnostics map[string]T) []string {
	missing := []string{}
	for obligationID, route := range routes {
		if len(receiptGroups[keyString(routeKey(route))]) == 1 {
			if _, ok := diagnostics[obligationID]; !ok {
				missing = append(missing, obligationID)
			}
		}
	}
	sort.Strings(missing)
	return missing
}

func routeKey(route map[string]any) commandKey {
	var source *string
	if value, ok := route["sourcePath"].(string); ok {
		source = &value
	}
	return commandKey{ID: route["commandId"].(string), Command: route["command"].(string), SourcePath: source}
}

func selectiveEvidenceStates(receipts []receiptSummary) []string {
	if len(receipts) == 0 {
		return []string{"missing_receipt"}
	}
	if len(receipts) > 1 {
		return []string{"invalid_receipt"}
	}
	switch receipts[0].Status {
	case "failed":
		return []string{"failed"}
	case "blocked":
		return []string{"blocked_missing_precondition"}
	case "not_run":
		return []string{"missing_receipt"}
	default:
		return []string{"satisfied"}
	}
}

func currentnessStates(diagnostic *currentnessProjectionDiagnostic) []string {
	if diagnostic == nil {
		return []string{"unknown_scope"}
	}
	return diagnostic.DecisionStates
}

func trustStates(diagnostic *trustProjectionDiagnostic) []string {
	if diagnostic == nil {
		return []string{"invalid_producer"}
	}
	return diagnostic.DecisionStates
}

func decisionStates(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(left int, right int) bool {
		return proofvocab.ObligationDecisionStateRank(result[left]) < proofvocab.ObligationDecisionStateRank(result[right])
	})
	return result
}
