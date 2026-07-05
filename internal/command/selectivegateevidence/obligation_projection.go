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
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
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
	record, _, err := receiptcurrentnessscope.Build(raw)
	if err != nil {
		return nil, err
	}
	rawByObligation, err := rawObligationRecords(raw, "receiptCurrentnessScopeAdmission", "obligationReceipts")
	if err != nil {
		return nil, err
	}
	diagnostics, err := diagnosticsByKey(record, "receiptCurrentnessScope")
	if err != nil {
		return nil, err
	}
	result := map[string]*currentnessProjectionDiagnostic{}
	for _, diagnostic := range diagnostics {
		obligationID, err := requiredString(diagnostic["obligationId"], "receipt currentness-scope obligationId")
		if err != nil {
			return nil, err
		}
		route := routes[obligationID]
		if route == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt currentness-scope diagnostic is unscoped: %s", obligationID)
		}
		receipt, err := exactlyOneReceiptForRoute(route, receiptGroups, "receipt currentness-scope diagnostic", obligationID)
		if err != nil {
			return nil, err
		}
		if err := validateDiagnosticRouteBinding(diagnostic, route, "receipt currentness-scope", obligationID); err != nil {
			return nil, err
		}
		if receipt.ProducerReceiptID == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt currentness-scope diagnostic requires producerReceiptId for obligation: %s", obligationID)
		}
		receiptID, err := requiredString(diagnostic["receiptId"], "receipt currentness-scope receiptId")
		if err != nil {
			return nil, err
		}
		if *receipt.ProducerReceiptID != receiptID {
			return nil, fmt.Errorf("selective evidence obligation projection receipt currentness-scope receiptId mismatch for obligation: %s", obligationID)
		}
		rawRecord := rawByObligation[obligationID]
		if rawRecord == nil {
			return nil, fmt.Errorf("selective evidence obligation projection missing receipt currentness-scope diagnostics for obligations: %s", obligationID)
		}
		projection, err := currentnessProjectionFromRaw(rawRecord, diagnostic)
		if err != nil {
			return nil, err
		}
		result[obligationID] = projection
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
	record, _, err := receipttrustclass.Build(raw)
	if err != nil {
		return nil, err
	}
	rawByObligation, err := rawObligationRecords(raw, "receiptTrustClassAdmission", "obligationReceipts")
	if err != nil {
		return nil, err
	}
	diagnostics, err := diagnosticsByKey(record, "obligationReceiptTrust")
	if err != nil {
		return nil, err
	}
	result := map[string]*trustProjectionDiagnostic{}
	for _, diagnostic := range diagnostics {
		obligationID, err := requiredString(diagnostic["obligationId"], "receipt trust-class obligationId")
		if err != nil {
			return nil, err
		}
		route := routes[obligationID]
		if route == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class diagnostic is unscoped: %s", obligationID)
		}
		receipt, err := exactlyOneReceiptForRoute(route, receiptGroups, "receipt trust-class diagnostic", obligationID)
		if err != nil {
			return nil, err
		}
		if err := validateDiagnosticRouteBinding(diagnostic, route, "receipt trust-class", obligationID); err != nil {
			return nil, err
		}
		if receipt.ProducerReceiptID == nil {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class diagnostic requires producerReceiptId for obligation: %s", obligationID)
		}
		receiptID, err := requiredString(diagnostic["receiptId"], "receipt trust-class receiptId")
		if err != nil {
			return nil, err
		}
		if *receipt.ProducerReceiptID != receiptID {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class receiptId mismatch for obligation: %s", obligationID)
		}
		status, err := requiredString(diagnostic["receiptStatus"], "receipt trust-class receiptStatus")
		if err != nil {
			return nil, err
		}
		if receipt.Status != status {
			return nil, fmt.Errorf("selective evidence obligation projection receipt trust-class receiptStatus mismatch for obligation: %s", obligationID)
		}
		rawRecord := rawByObligation[obligationID]
		if rawRecord == nil {
			return nil, fmt.Errorf("selective evidence obligation projection missing receipt trust-class diagnostics for obligations: %s", obligationID)
		}
		projection, err := trustProjectionFromRaw(rawRecord, diagnostic)
		if err != nil {
			return nil, err
		}
		result[obligationID] = projection
	}
	missing := missingDiagnosticObligationIDs(routes, receiptGroups, result)
	if len(missing) > 0 {
		return nil, fmt.Errorf("selective evidence obligation projection missing receipt trust-class diagnostics for obligations: %s", strings.Join(missing, ", "))
	}
	return result, nil
}

func currentnessProjectionFromRaw(raw map[string]any, diagnostic map[string]any) (*currentnessProjectionDiagnostic, error) {
	evidenceRefs, err := sortedPathsFromAny(raw["evidenceRefs"], "selective evidence obligation projection receipt currentness-scope evidenceRefs", false)
	if err != nil {
		return nil, err
	}
	currentnessCheckRefs, err := checkEvidenceRefs(raw["currentnessChecks"], "selective evidence obligation projection receipt currentness-scope currentnessChecks")
	if err != nil {
		return nil, err
	}
	scopeCheckRefs, err := checkEvidenceRefs(raw["scopeChecks"], "selective evidence obligation projection receipt currentness-scope scopeChecks")
	if err != nil {
		return nil, err
	}
	states, err := stringSlice(diagnostic["decisionCandidateStates"], "receipt currentness-scope decisionCandidateStates")
	if err != nil {
		return nil, err
	}
	receiptID, err := requiredString(diagnostic["receiptId"], "receipt currentness-scope receiptId")
	if err != nil {
		return nil, err
	}
	requirementID, err := requiredString(diagnostic["requirementId"], "receipt currentness-scope requirementId")
	if err != nil {
		return nil, err
	}
	routeRef, err := requiredString(diagnostic["proofRouteRef"], "receipt currentness-scope proofRouteRef")
	if err != nil {
		return nil, err
	}
	return &currentnessProjectionDiagnostic{CurrentnessCheckRefs: currentnessCheckRefs, DecisionStates: states, EvidenceRefs: evidenceRefs, ReceiptID: receiptID, RequirementID: requirementID, ProofRouteRef: routeRef, ScopeCheckRefs: scopeCheckRefs}, nil
}

func trustProjectionFromRaw(raw map[string]any, diagnostic map[string]any) (*trustProjectionDiagnostic, error) {
	evidenceRefs, err := sortedPathsFromAny(raw["evidenceRefs"], "selective evidence obligation projection receipt trust-class evidenceRefs", false)
	if err != nil {
		return nil, err
	}
	artifactRefs, err := sortedPathsFromAny(raw["artifactRefs"], "selective evidence obligation projection receipt trust-class artifactRefs", true)
	if err != nil {
		return nil, err
	}
	var provenanceRef *string
	if raw["provenanceRef"] != nil {
		value, err := safePathAny(raw["provenanceRef"], "selective evidence obligation projection receipt trust-class provenanceRef")
		if err != nil {
			return nil, err
		}
		provenanceRef = &value
	}
	states, err := stringSlice(diagnostic["decisionCandidateStates"], "receipt trust-class decisionCandidateStates")
	if err != nil {
		return nil, err
	}
	receiptID, err := requiredString(diagnostic["receiptId"], "receipt trust-class receiptId")
	if err != nil {
		return nil, err
	}
	receiptStatus, err := requiredString(diagnostic["receiptStatus"], "receipt trust-class receiptStatus")
	if err != nil {
		return nil, err
	}
	requirementID, err := requiredString(diagnostic["requirementId"], "receipt trust-class requirementId")
	if err != nil {
		return nil, err
	}
	routeRef, err := requiredString(diagnostic["proofRouteRef"], "receipt trust-class proofRouteRef")
	if err != nil {
		return nil, err
	}
	return &trustProjectionDiagnostic{ArtifactRefs: artifactRefs, DecisionStates: states, EvidenceRefs: evidenceRefs, ProofRouteRef: routeRef, ProvenanceRef: provenanceRef, ReceiptID: receiptID, ReceiptStatus: receiptStatus, RequirementID: requirementID}, nil
}

func validateDiagnosticRouteBinding(diagnostic map[string]any, route map[string]any, label string, obligationID string) error {
	requirementID, err := requiredString(diagnostic["requirementId"], label+" requirementId")
	if err != nil {
		return err
	}
	if route["requirementId"] != requirementID {
		return fmt.Errorf("selective evidence obligation projection %s requirementId mismatch for obligation: %s", label, obligationID)
	}
	routeRef, err := requiredString(diagnostic["proofRouteRef"], label+" proofRouteRef")
	if err != nil {
		return err
	}
	if route["proofRouteRef"] != routeRef {
		return fmt.Errorf("selective evidence obligation projection %s proofRouteRef mismatch for obligation: %s", label, obligationID)
	}
	return nil
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

func rawObligationRecords(raw any, rootContext string, field string) (map[string]map[string]any, error) {
	root, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", rootContext)
	}
	records, err := arrayOfRecords(root[field], rootContext+" "+field)
	if err != nil {
		return nil, err
	}
	result := map[string]map[string]any{}
	for _, record := range records {
		obligationID, err := admit.RuleID(record["obligationId"], rootContext+" obligationId")
		if err != nil {
			return nil, err
		}
		if _, ok := result[obligationID]; ok {
			return nil, fmt.Errorf("%s obligation ids must be sorted and unique", rootContext)
		}
		result[obligationID] = record
	}
	return result, nil
}

func diagnosticsByKey(record report.Record, key string) ([]map[string]any, error) {
	for _, diagnostic := range record.Diagnostics {
		if diagnostic.Key != key {
			continue
		}
		values, ok := diagnostic.Value.([]any)
		if !ok {
			return nil, fmt.Errorf("%s diagnostics must be an array", key)
		}
		result := make([]map[string]any, 0, len(values))
		for _, value := range values {
			item, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s diagnostics must contain objects", key)
			}
			result = append(result, item)
		}
		return result, nil
	}
	return nil, fmt.Errorf("%s diagnostics are missing", key)
}

func checkEvidenceRefs(raw any, context string) ([][]string, error) {
	records, err := arrayOfRecords(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([][]string, 0, len(records))
	for _, record := range records {
		refs, err := sortedPathsFromAny(record["evidenceRefs"], context+" evidenceRefs", false)
		if err != nil {
			return nil, err
		}
		result = append(result, refs)
	}
	return result, nil
}

func requiredString(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s must be non-empty text", context)
	}
	return value, nil
}

func stringSlice(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("%s must contain non-empty text", context)
		}
		result = append(result, text)
	}
	return result, nil
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
