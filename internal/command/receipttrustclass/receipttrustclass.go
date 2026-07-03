package receipttrustclass

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.receipt-trust-class-admission"

var producerAdmissionLevels = proofvocab.MergeSatisfactionClasses()
var producerAdmissionLevelSet = proofvocab.MergeSatisfactionClassSet()

var receiptStatuses = proofvocab.ReceiptStatuses()
var receiptStatusSet = proofvocab.ReceiptStatusSet()

var boundaryNonClaims = []string{
	"Receipt trust-class admission does not approve merge, release, rollout, or production readiness.",
	"Receipt trust-class admission does not authenticate producer identity.",
	"Receipt trust-class admission does not compute receipt freshness.",
	"Receipt trust-class admission does not execute native commands or prove command semantics.",
	"Receipt trust-class admission does not own proof-class or risk policy.",
}

type trustClass struct {
	AllowedProducerAdmissionLevels []string
	AllowedReceiptStatuses         []string
	NonClaims                      []string
	Rank                           int
	RequiresArtifactRefs           bool
	RequiresProvenanceRef          bool
	TrustClassID                   string
}

type proofClass struct {
	AllowedEnvironmentClasses []string
	AllowedReceiptKinds       []string
	MinimumTrustClassID       string
	NonClaims                 []string
	Owner                     string
	ProofClassID              string
	Rationale                 string
	RiskClass                 string
}

type obligationReceipt struct {
	ArtifactRefs           []string
	EnvironmentClass       string
	EvidenceRefs           []string
	NonClaims              []string
	ObligationID           string
	ProducerAdmissionClass string
	ProofClassID           string
	ProofRouteRef          string
	ProvenanceRef          *string
	ReceiptID              string
	ReceiptKind            string
	ReceiptStatus          string
	RequirementID          string
	TrustClassID           string
}

type diagnostic struct {
	obligationReceipt
	ActualTrustRank         *int
	DecisionCandidateStates []string
	MinimumTrustClassID     *string
	MinimumTrustRank        *int
	RiskClass               *string
	StructuralFindings      []string
}

type admittedInput struct {
	NonClaims          []string
	ObligationReceipts []obligationReceipt
	PolicyID           string
	ProofClasses       []proofClass
	TrustClasses       []trustClass
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	trustClassesByID := map[string]trustClass{}
	for _, item := range input.TrustClasses {
		trustClassesByID[item.TrustClassID] = item
	}
	proofClassesByID := map[string]proofClass{}
	for _, item := range input.ProofClasses {
		proofClassesByID[item.ProofClassID] = item
	}
	diagnostics := make([]diagnostic, 0, len(input.ObligationReceipts))
	for _, obligation := range input.ObligationReceipts {
		diagnostics = append(diagnostics, evaluateObligationTrust(obligation, trustClassesByID, proofClassesByID))
	}
	failedObligationIDs := []string{}
	for _, item := range diagnostics {
		if len(item.StructuralFindings) > 0 {
			failedObligationIDs = append(failedObligationIDs, item.ObligationID)
		}
	}
	state := "passed"
	if len(failedObligationIDs) > 0 {
		state = "failed"
	}
	nonClaims, err := sortedText(append(append([]string{}, boundaryNonClaims...), input.NonClaims...), "receipt trust-class nonClaims", false)
	if err != nil {
		return report.Record{}, 1, err
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.PolicyID,
		State:         state,
		Summary: map[string]any{
			"failedObligationCount":  len(failedObligationIDs),
			"obligationReceiptCount": len(diagnostics),
			"proofClassCount":        len(input.ProofClasses),
			"trustClassCount":        len(input.TrustClasses),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failedObligationIds", Value: admit.StringSliceToAny(failedObligationIDs)},
			{Key: "obligationReceiptTrust", Value: reportDiagnostics(diagnostics)},
		},
		RuleResults: ruleResults(diagnostics),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("receipt trust-class input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "obligationReceipts", "policyId", "proofClasses", "schemaVersion", "trustClasses"}, "receipt trust-class input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("receipt trust-class schemaVersion must be 1")
	}
	trustClasses, err := trustClassArray(record["trustClasses"])
	if err != nil {
		return admittedInput{}, err
	}
	trustClassIDs := map[string]struct{}{}
	for _, item := range trustClasses {
		trustClassIDs[item.TrustClassID] = struct{}{}
	}
	proofClasses, err := proofClassArray(record["proofClasses"], trustClassIDs)
	if err != nil {
		return admittedInput{}, err
	}
	obligationReceipts, err := obligationArray(record["obligationReceipts"])
	if err != nil {
		return admittedInput{}, err
	}
	policyID, err := admit.RuleID(record["policyId"], "receipt trust-class policyId")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt trust-class nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		NonClaims:          nonClaims,
		ObligationReceipts: obligationReceipts,
		PolicyID:           policyID,
		ProofClasses:       proofClasses,
		TrustClasses:       trustClasses,
	}, nil
}

func trustClassArray(raw any) ([]trustClass, error) {
	records, err := nonEmptyRecords(raw, "receipt trust-class trustClasses")
	if err != nil {
		return nil, err
	}
	result := make([]trustClass, 0, len(records))
	for _, record := range records {
		item, err := admitTrustClass(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].TrustClassID < result[right].TrustClassID
	})
	ids := make([]string, 0, len(result))
	ranks := map[int]struct{}{}
	for _, item := range result {
		ids = append(ids, item.TrustClassID)
		ranks[item.Rank] = struct{}{}
	}
	if err := preserveSortedUnique(ids, "receipt trust-class trustClass ids", false); err != nil {
		return nil, err
	}
	if len(ranks) != len(result) {
		return nil, fmt.Errorf("receipt trust-class ranks must be unique")
	}
	return result, nil
}

func admitTrustClass(record map[string]any) (trustClass, error) {
	if err := admit.KnownKeys(record, []string{"allowedProducerAdmissionLevels", "allowedReceiptStatuses", "nonClaims", "rank", "requiresArtifactRefs", "requiresProvenanceRef", "trustClassId"}, "receipt trust-class trustClass"); err != nil {
		return trustClass{}, err
	}
	requiresProvenanceRef, err := admit.Bool(record["requiresProvenanceRef"], "receipt trust-class requiresProvenanceRef")
	if err != nil {
		return trustClass{}, err
	}
	requiresArtifactRefs, err := admit.Bool(record["requiresArtifactRefs"], "receipt trust-class requiresArtifactRefs")
	if err != nil {
		return trustClass{}, err
	}
	trustClassID, err := admit.RuleID(record["trustClassId"], "receipt trust-class trustClassId")
	if err != nil {
		return trustClass{}, err
	}
	rank, err := admit.PositiveInteger(record["rank"], "receipt trust-class rank")
	if err != nil {
		return trustClass{}, err
	}
	allowedProducerAdmissionLevels, err := enumArray(record["allowedProducerAdmissionLevels"], producerAdmissionLevelSet, producerAdmissionLevels, "receipt trust-class allowedProducerAdmissionLevels")
	if err != nil {
		return trustClass{}, err
	}
	allowedReceiptStatuses, err := enumArray(record["allowedReceiptStatuses"], receiptStatusSet, receiptStatuses, "receipt trust-class allowedReceiptStatuses")
	if err != nil {
		return trustClass{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt trust-class trustClass nonClaims", false)
	if err != nil {
		return trustClass{}, err
	}
	return trustClass{
		AllowedProducerAdmissionLevels: allowedProducerAdmissionLevels,
		AllowedReceiptStatuses:         allowedReceiptStatuses,
		NonClaims:                      nonClaims,
		Rank:                           rank,
		RequiresArtifactRefs:           requiresArtifactRefs,
		RequiresProvenanceRef:          requiresProvenanceRef,
		TrustClassID:                   trustClassID,
	}, nil
}

func proofClassArray(raw any, trustClassIDs map[string]struct{}) ([]proofClass, error) {
	records, err := nonEmptyRecords(raw, "receipt trust-class proofClasses")
	if err != nil {
		return nil, err
	}
	result := make([]proofClass, 0, len(records))
	for _, record := range records {
		item, err := admitProofClass(record, trustClassIDs)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ProofClassID < result[right].ProofClassID
	})
	ids := make([]string, 0, len(result))
	for _, item := range result {
		ids = append(ids, item.ProofClassID)
	}
	if err := preserveSortedUnique(ids, "receipt trust-class proofClass ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitProofClass(record map[string]any, trustClassIDs map[string]struct{}) (proofClass, error) {
	if err := admit.KnownKeys(record, []string{"allowedEnvironmentClasses", "allowedReceiptKinds", "minimumTrustClassId", "nonClaims", "owner", "proofClassId", "rationale", "riskClass"}, "receipt trust-class proofClass"); err != nil {
		return proofClass{}, err
	}
	minimumTrustClassID, err := admit.RuleID(record["minimumTrustClassId"], "receipt trust-class minimumTrustClassId")
	if err != nil {
		return proofClass{}, err
	}
	if _, ok := trustClassIDs[minimumTrustClassID]; !ok {
		return proofClass{}, fmt.Errorf("receipt trust-class proofClass minimumTrustClassId is unknown: %s", minimumTrustClassID)
	}
	proofClassID, err := admit.RuleID(record["proofClassId"], "receipt trust-class proofClassId")
	if err != nil {
		return proofClass{}, err
	}
	riskClass, err := admit.RuleID(record["riskClass"], "receipt trust-class riskClass")
	if err != nil {
		return proofClass{}, err
	}
	allowedReceiptKinds, err := sortedRuleIDs(record["allowedReceiptKinds"], "receipt trust-class allowedReceiptKinds")
	if err != nil {
		return proofClass{}, err
	}
	allowedEnvironmentClasses, err := sortedRuleIDs(record["allowedEnvironmentClasses"], "receipt trust-class allowedEnvironmentClasses")
	if err != nil {
		return proofClass{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], "receipt trust-class proofClass owner")
	if err != nil {
		return proofClass{}, err
	}
	rationale, err := admit.NonEmptyText(record["rationale"], "receipt trust-class proofClass rationale")
	if err != nil {
		return proofClass{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt trust-class proofClass nonClaims", false)
	if err != nil {
		return proofClass{}, err
	}
	return proofClass{
		AllowedEnvironmentClasses: allowedEnvironmentClasses,
		AllowedReceiptKinds:       allowedReceiptKinds,
		MinimumTrustClassID:       minimumTrustClassID,
		NonClaims:                 nonClaims,
		Owner:                     owner,
		ProofClassID:              proofClassID,
		Rationale:                 rationale,
		RiskClass:                 riskClass,
	}, nil
}

func obligationArray(raw any) ([]obligationReceipt, error) {
	records, err := nonEmptyRecords(raw, "receipt trust-class obligationReceipts")
	if err != nil {
		return nil, err
	}
	result := make([]obligationReceipt, 0, len(records))
	for _, record := range records {
		item, err := admitObligation(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return compareObligations(result[left], result[right]) < 0
	})
	ids := make([]string, 0, len(result))
	for _, item := range result {
		ids = append(ids, item.ObligationID)
	}
	if err := preserveSortedUnique(ids, "receipt trust-class obligation ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitObligation(record map[string]any) (obligationReceipt, error) {
	if err := admit.KnownKeys(record, []string{"artifactRefs", "environmentClass", "evidenceRefs", "nonClaims", "obligationId", "producerAdmissionClass", "proofClassId", "proofRouteRef", "provenanceRef", "receiptId", "receiptKind", "receiptStatus", "requirementId", "trustClassId"}, "receipt trust-class obligation receipt"); err != nil {
		return obligationReceipt{}, err
	}
	obligationID, err := admit.RuleID(record["obligationId"], "receipt trust-class obligationId")
	if err != nil {
		return obligationReceipt{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "receipt trust-class requirementId")
	if err != nil {
		return obligationReceipt{}, err
	}
	proofRouteRef, err := admit.RuleID(record["proofRouteRef"], "receipt trust-class proofRouteRef")
	if err != nil {
		return obligationReceipt{}, err
	}
	proofClassID, err := admit.RuleID(record["proofClassId"], "receipt trust-class proofClassId")
	if err != nil {
		return obligationReceipt{}, err
	}
	receiptID, err := admit.RuleID(record["receiptId"], "receipt trust-class receiptId")
	if err != nil {
		return obligationReceipt{}, err
	}
	receiptKind, err := admit.RuleID(record["receiptKind"], "receipt trust-class receiptKind")
	if err != nil {
		return obligationReceipt{}, err
	}
	environmentClass, err := admit.RuleID(record["environmentClass"], "receipt trust-class environmentClass")
	if err != nil {
		return obligationReceipt{}, err
	}
	receiptStatus, err := enum(record["receiptStatus"], receiptStatusSet, receiptStatuses, "receipt trust-class receiptStatus")
	if err != nil {
		return obligationReceipt{}, err
	}
	producerAdmissionClass, err := enum(record["producerAdmissionClass"], producerAdmissionLevelSet, producerAdmissionLevels, "receipt trust-class producerAdmissionClass")
	if err != nil {
		return obligationReceipt{}, err
	}
	trustClassID, err := admit.RuleID(record["trustClassId"], "receipt trust-class trustClassId")
	if err != nil {
		return obligationReceipt{}, err
	}
	provenanceRef, err := optionalPath(record, "provenanceRef", "receipt trust-class provenanceRef")
	if err != nil {
		return obligationReceipt{}, err
	}
	artifactRefs, err := sortedPathsFromRaw(record["artifactRefs"], "receipt trust-class artifactRefs", true)
	if err != nil {
		return obligationReceipt{}, err
	}
	evidenceRefs, err := sortedPathsFromRaw(record["evidenceRefs"], "receipt trust-class evidenceRefs", false)
	if err != nil {
		return obligationReceipt{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt trust-class obligation nonClaims", false)
	if err != nil {
		return obligationReceipt{}, err
	}
	return obligationReceipt{
		ArtifactRefs:           artifactRefs,
		EnvironmentClass:       environmentClass,
		EvidenceRefs:           evidenceRefs,
		NonClaims:              nonClaims,
		ObligationID:           obligationID,
		ProducerAdmissionClass: producerAdmissionClass,
		ProofClassID:           proofClassID,
		ProofRouteRef:          proofRouteRef,
		ProvenanceRef:          provenanceRef,
		ReceiptID:              receiptID,
		ReceiptKind:            receiptKind,
		ReceiptStatus:          receiptStatus,
		RequirementID:          requirementID,
		TrustClassID:           trustClassID,
	}, nil
}

func evaluateObligationTrust(obligation obligationReceipt, trustClassesByID map[string]trustClass, proofClassesByID map[string]proofClass) diagnostic {
	selectedTrustClass, trustClassOK := trustClassesByID[obligation.TrustClassID]
	proofClass, proofClassOK := proofClassesByID[obligation.ProofClassID]
	var minimumTrustClass trustClass
	minimumTrustClassOK := false
	if proofClassOK {
		minimumTrustClass, minimumTrustClassOK = trustClassesByID[proofClass.MinimumTrustClassID]
	}
	findings := []string{}
	decisionCandidateStates := map[string]struct{}{}
	if !proofClassOK {
		findings = append(findings, fmt.Sprintf("obligation %s references unknown proofClassId: %s", obligation.ObligationID, obligation.ProofClassID))
		decisionCandidateStates["invalid_producer"] = struct{}{}
	}
	if !trustClassOK {
		findings = append(findings, fmt.Sprintf("obligation %s references unknown trustClassId: %s", obligation.ObligationID, obligation.TrustClassID))
		decisionCandidateStates["invalid_producer"] = struct{}{}
	}
	if proofClassOK {
		if !contains(proofClass.AllowedReceiptKinds, obligation.ReceiptKind) {
			findings = append(findings, fmt.Sprintf("obligation %s uses receiptKind %s outside proof class %s", obligation.ObligationID, obligation.ReceiptKind, proofClass.ProofClassID))
			decisionCandidateStates["invalid_receipt"] = struct{}{}
		}
		if !contains(proofClass.AllowedEnvironmentClasses, obligation.EnvironmentClass) {
			findings = append(findings, fmt.Sprintf("obligation %s uses environmentClass %s outside proof class %s", obligation.ObligationID, obligation.EnvironmentClass, proofClass.ProofClassID))
			decisionCandidateStates["invalid_receipt"] = struct{}{}
		}
	}
	if trustClassOK {
		if !contains(selectedTrustClass.AllowedProducerAdmissionLevels, obligation.ProducerAdmissionClass) {
			findings = append(findings, fmt.Sprintf("obligation %s uses producerAdmissionClass %s outside trust class %s", obligation.ObligationID, obligation.ProducerAdmissionClass, selectedTrustClass.TrustClassID))
			decisionCandidateStates["invalid_producer"] = struct{}{}
		}
		if !contains(selectedTrustClass.AllowedReceiptStatuses, obligation.ReceiptStatus) {
			findings = append(findings, fmt.Sprintf("obligation %s uses receiptStatus %s outside trust class %s", obligation.ObligationID, obligation.ReceiptStatus, selectedTrustClass.TrustClassID))
			decisionCandidateStates["invalid_receipt"] = struct{}{}
		}
		if selectedTrustClass.RequiresProvenanceRef && obligation.ProvenanceRef == nil {
			findings = append(findings, fmt.Sprintf("obligation %s requires provenanceRef for trust class %s", obligation.ObligationID, selectedTrustClass.TrustClassID))
			decisionCandidateStates["invalid_receipt"] = struct{}{}
		}
		if selectedTrustClass.RequiresArtifactRefs && len(obligation.ArtifactRefs) == 0 {
			findings = append(findings, fmt.Sprintf("obligation %s requires artifactRefs for trust class %s", obligation.ObligationID, selectedTrustClass.TrustClassID))
			decisionCandidateStates["invalid_receipt"] = struct{}{}
		}
	}
	if trustClassOK && minimumTrustClassOK && selectedTrustClass.Rank < minimumTrustClass.Rank {
		findings = append(findings, fmt.Sprintf("obligation %s trust class %s rank %d is below minimum %s rank %d", obligation.ObligationID, selectedTrustClass.TrustClassID, selectedTrustClass.Rank, minimumTrustClass.TrustClassID, minimumTrustClass.Rank))
		decisionCandidateStates["invalid_producer"] = struct{}{}
	}
	sort.Strings(findings)
	var actualTrustRank *int
	if trustClassOK {
		value := selectedTrustClass.Rank
		actualTrustRank = &value
	}
	var minimumTrustClassID *string
	var minimumTrustRank *int
	var riskClass *string
	if proofClassOK {
		value := proofClass.MinimumTrustClassID
		minimumTrustClassID = &value
		risk := proofClass.RiskClass
		riskClass = &risk
	}
	if minimumTrustClassOK {
		value := minimumTrustClass.Rank
		minimumTrustRank = &value
	}
	return diagnostic{
		obligationReceipt:       obligation,
		ActualTrustRank:         actualTrustRank,
		DecisionCandidateStates: sortDecisionCandidateStates(decisionCandidateStates),
		MinimumTrustClassID:     minimumTrustClassID,
		MinimumTrustRank:        minimumTrustRank,
		RiskClass:               riskClass,
		StructuralFindings:      findings,
	}
}

func ruleResults(diagnostics []diagnostic) []report.RuleResult {
	results := make([]report.RuleResult, 0, len(diagnostics))
	for _, item := range diagnostics {
		status := "passed"
		message := fmt.Sprintf("obligation %s has admitted receipt trust class", item.ObligationID)
		if len(item.StructuralFindings) > 0 {
			status = "failed"
			message = fmt.Sprintf("obligation %s has invalid receipt trust class", item.ObligationID)
		}
		results = append(results, report.RuleResult{
			RuleID:  "proofkit.receipt-trust-class." + item.ObligationID,
			Status:  status,
			Message: message,
			Diagnostics: []report.Diagnostic{
				{Key: "receiptTrustClass", Value: reportDiagnostic(item)},
			},
		})
	}
	return results
}

func reportDiagnostics(diagnostics []diagnostic) []any {
	result := make([]any, 0, len(diagnostics))
	for _, item := range diagnostics {
		result = append(result, reportDiagnostic(item))
	}
	return result
}

func reportDiagnostic(item diagnostic) map[string]any {
	return map[string]any{
		"actualTrustRank":         nullableInt(item.ActualTrustRank),
		"decisionCandidateStates": admit.StringSliceToAny(item.DecisionCandidateStates),
		"environmentClass":        item.EnvironmentClass,
		"minimumTrustClassId":     nullableString(item.MinimumTrustClassID),
		"minimumTrustRank":        nullableInt(item.MinimumTrustRank),
		"obligationId":            item.ObligationID,
		"producerAdmissionClass":  item.ProducerAdmissionClass,
		"proofClassId":            item.ProofClassID,
		"proofRouteRef":           item.ProofRouteRef,
		"receiptId":               item.ReceiptID,
		"receiptKind":             item.ReceiptKind,
		"receiptStatus":           item.ReceiptStatus,
		"requirementId":           item.RequirementID,
		"riskClass":               nullableString(item.RiskClass),
		"structuralFindings":      admit.StringSliceToAny(item.StructuralFindings),
		"trustClassId":            item.TrustClassID,
	}
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	values, err := sortedTextFromRaw(raw, context, false)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		ruleID, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, ruleID)
	}
	return result, nil
}

func sortedPathsFromRaw(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		path, err := admit.SafeRepoRelativePath(text, context)
		if err != nil {
			return nil, err
		}
		result = append(result, path)
	}
	return sortedText(result, context, allowEmpty)
}

func sortedTextFromRaw(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return sortedText(result, context, allowEmpty)
}

func enumArray(raw any, allowed map[string]struct{}, ordered []string, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		enumValue, err := enum(value, allowed, ordered, context)
		if err != nil {
			return nil, err
		}
		result = append(result, enumValue)
	}
	sort.Strings(result)
	if err := preserveSortedUnique(result, context, false); err != nil {
		return nil, err
	}
	return result, nil
}

func sortedText(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	sort.Strings(values)
	if err := preserveSortedUnique(values, context, allowEmpty); err != nil {
		return nil, err
	}
	return values, nil
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must not be empty", context)
	}
	for index := range values {
		if index > 0 && (values[index-1] == values[index] || values[index-1] > values[index]) {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func nonEmptyRecords(raw any, context string) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty array", context)
	}
	result := make([]map[string]any, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		result = append(result, record)
	}
	return result, nil
}

func optionalPath(record map[string]any, key string, context string) (*string, error) {
	raw, ok := record[key]
	if !ok {
		return nil, fmt.Errorf("%s must be a string or null", context)
	}
	if raw == nil {
		return nil, nil
	}
	text, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be a string or null", context)
	}
	path, err := admit.SafeRepoRelativePath(text, context)
	if err != nil {
		return nil, err
	}
	return &path, nil
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered, ", "))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered, ", "))
	}
	return value, nil
}

func sortDecisionCandidateStates(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left int, right int) bool {
		return proofvocab.ObligationDecisionStateRank(result[left]) < proofvocab.ObligationDecisionStateRank(result[right])
	})
	return result
}

func compareObligations(left obligationReceipt, right obligationReceipt) int {
	if left.ObligationID < right.ObligationID {
		return -1
	}
	if left.ObligationID > right.ObligationID {
		return 1
	}
	if left.ReceiptID < right.ReceiptID {
		return -1
	}
	if left.ReceiptID > right.ReceiptID {
		return 1
	}
	return 0
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func join(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += separator + value
	}
	return result
}
