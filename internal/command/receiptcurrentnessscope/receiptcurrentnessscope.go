package receiptcurrentnessscope

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.receipt-currentness-scope-admission"

var scopeAdmissionStates = []string{
	"admitted_current_scope",
	"not_admitted_current_scope",
	"not_applicable",
	"unknown_current_scope",
}
var scopeAdmissionStateSet = toSet(scopeAdmissionStates)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

var boundaryNonClaims = []string{
	"Receipt currentness-scope admission does not approve merge, release, rollout, or production readiness.",
	"Receipt currentness-scope admission does not authenticate producer identity.",
	"Receipt currentness-scope admission does not compute time-based receipt freshness.",
	"Receipt currentness-scope admission does not discover current repository facts.",
	"Receipt currentness-scope admission does not execute native commands or prove command semantics.",
}

type currentnessCheck struct {
	CheckClass     string
	CheckID        string
	CurrentDigest  string
	EvidenceRefs   []string
	NonClaims      []string
	RecordedDigest string
}

type scopeCheck struct {
	AdmissionState      string
	CheckID             string
	CurrentScopeDigest  *string
	EvidenceRefs        []string
	NonClaims           []string
	Reason              string
	RecordedScopeDigest *string
	ScopeClass          string
}

type obligationReceipt struct {
	CurrentnessChecks []currentnessCheck
	EvidenceRefs      []string
	NonClaims         []string
	ObligationID      string
	Owner             string
	ProofRouteRef     string
	Reason            string
	ReceiptID         string
	RequirementID     string
	ScopeChecks       []scopeCheck
}

type diagnostic struct {
	obligationReceipt
	CurrentnessFindings     []string
	DecisionCandidateStates []string
	ScopeFindings           []string
}

type ProjectionDiagnostic struct {
	CurrentnessCheckRefs    [][]string
	DecisionCandidateStates []string
	EvidenceRefs            []string
	ObligationID            string
	ProofRouteRef           string
	ReceiptID               string
	RequirementID           string
	ScopeCheckRefs          [][]string
}

type admittedInput struct {
	AdmissionID        string
	NonClaims          []string
	ObligationReceipts []obligationReceipt
}

func Build(raw any) (report.Record, int, error) {
	record, exitCode, _, err := evaluate(raw)
	return record, exitCode, err
}

func ProjectionDiagnostics(raw any) (report.Record, int, []ProjectionDiagnostic, error) {
	record, exitCode, diagnostics, err := evaluate(raw)
	if err != nil {
		return report.Record{}, 1, nil, err
	}
	return record, exitCode, projectionDiagnostics(diagnostics), nil
}

func evaluate(raw any) (report.Record, int, []diagnostic, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, nil, err
	}
	diagnostics := make([]diagnostic, 0, len(input.ObligationReceipts))
	for _, receipt := range input.ObligationReceipts {
		diagnostics = append(diagnostics, evaluateObligationReceipt(receipt))
	}
	sort.Slice(diagnostics, func(left int, right int) bool {
		return compareDiagnostics(diagnostics[left], diagnostics[right]) < 0
	})
	staleObligationIDs := []string{}
	unknownScopeObligationIDs := []string{}
	failedObligationIDs := []string{}
	for _, item := range diagnostics {
		if contains(item.DecisionCandidateStates, "stale_receipt") {
			staleObligationIDs = append(staleObligationIDs, item.ObligationID)
		}
		if contains(item.DecisionCandidateStates, "unknown_scope") {
			unknownScopeObligationIDs = append(unknownScopeObligationIDs, item.ObligationID)
		}
		if len(item.CurrentnessFindings) > 0 || len(item.ScopeFindings) > 0 {
			failedObligationIDs = append(failedObligationIDs, item.ObligationID)
		}
	}
	state := "passed"
	if len(failedObligationIDs) > 0 {
		state = "failed"
	}
	nonClaims, err := sortedText(append(append([]string{}, boundaryNonClaims...), input.NonClaims...), "receipt currentness-scope nonClaims", false)
	if err != nil {
		return report.Record{}, 1, nil, err
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.AdmissionID,
		State:         state,
		Summary: map[string]any{
			"currentReceiptCount":     currentReceiptCount(diagnostics),
			"currentnessFindingCount": currentnessFindingCount(diagnostics),
			"failedObligationCount":   len(failedObligationIDs),
			"notApplicableCount":      decisionStateCount(diagnostics, "not_applicable"),
			"obligationReceiptCount":  len(diagnostics),
			"scopeFindingCount":       scopeFindingCount(diagnostics),
			"staleReceiptCount":       len(staleObligationIDs),
			"unknownScopeCount":       len(unknownScopeObligationIDs),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failedObligationIds", Value: admit.StringSliceToAny(failedObligationIDs)},
			{Key: "receiptCurrentnessScope", Value: reportDiagnostics(diagnostics)},
		},
		RuleResults: ruleResults(diagnostics),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	if state == "passed" {
		return record, 0, diagnostics, nil
	}
	return record, 1, diagnostics, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("receipt currentness-scope input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"admissionId", "nonClaims", "obligationReceipts", "schemaVersion"}, "receipt currentness-scope input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("receipt currentness-scope schemaVersion must be 1")
	}
	obligationReceipts, err := obligationReceiptArray(record["obligationReceipts"])
	if err != nil {
		return admittedInput{}, err
	}
	admissionID, err := admit.RuleID(record["admissionId"], "receipt currentness-scope admissionId")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt currentness-scope nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		AdmissionID:        admissionID,
		NonClaims:          nonClaims,
		ObligationReceipts: obligationReceipts,
	}, nil
}

func obligationReceiptArray(raw any) ([]obligationReceipt, error) {
	records, err := nonEmptyRecords(raw, "receipt currentness-scope obligationReceipts")
	if err != nil {
		return nil, err
	}
	result := make([]obligationReceipt, 0, len(records))
	for _, record := range records {
		item, err := admitObligationReceipt(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return compareObligationReceipts(result[left], result[right]) < 0
	})
	ids := make([]string, 0, len(result))
	for _, receipt := range result {
		ids = append(ids, receipt.ObligationID)
	}
	if err := preserveSortedUnique(ids, "receipt currentness-scope obligation ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitObligationReceipt(record map[string]any) (obligationReceipt, error) {
	if err := admit.KnownKeys(record, []string{"currentnessChecks", "evidenceRefs", "nonClaims", "obligationId", "owner", "proofRouteRef", "reason", "receiptId", "requirementId", "scopeChecks"}, "receipt currentness-scope obligation receipt"); err != nil {
		return obligationReceipt{}, err
	}
	obligationID, err := admit.RuleID(record["obligationId"], "receipt currentness-scope obligationId")
	if err != nil {
		return obligationReceipt{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "receipt currentness-scope requirementId")
	if err != nil {
		return obligationReceipt{}, err
	}
	proofRouteRef, err := admit.RuleID(record["proofRouteRef"], "receipt currentness-scope proofRouteRef")
	if err != nil {
		return obligationReceipt{}, err
	}
	receiptID, err := admit.RuleID(record["receiptId"], "receipt currentness-scope receiptId")
	if err != nil {
		return obligationReceipt{}, err
	}
	currentnessChecks, err := currentnessChecks(record["currentnessChecks"])
	if err != nil {
		return obligationReceipt{}, err
	}
	scopeChecks, err := scopeChecks(record["scopeChecks"])
	if err != nil {
		return obligationReceipt{}, err
	}
	evidenceRefs, err := sortedPathsFromRaw(record["evidenceRefs"], "receipt currentness-scope evidenceRefs", false)
	if err != nil {
		return obligationReceipt{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], "receipt currentness-scope owner")
	if err != nil {
		return obligationReceipt{}, err
	}
	reason, err := admit.NonEmptyText(record["reason"], "receipt currentness-scope reason")
	if err != nil {
		return obligationReceipt{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt currentness-scope obligation nonClaims", false)
	if err != nil {
		return obligationReceipt{}, err
	}
	return obligationReceipt{
		CurrentnessChecks: currentnessChecks,
		EvidenceRefs:      evidenceRefs,
		NonClaims:         nonClaims,
		ObligationID:      obligationID,
		Owner:             owner,
		ProofRouteRef:     proofRouteRef,
		Reason:            reason,
		ReceiptID:         receiptID,
		RequirementID:     requirementID,
		ScopeChecks:       scopeChecks,
	}, nil
}

func currentnessChecks(raw any) ([]currentnessCheck, error) {
	records, err := nonEmptyRecords(raw, "receipt currentness-scope currentnessChecks")
	if err != nil {
		return nil, err
	}
	result := make([]currentnessCheck, 0, len(records))
	for _, record := range records {
		item, err := admitCurrentnessCheck(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].CheckID < result[right].CheckID
	})
	ids := make([]string, 0, len(result))
	for _, check := range result {
		ids = append(ids, check.CheckID)
	}
	if err := preserveSortedUnique(ids, "receipt currentness-scope currentness check ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitCurrentnessCheck(record map[string]any) (currentnessCheck, error) {
	if err := admit.KnownKeys(record, []string{"checkClass", "checkId", "currentDigest", "evidenceRefs", "nonClaims", "recordedDigest"}, "receipt currentness-scope currentness check"); err != nil {
		return currentnessCheck{}, err
	}
	checkID, err := admit.RuleID(record["checkId"], "receipt currentness-scope currentness checkId")
	if err != nil {
		return currentnessCheck{}, err
	}
	checkClass, err := admit.RuleID(record["checkClass"], "receipt currentness-scope currentness checkClass")
	if err != nil {
		return currentnessCheck{}, err
	}
	recordedDigest, err := digest(record["recordedDigest"], "receipt currentness-scope currentness recordedDigest")
	if err != nil {
		return currentnessCheck{}, err
	}
	currentDigest, err := digest(record["currentDigest"], "receipt currentness-scope currentness currentDigest")
	if err != nil {
		return currentnessCheck{}, err
	}
	evidenceRefs, err := sortedPathsFromRaw(record["evidenceRefs"], "receipt currentness-scope currentness evidenceRefs", false)
	if err != nil {
		return currentnessCheck{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt currentness-scope currentness nonClaims", false)
	if err != nil {
		return currentnessCheck{}, err
	}
	return currentnessCheck{
		CheckClass:     checkClass,
		CheckID:        checkID,
		CurrentDigest:  currentDigest,
		EvidenceRefs:   evidenceRefs,
		NonClaims:      nonClaims,
		RecordedDigest: recordedDigest,
	}, nil
}

func scopeChecks(raw any) ([]scopeCheck, error) {
	records, err := nonEmptyRecords(raw, "receipt currentness-scope scopeChecks")
	if err != nil {
		return nil, err
	}
	result := make([]scopeCheck, 0, len(records))
	for _, record := range records {
		item, err := admitScopeCheck(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].CheckID < result[right].CheckID
	})
	ids := make([]string, 0, len(result))
	for _, check := range result {
		ids = append(ids, check.CheckID)
	}
	if err := preserveSortedUnique(ids, "receipt currentness-scope scope check ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitScopeCheck(record map[string]any) (scopeCheck, error) {
	if err := admit.KnownKeys(record, []string{"admissionState", "checkId", "currentScopeDigest", "evidenceRefs", "nonClaims", "reason", "recordedScopeDigest", "scopeClass"}, "receipt currentness-scope scope check"); err != nil {
		return scopeCheck{}, err
	}
	checkID, err := admit.RuleID(record["checkId"], "receipt currentness-scope scope checkId")
	if err != nil {
		return scopeCheck{}, err
	}
	scopeClass, err := admit.RuleID(record["scopeClass"], "receipt currentness-scope scopeClass")
	if err != nil {
		return scopeCheck{}, err
	}
	admissionState, err := enum(record["admissionState"], scopeAdmissionStateSet, scopeAdmissionStates, "receipt currentness-scope admissionState")
	if err != nil {
		return scopeCheck{}, err
	}
	recordedScopeDigest, err := optionalDigest(record, "recordedScopeDigest", "receipt currentness-scope recordedScopeDigest")
	if err != nil {
		return scopeCheck{}, err
	}
	currentScopeDigest, err := optionalDigest(record, "currentScopeDigest", "receipt currentness-scope currentScopeDigest")
	if err != nil {
		return scopeCheck{}, err
	}
	evidenceRefs, err := sortedPathsFromRaw(record["evidenceRefs"], "receipt currentness-scope scope evidenceRefs", false)
	if err != nil {
		return scopeCheck{}, err
	}
	reason, err := admit.NonEmptyText(record["reason"], "receipt currentness-scope scope reason")
	if err != nil {
		return scopeCheck{}, err
	}
	nonClaims, err := sortedTextFromRaw(record["nonClaims"], "receipt currentness-scope scope nonClaims", false)
	if err != nil {
		return scopeCheck{}, err
	}
	return scopeCheck{
		AdmissionState:      admissionState,
		CheckID:             checkID,
		CurrentScopeDigest:  currentScopeDigest,
		EvidenceRefs:        evidenceRefs,
		NonClaims:           nonClaims,
		Reason:              reason,
		RecordedScopeDigest: recordedScopeDigest,
		ScopeClass:          scopeClass,
	}, nil
}

func evaluateObligationReceipt(receipt obligationReceipt) diagnostic {
	currentnessFindings := []string{}
	for _, check := range receipt.CurrentnessChecks {
		if check.RecordedDigest != check.CurrentDigest {
			currentnessFindings = append(currentnessFindings, fmt.Sprintf("currentness check %s recorded digest does not match current digest", check.CheckID))
		}
	}
	sort.Strings(currentnessFindings)
	scopeFindings := []string{}
	for _, check := range receipt.ScopeChecks {
		if check.AdmissionState == "not_admitted_current_scope" ||
			check.AdmissionState == "unknown_current_scope" ||
			(check.AdmissionState == "admitted_current_scope" &&
				check.RecordedScopeDigest != nil &&
				check.CurrentScopeDigest != nil &&
				*check.RecordedScopeDigest != *check.CurrentScopeDigest) {
			scopeFindings = append(scopeFindings, scopeFinding(check))
		}
	}
	sort.Strings(scopeFindings)
	return diagnostic{
		obligationReceipt:       receipt,
		CurrentnessFindings:     currentnessFindings,
		DecisionCandidateStates: decisionCandidateStates(receipt.ScopeChecks, currentnessFindings, scopeFindings),
		ScopeFindings:           scopeFindings,
	}
}

func scopeFinding(check scopeCheck) string {
	if check.AdmissionState == "not_admitted_current_scope" {
		return fmt.Sprintf("scope check %s is not admitted for the current scope", check.CheckID)
	}
	if check.AdmissionState == "unknown_current_scope" {
		return fmt.Sprintf("scope check %s has unknown current scope", check.CheckID)
	}
	return fmt.Sprintf("scope check %s recorded scope digest does not match current scope digest", check.CheckID)
}

func decisionCandidateStates(scopeChecks []scopeCheck, currentnessFindings []string, scopeFindings []string) []string {
	states := []string{}
	if len(currentnessFindings) > 0 {
		states = append(states, "stale_receipt")
	}
	if len(scopeFindings) > 0 {
		states = append(states, "unknown_scope")
	}
	if len(states) == 0 && len(scopeChecks) > 0 && allNotApplicable(scopeChecks) {
		states = append(states, "not_applicable")
	}
	return states
}

func allNotApplicable(scopeChecks []scopeCheck) bool {
	for _, check := range scopeChecks {
		if check.AdmissionState != "not_applicable" {
			return false
		}
	}
	return true
}

func ruleResults(diagnostics []diagnostic) []report.RuleResult {
	results := make([]report.RuleResult, 0, len(diagnostics))
	for _, item := range diagnostics {
		failed := len(item.CurrentnessFindings) > 0 || len(item.ScopeFindings) > 0
		skipped := !failed && contains(item.DecisionCandidateStates, "not_applicable")
		status := "passed"
		message := fmt.Sprintf("receipt %s is current and scoped for %s", item.ReceiptID, item.ObligationID)
		if failed {
			status = "failed"
			message = fmt.Sprintf("receipt %s is stale or not scoped for %s", item.ReceiptID, item.ObligationID)
		} else if skipped {
			status = "skipped"
			message = fmt.Sprintf("receipt %s is not applicable for %s", item.ReceiptID, item.ObligationID)
		}
		results = append(results, report.RuleResult{
			RuleID:  "proofkit.receipt-currentness-scope." + item.ObligationID,
			Status:  status,
			Message: message,
			Diagnostics: []report.Diagnostic{
				{Key: "receiptCurrentnessScope", Value: reportDiagnostic(item)},
			},
		})
	}
	return results
}

func projectionDiagnostics(diagnostics []diagnostic) []ProjectionDiagnostic {
	result := make([]ProjectionDiagnostic, 0, len(diagnostics))
	for _, item := range diagnostics {
		result = append(result, ProjectionDiagnostic{
			CurrentnessCheckRefs:    currentnessCheckRefs(item.CurrentnessChecks),
			DecisionCandidateStates: append([]string{}, item.DecisionCandidateStates...),
			EvidenceRefs:            append([]string{}, item.EvidenceRefs...),
			ObligationID:            item.ObligationID,
			ProofRouteRef:           item.ProofRouteRef,
			ReceiptID:               item.ReceiptID,
			RequirementID:           item.RequirementID,
			ScopeCheckRefs:          scopeCheckRefs(item.ScopeChecks),
		})
	}
	return result
}

func currentnessCheckRefs(checks []currentnessCheck) [][]string {
	result := make([][]string, 0, len(checks))
	for _, check := range checks {
		result = append(result, append([]string{}, check.EvidenceRefs...))
	}
	return result
}

func scopeCheckRefs(checks []scopeCheck) [][]string {
	result := make([][]string, 0, len(checks))
	for _, check := range checks {
		result = append(result, append([]string{}, check.EvidenceRefs...))
	}
	return result
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
		"currentnessFindings":     admit.StringSliceToAny(item.CurrentnessFindings),
		"decisionCandidateStates": admit.StringSliceToAny(item.DecisionCandidateStates),
		"obligationId":            item.ObligationID,
		"proofRouteRef":           item.ProofRouteRef,
		"receiptId":               item.ReceiptID,
		"requirementId":           item.RequirementID,
		"scopeFindings":           admit.StringSliceToAny(item.ScopeFindings),
	}
}

func currentReceiptCount(diagnostics []diagnostic) int {
	count := 0
	for _, item := range diagnostics {
		if len(item.DecisionCandidateStates) == 0 {
			count++
		}
	}
	return count
}

func currentnessFindingCount(diagnostics []diagnostic) int {
	count := 0
	for _, item := range diagnostics {
		count += len(item.CurrentnessFindings)
	}
	return count
}

func scopeFindingCount(diagnostics []diagnostic) int {
	count := 0
	for _, item := range diagnostics {
		count += len(item.ScopeFindings)
	}
	return count
}

func decisionStateCount(diagnostics []diagnostic, state string) int {
	count := 0
	for _, item := range diagnostics {
		if contains(item.DecisionCandidateStates, state) {
			count++
		}
	}
	return count
}

func compareObligationReceipts(left obligationReceipt, right obligationReceipt) int {
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

func compareDiagnostics(left diagnostic, right diagnostic) int {
	return compareObligationReceipts(left.obligationReceipt, right.obligationReceipt)
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
		if index > 0 && values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
		if index > 0 && values[index-1] > values[index] {
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

func digest(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be a sha256 digest", context)
	}
	return value, nil
}

func optionalDigest(record map[string]any, key string, context string) (*string, error) {
	raw, ok := record[key]
	if !ok {
		return nil, fmt.Errorf("%s must be a sha256 digest", context)
	}
	if raw == nil {
		return nil, nil
	}
	value, err := digest(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
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
