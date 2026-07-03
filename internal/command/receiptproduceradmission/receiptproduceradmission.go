package receiptproduceradmission

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.receipt-producer-admission"

var admissionLevels = proofvocab.MergeSatisfactionClasses()
var admissionLevelSet = proofvocab.MergeSatisfactionClassSet()

var receiptStatuses = proofvocab.ReceiptStatuses()
var receiptStatusSet = proofvocab.ReceiptStatusSet()

var boundaryNonClaims = []string{
	"Receipt producer admission does not approve merge, rollout, or repository policy.",
	"Receipt producer admission does not authenticate producer identity.",
	"Receipt producer admission does not prove command execution or result correctness.",
	"Receipt producer admission does not prove receipt freshness.",
}

type producer struct {
	AdmissionLevel     string
	EnvironmentClasses []string
	EvidenceRefs       []string
	NonClaim           string
	Owner              string
	ProducerID         string
	ReceiptKinds       []string
}

type receipt struct {
	ArtifactRefs             []string
	EnvironmentClass         string
	EvidenceRef              string
	NonClaim                 string
	ProducerID               string
	ProvenanceRef            *string
	ReceiptID                string
	ReceiptKind              string
	SatisfiesMergeObligation bool
	Status                   string
	SubjectRef               string
}

type ReceiptProjection struct {
	ArtifactRefs             []string
	EnvironmentClass         string
	EvidenceRef              string
	ProducerID               string
	ProvenanceRef            *string
	ReceiptID                string
	ReceiptKind              string
	SatisfiesMergeObligation bool
	Status                   string
	SubjectRef               string
}

type Projection struct {
	PolicyID string
	Receipts []ReceiptProjection
}

type admittedInput struct {
	EnvironmentClasses []string
	NonClaims          []string
	PolicyID           string
	Producers          []producer
	ReceiptKinds       []string
	Receipts           []receipt
}

func Build(raw any) (report.Record, int, error) {
	_, record, exitCode, err := Evaluate(raw)
	return record, exitCode, err
}

func Evaluate(raw any) (Projection, report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Projection{}, report.Record{}, 1, err
	}
	producersByID := map[string]producer{}
	for _, item := range input.Producers {
		producersByID[item.ProducerID] = item
	}
	failures := append(
		producerCoverageFailures(input.Producers, input.ReceiptKinds, input.EnvironmentClasses),
		receiptFailures(input.Receipts, producersByID, input.ReceiptKinds, input.EnvironmentClasses)...,
	)
	sort.Strings(failures)
	mergeSatisfyingReceipts := []receipt{}
	for _, item := range input.Receipts {
		if item.SatisfiesMergeObligation {
			mergeSatisfyingReceipts = append(mergeSatisfyingReceipts, item)
		}
	}
	sort.Slice(mergeSatisfyingReceipts, func(left int, right int) bool {
		return mergeSatisfyingReceipts[left].ReceiptID < mergeSatisfyingReceipts[right].ReceiptID
	})
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.PolicyID,
		State:         state,
		Summary: map[string]any{
			"advisoryProducerCount":        countProducers(input.Producers, "advisory"),
			"environmentClassCount":        len(input.EnvironmentClasses),
			"failureCount":                 len(failures),
			"mergeSatisfyingProducerCount": countProducers(input.Producers, "merge_satisfying"),
			"mergeSatisfyingReceiptCount":  len(mergeSatisfyingReceipts),
			"producerCount":                len(input.Producers),
			"receiptCount":                 len(input.Receipts),
			"receiptKindCount":             len(input.ReceiptKinds),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "coverage", Value: map[string]any{
				"environmentClasses": admit.StringSliceToAny(input.EnvironmentClasses),
				"receiptKinds":       admit.StringSliceToAny(input.ReceiptKinds),
			}},
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "mergeSatisfyingReceipts", Value: mergeReceiptDiagnostics(mergeSatisfyingReceipts)},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	projection := Projection{
		PolicyID: input.PolicyID,
		Receipts: receiptProjections(input.Receipts),
	}
	if state == "passed" {
		return projection, record, 0, nil
	}
	return projection, record, 1, nil
}

func receiptProjections(receipts []receipt) []ReceiptProjection {
	result := make([]ReceiptProjection, 0, len(receipts))
	for _, receipt := range receipts {
		result = append(result, ReceiptProjection{
			ArtifactRefs:             append([]string{}, receipt.ArtifactRefs...),
			EnvironmentClass:         receipt.EnvironmentClass,
			EvidenceRef:              receipt.EvidenceRef,
			ProducerID:               receipt.ProducerID,
			ProvenanceRef:            cloneStringPointer(receipt.ProvenanceRef),
			ReceiptID:                receipt.ReceiptID,
			ReceiptKind:              receipt.ReceiptKind,
			SatisfiesMergeObligation: receipt.SatisfiesMergeObligation,
			Status:                   receipt.Status,
			SubjectRef:               receipt.SubjectRef,
		})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ReceiptID < result[right].ReceiptID
	})
	return result
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("receipt producer admission input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"environmentClasses", "nonClaims", "policyId", "producers", "receiptKinds", "receipts", "schemaVersion"}, "receipt producer admission input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("receipt producer admission schemaVersion must be 1")
	}
	receiptKinds, err := sortedRuleIDs(record["receiptKinds"], "receipt producer admission receiptKinds")
	if err != nil {
		return admittedInput{}, err
	}
	environmentClasses, err := sortedRuleIDs(record["environmentClasses"], "receipt producer admission environmentClasses")
	if err != nil {
		return admittedInput{}, err
	}
	producers, err := producers(record["producers"], receiptKinds, environmentClasses)
	if err != nil {
		return admittedInput{}, err
	}
	receipts, err := receipts(record["receipts"], receiptKinds, environmentClasses)
	if err != nil {
		return admittedInput{}, err
	}
	if err := assertUnique(producerIDs(producers), "receipt producer admission producer ids"); err != nil {
		return admittedInput{}, err
	}
	if err := assertUnique(receiptIDs(receipts), "receipt producer admission receipt ids"); err != nil {
		return admittedInput{}, err
	}
	policyID, err := admit.RuleID(record["policyId"], "receipt producer admission policyId")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "receipt producer admission nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		EnvironmentClasses: environmentClasses,
		NonClaims:          nonClaims,
		PolicyID:           policyID,
		Producers:          producers,
		ReceiptKinds:       receiptKinds,
		Receipts:           receipts,
	}, nil
}

func producers(raw any, receiptKinds []string, environmentClasses []string) ([]producer, error) {
	records, err := arrayOfRecords(raw, "receipt producer admission producers")
	if err != nil {
		return nil, err
	}
	result := make([]producer, 0, len(records))
	for _, record := range records {
		item, err := admitProducer(record, receiptKinds, environmentClasses)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ProducerID < result[right].ProducerID
	})
	return result, nil
}

func admitProducer(record map[string]any, receiptKinds []string, environmentClasses []string) (producer, error) {
	if err := admit.KnownKeys(record, []string{"admissionLevel", "environmentClasses", "evidenceRefs", "nonClaim", "owner", "producerId", "receiptKinds"}, "receipt producer admission producer"); err != nil {
		return producer{}, err
	}
	producerID, err := admit.RuleID(record["producerId"], "receipt producer admission producer.producerId")
	if err != nil {
		return producer{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], "receipt producer admission producer.owner")
	if err != nil {
		return producer{}, err
	}
	admissionLevel, err := enum(record["admissionLevel"], admissionLevelSet, admissionLevels, "receipt producer admission producer.admissionLevel")
	if err != nil {
		return producer{}, err
	}
	producerReceiptKinds, err := sortedRuleIDs(record["receiptKinds"], "receipt producer admission producer.receiptKinds")
	if err != nil {
		return producer{}, err
	}
	if err := subset(producerReceiptKinds, receiptKinds, "receipt producer admission producer.receiptKinds"); err != nil {
		return producer{}, err
	}
	producerEnvironmentClasses, err := sortedRuleIDs(record["environmentClasses"], "receipt producer admission producer.environmentClasses")
	if err != nil {
		return producer{}, err
	}
	if err := subset(producerEnvironmentClasses, environmentClasses, "receipt producer admission producer.environmentClasses"); err != nil {
		return producer{}, err
	}
	evidenceRefs, err := sortedPaths(record["evidenceRefs"], "receipt producer admission producer.evidenceRefs", true)
	if err != nil {
		return producer{}, err
	}
	nonClaim, err := admit.NonEmptyText(record["nonClaim"], "receipt producer admission producer.nonClaim")
	if err != nil {
		return producer{}, err
	}
	return producer{
		AdmissionLevel:     admissionLevel,
		EnvironmentClasses: producerEnvironmentClasses,
		EvidenceRefs:       evidenceRefs,
		NonClaim:           nonClaim,
		Owner:              owner,
		ProducerID:         producerID,
		ReceiptKinds:       producerReceiptKinds,
	}, nil
}

func receipts(raw any, receiptKinds []string, environmentClasses []string) ([]receipt, error) {
	records, err := arrayOfRecords(raw, "receipt producer admission receipts")
	if err != nil {
		return nil, err
	}
	result := make([]receipt, 0, len(records))
	for _, record := range records {
		item, err := admitReceipt(record, receiptKinds, environmentClasses)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ReceiptID < result[right].ReceiptID
	})
	return result, nil
}

func admitReceipt(record map[string]any, receiptKinds []string, environmentClasses []string) (receipt, error) {
	if err := admit.KnownKeys(record, []string{"artifactRefs", "environmentClass", "evidenceRef", "nonClaim", "producerId", "provenanceRef", "receiptId", "receiptKind", "satisfiesMergeObligation", "status", "subjectRef"}, "receipt producer admission receipt"); err != nil {
		return receipt{}, err
	}
	merge, err := admit.Bool(record["satisfiesMergeObligation"], "receipt producer admission receipt.satisfiesMergeObligation")
	if err != nil {
		return receipt{}, err
	}
	receiptID, err := admit.RuleID(record["receiptId"], "receipt producer admission receipt.receiptId")
	if err != nil {
		return receipt{}, err
	}
	producerID, err := admit.RuleID(record["producerId"], "receipt producer admission receipt.producerId")
	if err != nil {
		return receipt{}, err
	}
	receiptKind, err := vocabularyValue(record["receiptKind"], receiptKinds, "receipt producer admission receipt.receiptKind")
	if err != nil {
		return receipt{}, err
	}
	environmentClass, err := vocabularyValue(record["environmentClass"], environmentClasses, "receipt producer admission receipt.environmentClass")
	if err != nil {
		return receipt{}, err
	}
	status, err := enum(record["status"], receiptStatusSet, receiptStatuses, "receipt producer admission receipt.status")
	if err != nil {
		return receipt{}, err
	}
	subjectRef, err := admit.RuleID(record["subjectRef"], "receipt producer admission receipt.subjectRef")
	if err != nil {
		return receipt{}, err
	}
	evidenceRef, err := pathField(record["evidenceRef"], "receipt producer admission receipt.evidenceRef")
	if err != nil {
		return receipt{}, err
	}
	provenanceRef, err := optionalPathField(record["provenanceRef"], "receipt producer admission receipt.provenanceRef")
	if err != nil {
		return receipt{}, err
	}
	artifactRefs, err := sortedPaths(record["artifactRefs"], "receipt producer admission receipt.artifactRefs", true)
	if err != nil {
		return receipt{}, err
	}
	nonClaim, err := admit.NonEmptyText(record["nonClaim"], "receipt producer admission receipt.nonClaim")
	if err != nil {
		return receipt{}, err
	}
	return receipt{
		ArtifactRefs:             artifactRefs,
		EnvironmentClass:         environmentClass,
		EvidenceRef:              evidenceRef,
		NonClaim:                 nonClaim,
		ProducerID:               producerID,
		ProvenanceRef:            provenanceRef,
		ReceiptID:                receiptID,
		ReceiptKind:              receiptKind,
		SatisfiesMergeObligation: merge,
		Status:                   status,
		SubjectRef:               subjectRef,
	}, nil
}

func producerCoverageFailures(producers []producer, receiptKinds []string, environmentClasses []string) []string {
	failures := []string{}
	for _, receiptKind := range receiptKinds {
		found := false
		for _, producer := range producers {
			if contains(producer.ReceiptKinds, receiptKind) {
				found = true
				break
			}
		}
		if !found {
			failures = append(failures, "no producer admits receipt kind: "+receiptKind)
		}
	}
	for _, environmentClass := range environmentClasses {
		found := false
		for _, producer := range producers {
			if contains(producer.EnvironmentClasses, environmentClass) {
				found = true
				break
			}
		}
		if !found {
			failures = append(failures, "no producer admits environment class: "+environmentClass)
		}
	}
	return failures
}

func receiptFailures(receipts []receipt, producersByID map[string]producer, receiptKinds []string, environmentClasses []string) []string {
	failures := []string{}
	for _, receipt := range receipts {
		producer, ok := producersByID[receipt.ProducerID]
		if !ok {
			failures = append(failures, fmt.Sprintf("receipt %s references unknown producer: %s", receipt.ReceiptID, receipt.ProducerID))
			continue
		}
		if !contains(receiptKinds, receipt.ReceiptKind) {
			failures = append(failures, fmt.Sprintf("receipt %s uses unknown receipt kind: %s", receipt.ReceiptID, receipt.ReceiptKind))
		}
		if !contains(environmentClasses, receipt.EnvironmentClass) {
			failures = append(failures, fmt.Sprintf("receipt %s uses unknown environment class: %s", receipt.ReceiptID, receipt.EnvironmentClass))
		}
		if !contains(producer.ReceiptKinds, receipt.ReceiptKind) {
			failures = append(failures, fmt.Sprintf("receipt %s uses receipt kind not admitted for producer %s: %s", receipt.ReceiptID, producer.ProducerID, receipt.ReceiptKind))
		}
		if !contains(producer.EnvironmentClasses, receipt.EnvironmentClass) {
			failures = append(failures, fmt.Sprintf("receipt %s uses environment class not admitted for producer %s: %s", receipt.ReceiptID, producer.ProducerID, receipt.EnvironmentClass))
		}
		if receipt.SatisfiesMergeObligation && producer.AdmissionLevel != "merge_satisfying" {
			failures = append(failures, fmt.Sprintf("receipt %s claims merge obligation with advisory producer: %s", receipt.ReceiptID, producer.ProducerID))
		}
		if receipt.SatisfiesMergeObligation && receipt.Status != "passed" {
			failures = append(failures, fmt.Sprintf("receipt %s claims merge obligation without passed status", receipt.ReceiptID))
		}
		if receipt.SatisfiesMergeObligation && receipt.ProvenanceRef == nil {
			failures = append(failures, fmt.Sprintf("receipt %s claims merge obligation without provenanceRef", receipt.ReceiptID))
		}
	}
	return failures
}

func ruleResults(failures []string) []report.RuleResult {
	coverageFailed := false
	receiptFailed := false
	for _, failure := range failures {
		if hasPrefix(failure, "no producer admits") {
			coverageFailed = true
		}
		if hasPrefix(failure, "receipt ") {
			receiptFailed = true
		}
	}
	return []report.RuleResult{
		{
			RuleID:      "proofkit.receipt-producer-admission.boundary",
			Status:      "passed",
			Message:     "proofkit validated caller-provided producer policy without authenticating producers or executing commands",
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      "proofkit.receipt-producer-admission.coverage",
			Status:      statusFailedIf(coverageFailed),
			Message:     "producer policy covers declared receipt kinds and environment classes",
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      "proofkit.receipt-producer-admission.receipts",
			Status:      statusFailedIf(receiptFailed),
			Message:     "receipts match declared producer, kind, environment, status, and merge-obligation boundaries",
			Diagnostics: failureDiagnostics(failures),
		},
	}
}

func mergeReceiptDiagnostics(receipts []receipt) []any {
	result := make([]any, 0, len(receipts))
	for _, receipt := range receipts {
		result = append(result, map[string]any{
			"environmentClass": receipt.EnvironmentClass,
			"producerId":       receipt.ProducerID,
			"provenanceRef":    nullableString(receipt.ProvenanceRef),
			"receiptId":        receipt.ReceiptID,
			"receiptKind":      receipt.ReceiptKind,
			"status":           receipt.Status,
			"subjectRef":       receipt.SubjectRef,
		})
	}
	return result
}

func failureDiagnostics(failures []string) []report.Diagnostic {
	diagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		diagnostics = append(diagnostics, report.Diagnostic{Key: fmt.Sprintf("failure.%03d", index+1), Value: failure})
	}
	return diagnostics
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	return sortedMapped(raw, context, true, admit.RuleID)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, admit.NonEmptyText)
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, func(value any, itemContext string) (string, error) {
		return pathField(value, itemContext)
	})
}

func sortedMapped(raw any, context string, allowEmpty bool, mapper func(any, string) (string, error)) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, err := mapper(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return preserveSortedUnique(result, context, allowEmpty)
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	for index := range values {
		if values[index] != sorted[index] || (index > 0 && values[index-1] == values[index]) {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func arrayOfRecords(raw any, context string) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
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

func subset(values []string, vocabulary []string, context string) error {
	unknown := []string{}
	for _, value := range values {
		if !contains(vocabulary, value) {
			unknown = append(unknown, value)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%s must reference declared vocabulary values: %s", context, join(unknown))
	}
	return nil
}

func vocabularyValue(raw any, vocabulary []string, context string) (string, error) {
	value, err := admit.RuleID(raw, context)
	if err != nil {
		return "", err
	}
	if !contains(vocabulary, value) {
		return "", fmt.Errorf("%s must reference declared vocabulary value", context)
	}
	return value, nil
}

func pathField(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func optionalPathField(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := pathField(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func assertUnique(values []string, context string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s must be unique", context)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	return value, nil
}

func producerIDs(producers []producer) []string {
	values := make([]string, 0, len(producers))
	for _, producer := range producers {
		values = append(values, producer.ProducerID)
	}
	return values
}

func receiptIDs(receipts []receipt) []string {
	values := make([]string, 0, len(receipts))
	for _, receipt := range receipts {
		values = append(values, receipt.ReceiptID)
	}
	return values
}

func countProducers(producers []producer, admissionLevel string) int {
	count := 0
	for _, producer := range producers {
		if producer.AdmissionLevel == admissionLevel {
			count++
		}
	}
	return count
}

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasPrefix(value string, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

func join(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += ", " + value
	}
	return result
}
