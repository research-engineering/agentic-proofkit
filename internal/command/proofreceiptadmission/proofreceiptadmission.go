package proofreceiptadmission

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.proof-receipt-admission"

var proofReceiptStatuses = proofvocab.ReceiptStatuses()
var proofReceiptStatusSet = proofvocab.ReceiptStatusSet()

var artifactKinds = []string{"artifact", "log", "report"}
var artifactKindSet = toSet(artifactKinds)

var producerAdmissionClasses = proofvocab.MergeSatisfactionClasses()
var producerAdmissionClassSet = proofvocab.MergeSatisfactionClassSet()

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var utcTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.[0-9]{1,9})?Z$`)

var boundaryNonClaims = []string{
	"Proof receipt admission does not approve merge, release, rollout, or production readiness.",
	"Proof receipt admission does not authenticate producer identity.",
	"Proof receipt admission does not compute receipt freshness.",
	"Proof receipt admission does not execute native commands or prove command semantics.",
	"Proof receipt admission does not match receipts to current repository obligations.",
}

type artifactRef struct {
	Kind   string
	Path   string
	Sha256 string
}

type receipt struct {
	ArtifactRefs           []artifactRef
	CommandDigest          string
	DependencyDigest       *string
	EnvironmentClass       string
	EnvironmentDigest      string
	EvidenceRefs           []string
	ExitCode               *int
	FinishedAt             string
	LockfileDigest         *string
	NonClaims              []string
	PreconditionDigest     string
	ProducerAdmissionClass string
	ProducerID             string
	ProofBindingDigest     string
	ProofPlanID            string
	ProvenanceRef          *string
	ReceiptID              string
	ReceiptKind            string
	RunnerClass            string
	RunnerIdentity         string
	SourceRevision         string
	StartedAt              string
	Status                 string
	ToolchainDigest        string
	WitnessSelectorDigest  string
	WitnessSelectors       []string
}

type admittedInput struct {
	NonClaims    []string
	ReceiptSetID string
	Receipts     []receipt
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	failures := receiptFailures(input.Receipts)
	sort.Strings(failures)
	passedReceipts := countStatus(input.Receipts, "passed")
	failedReceipts := countStatus(input.Receipts, "failed")
	blockedReceipts := countStatus(input.Receipts, "blocked")
	notRunReceipts := countStatus(input.Receipts, "not_run")
	mergeSatisfyingReceipts := countProducerAdmissionClass(input.Receipts, "merge_satisfying")
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ReceiptSetID,
		State:         state,
		Summary: map[string]any{
			"artifactRefCount":                                 artifactRefCount(input.Receipts),
			"blockedReceiptCount":                              blockedReceipts,
			"declaredAdvisoryProducerClassReceiptCount":        len(input.Receipts) - mergeSatisfyingReceipts,
			"declaredMergeSatisfyingProducerClassReceiptCount": mergeSatisfyingReceipts,
			"evidenceRefCount":                                 evidenceRefCount(input.Receipts),
			"failedReceiptCount":                               failedReceipts,
			"failureCount":                                     len(failures),
			"notRunReceiptCount":                               notRunReceipts,
			"passedReceiptCount":                               passedReceipts,
			"receiptCount":                                     len(input.Receipts),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "receipts", Value: receiptDiagnostics(input.Receipts)},
		},
		RuleResults: ruleResults(failures),
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
		return admittedInput{}, fmt.Errorf("proof receipt admission input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "receiptSetId", "receipts", "schemaVersion"}, "proof receipt admission input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("proof receipt admission schemaVersion must be 1")
	}
	receipts, err := receipts(record["receipts"])
	if err != nil {
		return admittedInput{}, err
	}
	if len(receipts) == 0 {
		return admittedInput{}, fmt.Errorf("proof receipt admission receipts must be non-empty")
	}
	receiptIDs := make([]string, 0, len(receipts))
	for _, item := range receipts {
		receiptIDs = append(receiptIDs, item.ReceiptID)
	}
	if err := assertUnique(receiptIDs, "proof receipt admission receipt ids"); err != nil {
		return admittedInput{}, err
	}
	receiptSetID, err := admit.RuleID(record["receiptSetId"], "proof receipt admission receiptSetId")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "proof receipt admission nonClaims", true)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		NonClaims:    nonClaims,
		ReceiptSetID: receiptSetID,
		Receipts:     receipts,
	}, nil
}

func receipts(raw any) ([]receipt, error) {
	records, err := arrayOfRecords(raw, "proof receipt admission receipts")
	if err != nil {
		return nil, err
	}
	result := make([]receipt, 0, len(records))
	for _, record := range records {
		item, err := admitReceipt(record)
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

func admitReceipt(record map[string]any) (receipt, error) {
	if err := admit.KnownKeys(record, []string{"artifactRefs", "commandDigest", "dependencyDigest", "environmentClass", "environmentDigest", "evidenceRefs", "exitCode", "finishedAt", "lockfileDigest", "nonClaims", "preconditionDigest", "producerAdmissionClass", "producerId", "proofBindingDigest", "proofPlanId", "provenanceRef", "receiptId", "receiptKind", "runnerClass", "runnerIdentity", "sourceRevision", "startedAt", "status", "toolchainDigest", "witnessSelectorDigest", "witnessSelectors"}, "proof receipt admission receipt"); err != nil {
		return receipt{}, err
	}
	artifacts, err := artifactRefs(record["artifactRefs"])
	if err != nil {
		return receipt{}, err
	}
	artifactKeys := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		artifactKeys = append(artifactKeys, artifact.Kind+":"+artifact.Path)
	}
	if err := assertUnique(artifactKeys, "proof receipt admission receipt artifact refs"); err != nil {
		return receipt{}, err
	}
	receiptID, err := admit.RuleID(record["receiptId"], "proof receipt admission receipt.receiptId")
	if err != nil {
		return receipt{}, err
	}
	receiptKind, err := admit.RuleID(record["receiptKind"], "proof receipt admission receipt.receiptKind")
	if err != nil {
		return receipt{}, err
	}
	sourceRevision, err := admit.NonEmptyText(record["sourceRevision"], "proof receipt admission receipt.sourceRevision")
	if err != nil {
		return receipt{}, err
	}
	proofPlanID, err := admit.RuleID(record["proofPlanId"], "proof receipt admission receipt.proofPlanId")
	if err != nil {
		return receipt{}, err
	}
	proofBindingDigest, err := digest(record["proofBindingDigest"], "proof receipt admission receipt.proofBindingDigest")
	if err != nil {
		return receipt{}, err
	}
	commandDigest, err := digest(record["commandDigest"], "proof receipt admission receipt.commandDigest")
	if err != nil {
		return receipt{}, err
	}
	environmentClass, err := admit.RuleID(record["environmentClass"], "proof receipt admission receipt.environmentClass")
	if err != nil {
		return receipt{}, err
	}
	environmentDigest, err := digest(record["environmentDigest"], "proof receipt admission receipt.environmentDigest")
	if err != nil {
		return receipt{}, err
	}
	preconditionDigest, err := digest(record["preconditionDigest"], "proof receipt admission receipt.preconditionDigest")
	if err != nil {
		return receipt{}, err
	}
	witnessSelectors, err := sortedRuleIDs(record["witnessSelectors"], "proof receipt admission receipt.witnessSelectors")
	if err != nil {
		return receipt{}, err
	}
	witnessSelectorDigest, err := digest(record["witnessSelectorDigest"], "proof receipt admission receipt.witnessSelectorDigest")
	if err != nil {
		return receipt{}, err
	}
	toolchainDigest, err := digest(record["toolchainDigest"], "proof receipt admission receipt.toolchainDigest")
	if err != nil {
		return receipt{}, err
	}
	dependencyDigest, err := optionalDigest(record["dependencyDigest"], "proof receipt admission receipt.dependencyDigest")
	if err != nil {
		return receipt{}, err
	}
	lockfileDigest, err := optionalDigest(record["lockfileDigest"], "proof receipt admission receipt.lockfileDigest")
	if err != nil {
		return receipt{}, err
	}
	runnerIdentity, err := admit.RuleID(record["runnerIdentity"], "proof receipt admission receipt.runnerIdentity")
	if err != nil {
		return receipt{}, err
	}
	runnerClass, err := admit.RuleID(record["runnerClass"], "proof receipt admission receipt.runnerClass")
	if err != nil {
		return receipt{}, err
	}
	producerID, err := admit.RuleID(record["producerId"], "proof receipt admission receipt.producerId")
	if err != nil {
		return receipt{}, err
	}
	producerAdmissionClass, err := enum(record["producerAdmissionClass"], producerAdmissionClassSet, producerAdmissionClasses, "proof receipt admission receipt.producerAdmissionClass")
	if err != nil {
		return receipt{}, err
	}
	provenanceRef, err := optionalPath(record["provenanceRef"], "proof receipt admission receipt.provenanceRef")
	if err != nil {
		return receipt{}, err
	}
	startedAt, err := utcTimestamp(record["startedAt"], "proof receipt admission receipt.startedAt")
	if err != nil {
		return receipt{}, err
	}
	finishedAt, err := utcTimestamp(record["finishedAt"], "proof receipt admission receipt.finishedAt")
	if err != nil {
		return receipt{}, err
	}
	status, err := enum(record["status"], proofReceiptStatusSet, proofReceiptStatuses, "proof receipt admission receipt.status")
	if err != nil {
		return receipt{}, err
	}
	exitCode, err := exitCode(record["exitCode"], "proof receipt admission receipt.exitCode")
	if err != nil {
		return receipt{}, err
	}
	evidenceRefs, err := sortedPaths(record["evidenceRefs"], "proof receipt admission receipt.evidenceRefs", false)
	if err != nil {
		return receipt{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "proof receipt admission receipt.nonClaims", true)
	if err != nil {
		return receipt{}, err
	}
	return receipt{
		ArtifactRefs:           artifacts,
		CommandDigest:          commandDigest,
		DependencyDigest:       dependencyDigest,
		EnvironmentClass:       environmentClass,
		EnvironmentDigest:      environmentDigest,
		EvidenceRefs:           evidenceRefs,
		ExitCode:               exitCode,
		FinishedAt:             finishedAt,
		LockfileDigest:         lockfileDigest,
		NonClaims:              nonClaims,
		PreconditionDigest:     preconditionDigest,
		ProducerAdmissionClass: producerAdmissionClass,
		ProducerID:             producerID,
		ProofBindingDigest:     proofBindingDigest,
		ProofPlanID:            proofPlanID,
		ProvenanceRef:          provenanceRef,
		ReceiptID:              receiptID,
		ReceiptKind:            receiptKind,
		RunnerClass:            runnerClass,
		RunnerIdentity:         runnerIdentity,
		SourceRevision:         sourceRevision,
		StartedAt:              startedAt,
		Status:                 status,
		ToolchainDigest:        toolchainDigest,
		WitnessSelectorDigest:  witnessSelectorDigest,
		WitnessSelectors:       witnessSelectors,
	}, nil
}

func artifactRefs(raw any) ([]artifactRef, error) {
	records, err := arrayOfRecords(raw, "proof receipt admission receipt.artifactRefs")
	if err != nil {
		return nil, err
	}
	result := make([]artifactRef, 0, len(records))
	for _, record := range records {
		item, err := admitArtifactRef(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		if result[left].Kind == result[right].Kind {
			return result[left].Path < result[right].Path
		}
		return result[left].Kind < result[right].Kind
	})
	return result, nil
}

func admitArtifactRef(record map[string]any) (artifactRef, error) {
	if err := admit.KnownKeys(record, []string{"kind", "path", "sha256"}, "proof receipt admission artifactRef"); err != nil {
		return artifactRef{}, err
	}
	kind, err := enum(record["kind"], artifactKindSet, artifactKinds, "proof receipt admission artifactRef.kind")
	if err != nil {
		return artifactRef{}, err
	}
	path, err := pathField(record["path"], "proof receipt admission artifactRef.path")
	if err != nil {
		return artifactRef{}, err
	}
	sha256, err := digest(record["sha256"], "proof receipt admission artifactRef.sha256")
	if err != nil {
		return artifactRef{}, err
	}
	return artifactRef{Kind: kind, Path: path, Sha256: sha256}, nil
}

func receiptFailures(receipts []receipt) []string {
	failures := []string{}
	for _, receipt := range receipts {
		if parsedTime(receipt.FinishedAt).Before(parsedTime(receipt.StartedAt)) {
			failures = append(failures, fmt.Sprintf("receipt %s finished before it started", receipt.ReceiptID))
		}
		if (receipt.Status == "passed" || receipt.Status == "failed") && receipt.ExitCode == nil {
			failures = append(failures, fmt.Sprintf("receipt %s records %s without exitCode", receipt.ReceiptID, receipt.Status))
		}
		if receipt.Status == "passed" && receipt.ExitCode != nil && *receipt.ExitCode != 0 {
			failures = append(failures, fmt.Sprintf("receipt %s records passed with non-zero exitCode", receipt.ReceiptID))
		}
		if receipt.Status == "failed" && receipt.ExitCode != nil && *receipt.ExitCode == 0 {
			failures = append(failures, fmt.Sprintf("receipt %s records failed with zero exitCode", receipt.ReceiptID))
		}
		if (receipt.Status == "blocked" || receipt.Status == "not_run") && receipt.ExitCode != nil {
			failures = append(failures, fmt.Sprintf("receipt %s records %s with exitCode", receipt.ReceiptID, receipt.Status))
		}
		if (receipt.Status == "passed" || receipt.Status == "failed") && len(receipt.ArtifactRefs) == 0 {
			failures = append(failures, fmt.Sprintf("receipt %s records %s without artifact refs", receipt.ReceiptID, receipt.Status))
		}
		if (receipt.Status == "blocked" || receipt.Status == "not_run") && len(receipt.NonClaims) == 0 {
			failures = append(failures, fmt.Sprintf("receipt %s records %s without proof-scope non-claims", receipt.ReceiptID, receipt.Status))
		}
		if receipt.ProducerAdmissionClass == "merge_satisfying" && receipt.ProvenanceRef == nil {
			failures = append(failures, fmt.Sprintf("receipt %s records merge_satisfying producer admission without provenanceRef", receipt.ReceiptID))
		}
	}
	return failures
}

func ruleResults(failures []string) []report.RuleResult {
	return []report.RuleResult{
		{
			RuleID:      "proofkit.proof-receipt-admission.boundary",
			Status:      "passed",
			Message:     "proofkit validates proof receipt shape without authenticating producers, executing commands, or deciding freshness",
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      "proofkit.proof-receipt-admission.receipts",
			Status:      statusFailedIf(len(failures) > 0),
			Message:     "receipts carry required plan, binding, command, environment, witness, runner, producer, timestamp, evidence, artifact, and non-claim fields",
			Diagnostics: failureDiagnostics(failures),
		},
	}
}

func receiptDiagnostics(receipts []receipt) []any {
	result := make([]any, 0, len(receipts))
	for _, receipt := range receipts {
		result = append(result, map[string]any{
			"environmentClass":       receipt.EnvironmentClass,
			"producerAdmissionClass": receipt.ProducerAdmissionClass,
			"producerId":             receipt.ProducerID,
			"proofPlanId":            receipt.ProofPlanID,
			"receiptId":              receipt.ReceiptID,
			"receiptKind":            receipt.ReceiptKind,
			"runnerClass":            receipt.RunnerClass,
			"status":                 receipt.Status,
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

func digest(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be sha256:<64 lowercase hex>", context)
	}
	return value, nil
}

func optionalDigest(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := digest(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func utcTimestamp(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !utcTimestampPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an RFC3339 UTC timestamp", context)
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return "", fmt.Errorf("%s must be a valid RFC3339 UTC timestamp", context)
	}
	return value, nil
}

func parsedTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func exitCode(raw any, context string) (*int, error) {
	if raw == nil {
		return nil, nil
	}
	number, ok := raw.(json.Number)
	if !ok {
		return nil, fmt.Errorf("%s must be null or an integer between 0 and 255", context)
	}
	value, err := number.Int64()
	if err != nil || value < 0 || value > 255 || int64(int(value)) != value {
		return nil, fmt.Errorf("%s must be null or an integer between 0 and 255", context)
	}
	intValue := int(value)
	return &intValue, nil
}

func optionalPath(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := pathField(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	return sortedMapped(raw, context, false, admit.RuleID)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, admit.NonEmptyText)
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, pathField)
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

func pathField(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
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

func artifactRefCount(receipts []receipt) int {
	count := 0
	for _, receipt := range receipts {
		count += len(receipt.ArtifactRefs)
	}
	return count
}

func evidenceRefCount(receipts []receipt) int {
	count := 0
	for _, receipt := range receipts {
		count += len(receipt.EvidenceRefs)
	}
	return count
}

func countStatus(receipts []receipt, status string) int {
	count := 0
	for _, receipt := range receipts {
		if receipt.Status == status {
			count++
		}
	}
	return count
}

func countProducerAdmissionClass(receipts []receipt, admissionClass string) int {
	count := 0
	for _, receipt := range receipts {
		if receipt.ProducerAdmissionClass == admissionClass {
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

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
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
