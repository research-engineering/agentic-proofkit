package selectivegateevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const itemLimit = 24

var boundaryNonClaims = []string{
	"Selective gate evidence reports do not authenticate receipt producers without admitted producerAdmission.",
	"Selective gate evidence reports do not prove receipt freshness without caller-owned freshness policy.",
	"Selective gate evidence reports do not execute planned commands or native witnesses.",
	"Selective gate evidence reports do not approve merge; consuming repositories own obligation decisions and merge admission.",
}

var receiptStatusSet = proofvocab.ReceiptStatusSet()
var obligationClassSet = proofvocab.ObligationClassSet()
var evidenceClassSet = proofvocab.MergeSatisfactionClassSet()

type commandKey struct {
	ID         string
	Command    string
	SourcePath *string
}

type receiptSummary struct {
	commandKey
	Status            string
	ExitCode          any
	EvidenceRef       string
	ArtifactRefs      []string
	ProducerReceiptID *string
}

type Result struct {
	Report                    report.Record
	PlanHash                  string
	MissingReceipts           []commandKey
	FailedReceipts            []receiptSummary
	BlockedReceipts           []receiptSummary
	NotRunReceipts            []receiptSummary
	UnexpectedReceipts        []receiptSummary
	DuplicateReceipts         []commandKey
	ProducerAdmissionFailures []string
	ExitCode                  int
}

func Build(raw any) (Result, error) {
	input, err := admitEvidenceInput(raw)
	if err != nil {
		return Result{}, err
	}
	return buildEvidence(input)
}

type plan struct {
	PlanState        string
	RequiredCommands []map[string]any
	Failures         []string
	ChangedPaths     []string
	Generated        []any
	Raw              map[string]any
}

type evidenceInput struct {
	EvidenceID           string
	EvidenceClass        string
	Plan                 plan
	Receipts             []receiptSummary
	ProducerAdmissionRaw any
	PreexistingFailures  []string
	NonClaims            []string
}

func admitEvidenceInput(raw any) (evidenceInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return evidenceInput{}, fmt.Errorf("selective gate evidence input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"evidenceClass", "evidenceId", "nonClaims", "plan", "preexistingFailures", "producerAdmission", "receipts", "schemaVersion"}, "selective gate evidence input"); err != nil {
		return evidenceInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return evidenceInput{}, fmt.Errorf("selective gate evidence schemaVersion must be 1")
	}
	evidenceID, err := admit.RuleID(record["evidenceId"], "selective gate evidenceId")
	if err != nil {
		return evidenceInput{}, err
	}
	evidenceClass, err := admit.Enum(record["evidenceClass"], evidenceClassSet, "selective gate evidence evidenceClass")
	if err != nil {
		return evidenceInput{}, err
	}
	plan, err := admitPlan(record["plan"])
	if err != nil {
		return evidenceInput{}, err
	}
	receipts, err := admitReceipts(record["receipts"])
	if err != nil {
		return evidenceInput{}, err
	}
	preexisting, err := sortedTextFromAny(record["preexistingFailures"], "selective gate evidence preexistingFailures", true)
	if err != nil {
		return evidenceInput{}, err
	}
	nonClaims, err := sortedTextFromAny(record["nonClaims"], "selective gate evidence nonClaims", false)
	if err != nil {
		return evidenceInput{}, err
	}
	return evidenceInput{EvidenceID: evidenceID, EvidenceClass: evidenceClass, Plan: plan, Receipts: receipts, ProducerAdmissionRaw: record["producerAdmission"], PreexistingFailures: preexisting, NonClaims: nonClaims}, nil
}

func admitPlan(raw any) (plan, error) {
	projection, err := selectivegateplan.AdmitEvidencePlan(raw)
	if err != nil {
		return plan{}, err
	}
	return plan{
		PlanState:        projection.PlanState,
		RequiredCommands: projection.RequiredCommands,
		Failures:         projection.Failures,
		ChangedPaths:     projection.ChangedPaths,
		Generated:        projection.Generated,
		Raw:              projection.Raw,
	}, nil
}

func buildEvidence(input evidenceInput) (Result, error) {
	planHash := stableHash(input.Plan.Raw)
	expected := map[string]commandKey{}
	for _, command := range input.Plan.RequiredCommands {
		key := commandKeyFromCommand(command)
		expected[keyString(key)] = key
	}
	receiptGroups := groupReceipts(input.Receipts)
	missing := []commandKey{}
	for key, value := range expected {
		if _, ok := receiptGroups[key]; !ok {
			missing = append(missing, value)
		}
	}
	sort.Slice(missing, func(left int, right int) bool { return keyString(missing[left]) < keyString(missing[right]) })
	duplicates := []commandKey{}
	for key, values := range receiptGroups {
		if len(values) > 1 {
			duplicates = append(duplicates, parseKey(key))
		}
	}
	sort.Slice(duplicates, func(left int, right int) bool { return keyString(duplicates[left]) < keyString(duplicates[right]) })
	unexpected := []receiptSummary{}
	failed := []receiptSummary{}
	blocked := []receiptSummary{}
	notRun := []receiptSummary{}
	for _, receipt := range input.Receipts {
		if _, ok := expected[keyString(receipt.commandKey)]; !ok {
			unexpected = append(unexpected, receipt)
		}
		switch receipt.Status {
		case "failed":
			failed = append(failed, receipt)
		case "blocked":
			blocked = append(blocked, receipt)
		case "not_run":
			notRun = append(notRun, receipt)
		}
	}
	sortReceipts(unexpected)
	sortReceipts(failed)
	sortReceipts(blocked)
	sortReceipts(notRun)
	producerFailures := []string{}
	producerState := "not_provided"
	producerReceiptCount := 0
	if input.ProducerAdmissionRaw != nil {
		projection, record, _, err := receiptproduceradmission.Evaluate(input.ProducerAdmissionRaw)
		if err != nil {
			return Result{}, err
		}
		producerState = record.State
		if value, ok := record.Summary["receiptCount"].(int); ok {
			producerReceiptCount = value
		}
		producerFailures = validateProducerAdmission(input.Receipts, expected, record, projection)
	}
	if input.EvidenceClass == "merge_satisfying" && input.ProducerAdmissionRaw == nil {
		producerFailures = append(producerFailures, "merge_satisfying evidence requires producerAdmission")
	}
	failures := []string{}
	failures = append(failures, input.PreexistingFailures...)
	for _, failure := range input.Plan.Failures {
		failures = append(failures, "selective gate plan failed closed: "+failure)
	}
	for _, item := range missing {
		failures = append(failures, "missing receipt for required command: "+describeKey(item))
	}
	for _, item := range duplicates {
		failures = append(failures, "duplicate receipt for required command: "+describeKey(item))
	}
	for _, item := range unexpected {
		failures = append(failures, "unexpected receipt without planned command: "+describeKey(item.commandKey))
	}
	for _, item := range failed {
		failures = append(failures, "failed receipt for planned command: "+describeKey(item.commandKey))
	}
	for _, item := range notRun {
		failures = append(failures, "not_run receipt for planned command: "+describeKey(item.commandKey))
	}
	failures = append(failures, producerFailures...)
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	} else if len(blocked) > 0 || input.Plan.PlanState == "fail_closed" {
		state = "blocked"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.selective-gate-evidence",
		ReportID:      input.EvidenceID,
		State:         state,
		Summary: map[string]any{
			"blockedReceiptCount":           len(blocked),
			"duplicateReceiptCount":         len(duplicates),
			"evidenceClass":                 input.EvidenceClass,
			"failedReceiptCount":            len(failed),
			"missingReceiptCount":           len(missing),
			"mergeEvidence":                 mergeEvidenceSummary(input.EvidenceClass, producerState, input.ProducerAdmissionRaw != nil, len(producerFailures) == 0),
			"notRunReceiptCount":            len(notRun),
			"plannedCommandCount":           len(input.Plan.RequiredCommands),
			"planHash":                      planHash,
			"planState":                     input.Plan.PlanState,
			"producerAdmissionFailureCount": len(producerFailures),
			"producerAdmissionState":        producerState,
			"producerAdmittedReceiptCount":  producerReceiptCount,
			"receiptCount":                  len(input.Receipts),
			"unexpectedReceiptCount":        len(unexpected),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "coverage", Value: map[string]any{
				"blockedReceipts":    receiptsJSON(blocked),
				"duplicateReceipts":  keysJSON(duplicates),
				"failedReceipts":     receiptsJSON(failed),
				"missingReceipts":    keysJSON(missing),
				"notRunReceipts":     receiptsJSON(notRun),
				"unexpectedReceipts": receiptsJSON(unexpected),
			}},
			{Key: "plan", Value: map[string]any{
				"changedPathCount":       len(input.Plan.ChangedPaths),
				"generatedArtifactCount": len(input.Plan.Generated),
				"planHash":               planHash,
				"planState":              input.Plan.PlanState,
				"requiredCommandCount":   len(input.Plan.RequiredCommands),
			}},
			{Key: "producerAdmission", Value: map[string]any{"state": producerState}},
		},
		RuleResults: evidenceRuleResults(input.EvidenceClass, input.Plan, missing, duplicates, unexpected, failed, blocked, notRun, producerFailures, input.ProducerAdmissionRaw != nil, failures),
		NonClaims:   admit.StringSliceToAny(sortedUniqueText(append(append([]string{}, boundaryNonClaims...), input.NonClaims...))),
	}
	exitCode := 1
	if state == "passed" {
		exitCode = 0
	}
	return Result{Report: record, PlanHash: planHash, MissingReceipts: missing, FailedReceipts: failed, BlockedReceipts: blocked, NotRunReceipts: notRun, UnexpectedReceipts: unexpected, DuplicateReceipts: duplicates, ProducerAdmissionFailures: producerFailures, ExitCode: exitCode}, nil
}

func mergeEvidenceSummary(evidenceClass string, producerState string, producerProvided bool, producerFailuresAbsent bool) map[string]any {
	producerPassed := producerProvided && producerState == "passed" && producerFailuresAbsent
	return map[string]any{
		"consumerObligationDecisionRequired": true,
		"evidenceClass":                      evidenceClass,
		"mergeAdmissionOwner":                "consumer_repository",
		"nonClaim":                           "Selective gate evidence classifies evidence facts only and does not approve merge.",
		"producerAdmissionPassed":            producerPassed,
		"producerAdmissionProvided":          producerProvided,
		"producerAdmissionRequired":          evidenceClass == "merge_satisfying",
	}
}

func evidenceRuleResults(evidenceClass string, plan plan, missing []commandKey, duplicates []commandKey, unexpected []receiptSummary, failed []receiptSummary, blocked []receiptSummary, notRun []receiptSummary, producerFailures []string, producerProvided bool, failures []string) []report.RuleResult {
	statusRuleStatus := "passed"
	statusMessage := "all matched receipts passed"
	if len(failed) > 0 || len(notRun) > 0 {
		statusRuleStatus = "failed"
		statusMessage = "one or more matched receipts failed or were not run"
	} else if len(blocked) > 0 {
		statusRuleStatus = "skipped"
		statusMessage = "one or more matched receipts were blocked"
	}
	producerStatus := "skipped"
	producerMessage := "producer admission was not provided"
	if evidenceClass == "merge_satisfying" && !producerProvided {
		producerStatus = "failed"
		producerMessage = "merge-satisfying evidence requires producer admission"
	}
	if producerProvided && len(producerFailures) == 0 {
		producerStatus = "passed"
		producerMessage = "passed receipts are bound to merge-satisfying producer admission receipts"
	}
	if producerProvided && len(producerFailures) > 0 {
		producerStatus = "failed"
		producerMessage = "producer admission failed or did not bind every passed receipt"
	}
	results := []report.RuleResult{
		{RuleID: "proofkit.selective-gate-evidence.plan", Status: passFail(plan.PlanState == "ok"), Message: choose(plan.PlanState == "ok", "selective gate plan is admissible", "selective gate plan failed closed")},
		{RuleID: "proofkit.selective-gate-evidence.coverage", Status: passFail(len(missing) == 0), Message: choose(len(missing) == 0, "every planned command has a receipt", "planned commands are missing receipts")},
		{RuleID: "proofkit.selective-gate-evidence.duplicates", Status: passFail(len(duplicates) == 0), Message: choose(len(duplicates) == 0, "receipts are unique by planned command", "duplicate receipts were supplied")},
		{RuleID: "proofkit.selective-gate-evidence.unexpected", Status: passFail(len(unexpected) == 0), Message: choose(len(unexpected) == 0, "every receipt maps to a planned command", "unexpected receipts were supplied")},
		{RuleID: "proofkit.selective-gate-evidence.status", Status: statusRuleStatus, Message: statusMessage},
		{RuleID: "proofkit.selective-gate-evidence.producer-admission", Status: producerStatus, Message: producerMessage, Diagnostics: failureDiagnostics(producerFailures)},
	}
	for index, failure := range failures {
		results = append(results, report.RuleResult{RuleID: fmt.Sprintf("proofkit.selective-gate-evidence.failure.%03d", index+1), Status: "failed", Message: failure})
	}
	sort.Slice(results, func(left int, right int) bool {
		return results[left].RuleID < results[right].RuleID
	})
	return results
}

func admitReceipts(raw any) ([]receiptSummary, error) {
	records, err := arrayOfRecords(raw, "selective gate receipts")
	if err != nil {
		return nil, err
	}
	result := make([]receiptSummary, 0, len(records))
	for _, record := range records {
		if err := admit.KnownKeys(record, []string{"artifactRefs", "command", "evidenceRef", "exitCode", "id", "producerReceiptId", "sourcePath", "status"}, "selective gate receipt"); err != nil {
			return nil, err
		}
		id, err := admit.RuleID(record["id"], "receipt id")
		if err != nil {
			return nil, err
		}
		commandText, err := admit.DisplayOnlyCommandText(record["command"], "receipt command")
		if err != nil {
			return nil, err
		}
		status, err := admit.Enum(record["status"], receiptStatusSet, "receipt status")
		if err != nil {
			return nil, err
		}
		exitCode, err := exitCode(record["exitCode"], status)
		if err != nil {
			return nil, err
		}
		evidenceRef, err := safePathAny(record["evidenceRef"], "receipt evidenceRef")
		if err != nil {
			return nil, err
		}
		artifactRefs, err := sortedPathsFromAny(record["artifactRefs"], "receipt artifactRefs", true)
		if err != nil {
			return nil, err
		}
		var sourcePath *string
		if rawSource, ok := record["sourcePath"]; ok {
			value, err := safePathAny(rawSource, "receipt sourcePath")
			if err != nil {
				return nil, err
			}
			sourcePath = &value
		}
		var producerReceiptID *string
		if rawProducer, ok := record["producerReceiptId"]; ok {
			value, err := admit.RuleID(rawProducer, "receipt producerReceiptId")
			if err != nil {
				return nil, err
			}
			producerReceiptID = &value
		}
		result = append(result, receiptSummary{commandKey: commandKey{ID: id, Command: commandText, SourcePath: sourcePath}, Status: status, ExitCode: exitCode, EvidenceRef: evidenceRef, ArtifactRefs: artifactRefs, ProducerReceiptID: producerReceiptID})
	}
	sortReceipts(result)
	return result, nil
}

func commandKeyFromCommand(command map[string]any) commandKey {
	var source *string
	if raw, ok := command["sourcePath"].(string); ok {
		source = &raw
	}
	id, _ := command["id"].(string)
	text, _ := command["command"].(string)
	return commandKey{ID: id, Command: text, SourcePath: source}
}

func commandKeyJSON(value commandKey) map[string]any {
	return map[string]any{"command": value.Command, "id": value.ID, "sourcePath": nullableString(value.SourcePath)}
}

func receiptJSON(value receiptSummary) map[string]any {
	return map[string]any{
		"artifactRefs":      admit.StringSliceToAny(value.ArtifactRefs),
		"command":           value.Command,
		"evidenceRef":       value.EvidenceRef,
		"exitCode":          value.ExitCode,
		"id":                value.ID,
		"producerReceiptId": nullableString(value.ProducerReceiptID),
		"sourcePath":        nullableString(value.SourcePath),
		"status":            value.Status,
	}
}

func keysJSON(values []commandKey) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, commandKeyJSON(value))
	}
	return result
}

func receiptsJSON(values []receiptSummary) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, receiptJSON(value))
	}
	return result
}

func groupReceipts(receipts []receiptSummary) map[string][]receiptSummary {
	result := map[string][]receiptSummary{}
	for _, receipt := range receipts {
		key := keyString(receipt.commandKey)
		result[key] = append(result[key], receipt)
	}
	for key := range result {
		sortReceipts(result[key])
	}
	return result
}

func validateProducerAdmission(receipts []receiptSummary, expected map[string]commandKey, record report.Record, projection receiptproduceradmission.Projection) []string {
	failures := []string{}
	for _, diagnostic := range record.Diagnostics {
		if diagnostic.Key == "failures" {
			values, ok := diagnostic.Value.([]any)
			if !ok {
				failures = append(failures, "producer admission failures diagnostic is malformed")
				continue
			}
			for _, failure := range admit.AnySliceToString(values) {
				failures = append(failures, "producer admission failed: "+failure)
			}
		}
	}
	if record.State != "passed" {
		if len(failures) == 0 {
			failures = append(failures, "producer admission report did not pass")
		}
		return failures
	}
	producerReceipts := producerReceiptsByID(projection.Receipts)
	for _, receipt := range receipts {
		if receipt.Status != "passed" {
			continue
		}
		if _, ok := expected[keyString(receipt.commandKey)]; !ok {
			continue
		}
		if receipt.ProducerReceiptID == nil {
			failures = append(failures, "passed planned receipt lacks producerReceiptId: "+describeKey(receipt.commandKey))
			continue
		}
		producerReceipt, ok := producerReceipts[*receipt.ProducerReceiptID]
		if !ok {
			failures = append(failures, "passed planned receipt references unknown producer receipt: "+*receipt.ProducerReceiptID)
			continue
		}
		if producerReceipt.SubjectRef != receipt.ID {
			failures = append(failures, "producer receipt subjectRef does not match planned command id: "+*receipt.ProducerReceiptID)
		}
		if producerReceipt.Status != receipt.Status {
			failures = append(failures, "producer receipt status does not match planned receipt: "+*receipt.ProducerReceiptID)
		}
		if producerReceipt.EvidenceRef != receipt.EvidenceRef {
			failures = append(failures, "producer receipt evidenceRef does not match planned receipt: "+*receipt.ProducerReceiptID)
		}
		if !equalStringSlices(producerReceipt.ArtifactRefs, receipt.ArtifactRefs) {
			failures = append(failures, "producer receipt artifactRefs do not match planned receipt: "+*receipt.ProducerReceiptID)
		}
		if !producerReceipt.SatisfiesMergeObligation {
			failures = append(failures, "producer receipt does not satisfy merge obligation: "+*receipt.ProducerReceiptID)
		}
		if producerReceipt.ProvenanceRef == nil {
			failures = append(failures, "producer receipt lacks provenanceRef for merge-satisfying evidence: "+*receipt.ProducerReceiptID)
		}
	}
	sort.Strings(failures)
	return failures
}

func producerReceiptsByID(receipts []receiptproduceradmission.ReceiptProjection) map[string]receiptproduceradmission.ReceiptProjection {
	result := map[string]receiptproduceradmission.ReceiptProjection{}
	for _, receipt := range receipts {
		result[receipt.ReceiptID] = receipt
	}
	return result
}

func arrayOfRecords(raw any, context string) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must contain objects", context)
		}
		result = append(result, record)
	}
	return result, nil
}

func safePathAny(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a repository-relative POSIX path", context)
	}
	return admit.SafeRepoRelativePath(value, context)
}

func nullableSourcePath(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be a repo-relative path or null", context)
	}
	path, err := admit.SafeRepoRelativePath(value, context)
	if err != nil {
		return nil, err
	}
	return &path, nil
}

func sortedTextFromAny(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	sort.Strings(values)
	if err := preserveSortedUnique(values, context, allowEmpty); err != nil {
		return nil, err
	}
	return values, nil
}

func sortedUniqueText(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func sortedPathsFromAny(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, value := range values {
		path, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, path)
	}
	sort.Strings(result)
	if err := preserveSortedUnique(result, context, allowEmpty); err != nil {
		return nil, err
	}
	return result, nil
}

func uniqueSortedPaths(values []string, context string) ([]string, error) {
	result := []string{}
	for _, value := range values {
		path, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, path)
	}
	sort.Strings(result)
	return dedupeStrings(result), nil
}

func dedupeStrings(values []string) []string {
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func equalStringSlices(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must be sorted and unique", context)
	}
	for index := range values {
		if index > 0 && values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func exitCode(raw any, status string) (any, error) {
	if status == "blocked" || status == "not_run" {
		if raw != nil {
			return nil, fmt.Errorf("blocked and not_run receipts must use null exitCode")
		}
		return nil, nil
	}
	number, ok := raw.(json.Number)
	if !ok {
		return nil, fmt.Errorf("passed and failed receipts must declare a non-negative integer exitCode")
	}
	value, err := number.Int64()
	if err != nil || value < 0 {
		return nil, fmt.Errorf("passed and failed receipts must declare a non-negative integer exitCode")
	}
	if status == "passed" && value != 0 {
		return nil, fmt.Errorf("passed receipts must declare zero exitCode")
	}
	if status == "failed" && value == 0 {
		return nil, fmt.Errorf("failed receipts must declare non-zero exitCode")
	}
	return int(value), nil
}

func keyString(key commandKey) string {
	source := ""
	if key.SourcePath != nil {
		source = *key.SourcePath
	}
	return key.ID + "\x00" + key.Command + "\x00" + source
}

func parseKey(value string) commandKey {
	parts := strings.Split(value, "\x00")
	key := commandKey{}
	if len(parts) > 0 {
		key.ID = parts[0]
	}
	if len(parts) > 1 {
		key.Command = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		key.SourcePath = &parts[2]
	}
	return key
}

func describeKey(key commandKey) string {
	if key.SourcePath == nil {
		return key.ID + " :: " + key.Command
	}
	return key.ID + " :: " + key.Command + " :: " + *key.SourcePath
}

func sortReceipts(values []receiptSummary) {
	sort.Slice(values, func(left int, right int) bool {
		if keyString(values[left].commandKey) != keyString(values[right].commandKey) {
			return keyString(values[left].commandKey) < keyString(values[right].commandKey)
		}
		if values[left].Status != values[right].Status {
			return values[left].Status < values[right].Status
		}
		return values[left].EvidenceRef < values[right].EvidenceRef
	})
}

func stableHash(value any) string {
	output, err := stablejson.Marshal(value)
	if err != nil {
		return "sha256:"
	}
	hash := sha256.Sum256(output)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func passFail(ok bool) string {
	if ok {
		return "passed"
	}
	return "failed"
}

func choose(ok bool, yes string, no string) string {
	if ok {
		return yes
	}
	return no
}

func failureDiagnostics(values []string) []report.Diagnostic {
	result := []report.Diagnostic{}
	for index, value := range values {
		result = append(result, report.Diagnostic{Key: fmt.Sprintf("failure.%03d", index+1), Value: value})
	}
	return result
}
