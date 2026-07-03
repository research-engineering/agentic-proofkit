package specproofbundleadmission

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var boundaryNonClaims = []string{
	"Spec proof bundle admission does not approve merge, release, rollout, or production readiness.",
	"Spec proof bundle admission does not authenticate receipt producers.",
	"Spec proof bundle admission does not compute receipt freshness.",
	"Spec proof bundle admission does not execute native witnesses.",
	"Spec proof bundle admission does not read repository files or generated views.",
	"Spec proof bundle admission validates linkage only over caller-provided inputs and reports.",
}

type childReport struct {
	EnvironmentClasses []string
	ExitCode           int
	Failures           []any
	NonClaims          []any
	ProducerProjection receiptproduceradmission.Projection
	Producers          []map[string]any
	ReceiptKinds       []string
	Report             map[string]any
	Receipts           []map[string]any
	State              string
}

func Build(raw any) (report.Record, int, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return report.Record{}, 1, fmt.Errorf("spec proof bundle admission input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"bundleId", "mergeRequiredReceiptIds", "nonClaims", "receiptAdmission", "receiptProducerAdmission", "requirementBindings", "schemaVersion", "witnessPlan"}, "spec proof bundle admission input"); err != nil {
		return report.Record{}, 1, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return report.Record{}, 1, fmt.Errorf("spec proof bundle admission schemaVersion must be 1")
	}
	bundleID, err := admit.RuleID(record["bundleId"], "spec proof bundle admission bundleId")
	if err != nil {
		return report.Record{}, 1, err
	}
	mergeRequiredReceiptIDs, err := sortedRuleIDs(record["mergeRequiredReceiptIds"], "spec proof bundle admission mergeRequiredReceiptIds", true)
	if err != nil {
		return report.Record{}, 1, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "spec proof bundle admission nonClaims", true)
	if err != nil {
		return report.Record{}, 1, err
	}
	requirementResult, err := requirementbinding.Build(record["requirementBindings"])
	if err != nil {
		return report.Record{}, 1, err
	}
	witnessProjection, witnessReport, witnessExitCode, err := witnessschedulerplan.Evaluate(record["witnessPlan"])
	if err != nil {
		return report.Record{}, 1, err
	}
	receiptProducer, err := optionalChild(record["receiptProducerAdmission"], "receipt producer admission", "proofkit.receipt-producer-admission")
	if err != nil {
		return report.Record{}, 1, err
	}
	receiptAdmission, err := optionalChild(record["receiptAdmission"], "receipt admission", "proofkit.proof-receipt-admission")
	if err != nil {
		return report.Record{}, 1, err
	}
	failures := []string{}
	if requirementResult.Record.State != "passed" {
		failures = append(failures, "requirement bindings report must pass before bundle admission")
	}
	if witnessReport.State != "passed" || witnessExitCode != 0 {
		failures = append(failures, "witness scheduler plan report must pass before bundle admission")
	}
	if receiptProducer != nil && receiptProducer.State != "passed" {
		failures = append(failures, "receipt producer admission report must pass before bundle admission")
	}
	if receiptAdmission != nil && receiptAdmission.State != "passed" {
		failures = append(failures, "receipt admission report must pass before bundle admission")
	}
	failures = append(failures, linkageFailures(witnessProjection, requirementResult.Graph, receiptAdmission, receiptProducer, mergeRequiredReceiptIDs)...)
	failures = sortedUnique(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	allNonClaims := append(append([]string{}, boundaryNonClaims...), nonClaims...)
	sort.Strings(allNonClaims)
	output := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.spec-proof-bundle-admission",
		ReportID:      bundleID,
		State:         state,
		Summary: map[string]any{
			"bindingCommandCount":       graphCommandCount(requirementResult.Graph),
			"bindingCount":              intValue(requirementResult.Graph["bindingCount"]),
			"failureCount":              len(failures),
			"mergeRequiredReceiptCount": len(mergeRequiredReceiptIDs),
			"receiptCount":              len(receiptsOrNil(receiptAdmission)),
			"receiptProducerAttached":   receiptProducer != nil,
			"requirementCount":          intValue(requirementResult.Graph["requirementCount"]),
			"witnessCommandCount":       len(witnessProjection.Commands),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "bundleReports", Value: map[string]any{
				"receiptAdmissionState":         childState(receiptAdmission),
				"receiptProducerAdmissionState": childState(receiptProducer),
				"requirementBindingState":       requirementResult.Record.State,
				"witnessSchedulerState":         witnessReport.State,
			}},
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
		},
		RuleResults: bundleRuleResults(failures),
		NonClaims:   admit.StringSliceToAny(allNonClaims),
	}
	if state == "passed" {
		return output, 0, nil
	}
	return output, 1, nil
}

func optionalChild(raw any, label string, expectedKind string) (*childReport, error) {
	if raw == nil {
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok || record["report"] == nil {
		return nil, fmt.Errorf("spec proof bundle %s must be a %s report", label, label)
	}
	allowedKeys := []string{"exitCode", "failures", "nonClaims", "producers", "receipts", "report"}
	if expectedKind == "proofkit.receipt-producer-admission" {
		allowedKeys = append(allowedKeys, "environmentClasses", "receiptKinds")
	}
	if err := admit.KnownKeys(record, allowedKeys, "spec proof bundle "+label); err != nil {
		return nil, err
	}
	reportRecord, ok := record["report"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("spec proof bundle %s.report must be an object", label)
	}
	if err := admit.KnownKeys(reportRecord, []string{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}, "spec proof bundle "+label+".report"); err != nil {
		return nil, err
	}
	if !childReportSchemaVersionOne(reportRecord["schemaVersion"]) {
		return nil, fmt.Errorf("spec proof bundle %s.report schemaVersion must be 1", label)
	}
	if reportRecord["reportKind"] != expectedKind {
		return nil, fmt.Errorf("spec proof bundle %s.reportKind must be %s", label, expectedKind)
	}
	reportID, err := admit.RuleID(reportRecord["reportId"], "spec proof bundle "+label+".reportId")
	if err != nil {
		return nil, err
	}
	nonClaims, ok := record["nonClaims"].([]any)
	if !ok {
		return nil, fmt.Errorf("spec proof bundle %s nonClaims must be an array", label)
	}
	state, err := text(reportRecord["state"], "spec proof bundle "+label+".state")
	if err != nil {
		return nil, err
	}
	receipts, ok := record["receipts"].([]any)
	if !ok {
		return nil, fmt.Errorf("spec proof bundle %s must include producer, receipt, and failure arrays", label)
	}
	rawProducers, ok := record["producers"].([]any)
	if !ok {
		return nil, fmt.Errorf("spec proof bundle %s must include producer, receipt, and failure arrays", label)
	}
	failures, ok := record["failures"].([]any)
	if !ok {
		return nil, fmt.Errorf("spec proof bundle %s must include producer, receipt, and failure arrays", label)
	}
	exitCode, err := binaryExitCode(record["exitCode"], "spec proof bundle "+label+".exitCode")
	if err != nil {
		return nil, err
	}
	if state == "passed" && exitCode != 0 {
		return nil, fmt.Errorf("spec proof bundle %s records passed with non-zero exitCode", label)
	}
	if state == "passed" && len(failures) != 0 {
		return nil, fmt.Errorf("spec proof bundle %s records passed with failures", label)
	}
	if state != "passed" && exitCode == 0 {
		return nil, fmt.Errorf("spec proof bundle %s records %s with zero exitCode", label, state)
	}
	result := make([]map[string]any, 0, len(receipts))
	for _, receipt := range receipts {
		receiptRecord, ok := receipt.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("spec proof bundle %s receipts must be objects", label)
		}
		result = append(result, receiptRecord)
	}
	producers := make([]map[string]any, 0, len(rawProducers))
	for _, producer := range rawProducers {
		producerRecord, ok := producer.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("spec proof bundle %s producers must be objects", label)
		}
		producers = append(producers, producerRecord)
	}
	receiptKinds := []string{}
	environmentClasses := []string{}
	if expectedKind == "proofkit.receipt-producer-admission" {
		receiptKinds, err = sortedRuleIDs(record["receiptKinds"], "spec proof bundle "+label+".receiptKinds", true)
		if err != nil {
			return nil, err
		}
		environmentClasses, err = sortedRuleIDs(record["environmentClasses"], "spec proof bundle "+label+".environmentClasses", true)
		if err != nil {
			return nil, err
		}
	}
	child := &childReport{
		EnvironmentClasses: environmentClasses,
		ExitCode:           exitCode,
		Failures:           failures,
		NonClaims:          nonClaims,
		Producers:          producers,
		ReceiptKinds:       receiptKinds,
		Report:             reportRecord,
		Receipts:           result,
		State:              state,
	}
	producerProjection, err := validateChildWithOwner(child, label, expectedKind, reportID)
	if err != nil {
		return nil, err
	}
	child.ProducerProjection = producerProjection
	return child, nil
}

func childReportSchemaVersionOne(raw any) bool {
	if admit.JSONNumberEquals(raw, 1) {
		return true
	}
	if value, ok := raw.(int); ok {
		return value == 1
	}
	return false
}

func validateChildWithOwner(child *childReport, label string, expectedKind string, reportID string) (receiptproduceradmission.Projection, error) {
	var (
		ownerReport        report.Record
		ownerExit          int
		producerProjection receiptproduceradmission.Projection
		err                error
	)
	switch expectedKind {
	case "proofkit.proof-receipt-admission":
		ownerReport, ownerExit, err = proofreceiptadmission.Build(map[string]any{
			"schemaVersion": json.Number("1"),
			"receiptSetId":  reportID,
			"receipts":      mapsToAny(child.Receipts),
			"nonClaims":     child.NonClaims,
		})
	case "proofkit.receipt-producer-admission":
		producerProjection, ownerReport, ownerExit, err = receiptproduceradmission.Evaluate(map[string]any{
			"schemaVersion":      json.Number("1"),
			"policyId":           reportID,
			"receiptKinds":       admit.StringSliceToAny(child.ReceiptKinds),
			"environmentClasses": admit.StringSliceToAny(child.EnvironmentClasses),
			"producers":          mapsToAny(child.Producers),
			"receipts":           mapsToAny(child.Receipts),
			"nonClaims":          child.NonClaims,
		})
	default:
		return receiptproduceradmission.Projection{}, fmt.Errorf("spec proof bundle %s has unsupported child report kind: %s", label, expectedKind)
	}
	if err != nil {
		return receiptproduceradmission.Projection{}, fmt.Errorf("spec proof bundle %s is not admitted by owner validator: %w", label, err)
	}
	if ownerReport.State != child.State || ownerExit != child.ExitCode {
		return receiptproduceradmission.Projection{}, fmt.Errorf("spec proof bundle %s does not match owner validator result", label)
	}
	if !sameStableJSON(ownerReport.JSONValue(), child.Report) {
		return receiptproduceradmission.Projection{}, fmt.Errorf("spec proof bundle %s report body does not match owner validator result", label)
	}
	return producerProjection, nil
}

func sameStableJSON(left any, right any) bool {
	leftBytes, leftErr := stablejson.Marshal(left)
	rightBytes, rightErr := stablejson.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func mapsToAny(records []map[string]any) []any {
	result := make([]any, 0, len(records))
	for _, record := range records {
		result = append(result, record)
	}
	return result
}

type jsonNumber interface {
	String() string
}

func binaryExitCode(raw any, context string) (int, error) {
	exit, ok := raw.(jsonNumber)
	if !ok || (exit.String() != "0" && exit.String() != "1") {
		return 0, fmt.Errorf("%s must be 0 or 1", context)
	}
	if exit.String() == "1" {
		return 1, nil
	}
	return 0, nil
}

func linkageFailures(witnessPlan witnessschedulerplan.Projection, graph map[string]any, receiptAdmission *childReport, receiptProducer *childReport, mergeRequiredReceiptIDs []string) []string {
	failures := []string{}
	commandIDs := map[string]struct{}{}
	commandEnvironments := map[string][]string{}
	for _, command := range witnessPlan.Commands {
		commandIDs[command.ID] = struct{}{}
		commandEnvironments[command.ID] = append([]string{}, command.EnvironmentClasses...)
	}
	bindingCommandIDs := map[string]struct{}{}
	selectorCommandIDs := map[string]map[string]struct{}{}
	for _, requirement := range graphRequirements(graph) {
		requirementID, _ := text(requirement["requirementId"], "graph requirementId")
		selectorCommandIDs[requirementID] = map[string]struct{}{}
		for _, scenario := range graphScenarios(requirement) {
			scenarioID, _ := text(scenario["scenarioId"], "graph scenarioId")
			selectorCommandIDs[scenarioID] = map[string]struct{}{}
			environmentClasses := stringArrayFromAny(scenario["environmentClasses"])
			scenarioCommandEnvironments := map[string]struct{}{}
			for _, commandID := range stringArrayFromAny(scenario["commandIds"]) {
				bindingCommandIDs[commandID] = struct{}{}
				selectorCommandIDs[requirementID][commandID] = struct{}{}
				selectorCommandIDs[scenarioID][commandID] = struct{}{}
				if _, ok := commandIDs[commandID]; !ok {
					failures = append(failures, "binding command lacks witness-plan command: "+commandID)
					continue
				}
				for _, environmentClass := range commandEnvironments[commandID] {
					scenarioCommandEnvironments[environmentClass] = struct{}{}
					if !contains(environmentClasses, environmentClass) {
						failures = append(failures, fmt.Sprintf("binding scenario %s omits witness-plan command %s environment %s", scenarioID, commandID, environmentClass))
					}
				}
			}
			for _, environmentClass := range environmentClasses {
				if _, ok := scenarioCommandEnvironments[environmentClass]; !ok {
					failures = append(failures, fmt.Sprintf("binding scenario %s declares environment %s not present on any witness-plan command", scenarioID, environmentClass))
				}
			}
		}
	}
	for commandID := range commandIDs {
		if _, ok := bindingCommandIDs[commandID]; !ok {
			failures = append(failures, "witness-plan command is not referenced by requirement bindings: "+commandID)
		}
	}
	if receiptAdmission == nil {
		if len(mergeRequiredReceiptIDs) > 0 {
			failures = append(failures, "mergeRequiredReceiptIds require an attached receiptAdmission report")
		}
		return failures
	}
	receiptByID := map[string]map[string]any{}
	for _, receipt := range receiptAdmission.Receipts {
		receiptID, _ := text(receipt["receiptId"], "receiptId")
		receiptByID[receiptID] = receipt
	}
	for _, receiptID := range mergeRequiredReceiptIDs {
		receipt, ok := receiptByID[receiptID]
		if !ok {
			failures = append(failures, "merge-required receipt is missing from receiptAdmission: "+receiptID)
			continue
		}
		if receipt["status"] != "passed" {
			failures = append(failures, "merge-required receipt must pass: "+receiptID)
		}
		if receipt["producerAdmissionClass"] != "merge_satisfying" {
			failures = append(failures, "merge-required receipt must use merge_satisfying producer admission: "+receiptID)
		}
	}
	for _, receipt := range receiptAdmission.Receipts {
		receiptID, _ := text(receipt["receiptId"], "receiptId")
		receiptKind := fmt.Sprint(receipt["receiptKind"])
		if receipt["proofPlanId"] != witnessPlan.SchedulerPlanID {
			failures = append(failures, "receipt "+receiptID+" proofPlanId does not match witness scheduler plan")
		}
		if _, ok := bindingCommandIDs[receiptKind]; !ok {
			failures = append(failures, "receipt "+receiptID+" receiptKind must match a requirement binding command id")
		}
		for _, selector := range stringArrayFromAny(receipt["witnessSelectors"]) {
			commandSet, ok := selectorCommandIDs[selector]
			if !ok {
				failures = append(failures, "receipt "+receiptID+" witness selector is not a requirement or scenario id: "+selector)
				continue
			}
			if _, ok := commandSet[receiptKind]; !ok {
				failures = append(failures, fmt.Sprintf("receipt %s receiptKind %s does not cover witness selector %s", receiptID, receiptKind, selector))
			}
		}
	}
	if receiptProducer == nil {
		for _, receipt := range receiptAdmission.Receipts {
			if receipt["producerAdmissionClass"] == "merge_satisfying" {
				failures = append(failures, "merge_satisfying receipts require an attached receiptProducerAdmission report")
				break
			}
		}
		return failures
	}
	producerReceipts := map[string]receiptproduceradmission.ReceiptProjection{}
	for _, receipt := range receiptProducer.ProducerProjection.Receipts {
		producerReceipts[receipt.ReceiptID] = receipt
	}
	for _, receipt := range receiptAdmission.Receipts {
		if receipt["producerAdmissionClass"] != "merge_satisfying" {
			continue
		}
		receiptID, _ := text(receipt["receiptId"], "receiptId")
		producerReceipt, ok := producerReceipts[receiptID]
		if !ok {
			failures = append(failures, "merge_satisfying receipt lacks producer admission row: "+receiptID)
			continue
		}
		for _, pair := range []struct {
			value   string
			field   string
			message string
		}{
			{producerReceipt.ProducerID, "producerId", "producerId"},
			{producerReceipt.ReceiptKind, "receiptKind", "receiptKind"},
			{producerReceipt.EnvironmentClass, "environmentClass", "environmentClass"},
			{producerReceipt.Status, "status", "status"},
		} {
			if pair.value != receipt[pair.field] {
				failures = append(failures, fmt.Sprintf("merge_satisfying receipt %s does not match producer admission row: %s", pair.message, receiptID))
			}
		}
		if !producerReceipt.SatisfiesMergeObligation {
			failures = append(failures, "merge_satisfying receipt producer admission row is not merge-obligation satisfying: "+receiptID)
		}
	}
	return failures
}

func graphRequirements(graph map[string]any) []map[string]any {
	values, _ := graph["requirements"].([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if ok {
			result = append(result, record)
		}
	}
	return result
}

func graphScenarios(requirement map[string]any) []map[string]any {
	values, _ := requirement["scenarios"].([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if ok {
			result = append(result, record)
		}
	}
	return result
}

func graphCommandCount(graph map[string]any) int {
	set := map[string]struct{}{}
	for _, requirement := range graphRequirements(graph) {
		for _, scenario := range graphScenarios(requirement) {
			for _, commandID := range stringArrayFromAny(scenario["commandIds"]) {
				set[commandID] = struct{}{}
			}
		}
	}
	return len(set)
}

func receiptsOrNil(child *childReport) []map[string]any {
	if child == nil {
		return nil
	}
	return child.Receipts
}

func childState(child *childReport) string {
	if child == nil {
		return "not_attached"
	}
	return child.State
}

func bundleRuleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{{RuleID: "proofkit.spec-proof-bundle-admission.accepted", Status: "passed", Message: "spec proof bundle is internally linked and child reports are admitted"}}
	}
	result := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		result = append(result, report.RuleResult{RuleID: fmt.Sprintf("proofkit.spec-proof-bundle-admission.failure.%03d", index+1), Status: "failed", Message: failure})
	}
	return result
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		id, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	sort.Strings(result)
	return result, assertUnique(result, context)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	sort.Strings(values)
	return sortedUnique(values), nil
}

func stringArrayFromAny(raw any) []string {
	values, _ := raw.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	sort.Strings(result)
	return result
}

func text(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func intValue(raw any) int {
	switch value := raw.(type) {
	case int:
		return value
	case jsonNumber:
		var result int
		_, _ = fmt.Sscanf(value.String(), "%d", &result)
		return result
	default:
		return 0
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func assertUnique(values []string, context string) error {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
