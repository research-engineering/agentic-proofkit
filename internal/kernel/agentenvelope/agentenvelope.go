package agentenvelope

import (
	"encoding/json"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	hardMaxActionItems            = 24
	hardMaxActionEvidenceRefs     = 96
	hardMaxBlockedPreconditions   = 12
	hardMaxClarificationQuestions = 12
	hardMaxCommandRefs            = 24
	hardMaxContextRefs            = 48
	hardMaxOmittedItems           = 24
	hardMaxReceiptRefs            = 24
	hardMaxRouteQuestions         = 12
)

var baseNonClaims = []string{
	"Agent guidance envelopes do not approve edits, rollout, or repository policy.",
	"Agent guidance envelopes do not execute native witnesses.",
	"Agent guidance envelopes do not prove report freshness.",
	"Agent guidance envelopes do not replace caller-owned review.",
	"Agent guidance receipt refs do not prove receipt freshness, producer admission, command success, or merge satisfaction.",
}

type Input struct {
	ActionPlan            []map[string]any
	BlockedPreconditions  []map[string]any
	Bounds                map[string]any
	ClarificationQuestion []map[string]any
	Commands              []map[string]any
	ContextRefs           []map[string]any
	EnvelopeID            string
	NonClaims             []string
	Omitted               []map[string]any
	ReceiptRefs           []map[string]any
	RouteQuestions        []map[string]any
	SourceReport          map[string]any
}

func Build(input Input) map[string]any {
	actionPlan := sortMaps(sanitizeMapList(input.ActionPlan), "stepId")
	contextRefs := sortMaps(sanitizeMapList(input.ContextRefs), "refId")
	routeQuestions := sortMaps(sanitizeMapList(input.RouteQuestions), "questionId")
	clarificationQuestions := sortMaps(sanitizeMapList(input.ClarificationQuestion), "questionId")
	blockedPreconditions := sortMaps(sanitizeMapList(input.BlockedPreconditions), "preconditionId")
	omitted := sortMaps(sanitizeMapList(input.Omitted), "omissionId")
	receiptRefs := sortMaps(sanitizeMapList(input.ReceiptRefs), "receiptRefId")
	commands := sortMaps(sanitizeMapList(input.Commands), "commandId")
	omittedCount := 0
	for _, item := range omitted {
		if count, ok := item["omittedCount"].(int); ok {
			omittedCount += count
		}
	}
	bounds := sanitizeMap(input.Bounds)
	if bounds == nil {
		bounds = map[string]any{
			"escalation":      "Caller must provide explicit bounds before treating this envelope as token-budgeted guidance.",
			"fanout":          "bounded",
			"maxActionItems":  len(input.ActionPlan),
			"maxCommandRefs":  len(commands),
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  len(receiptRefs),
			"maxTokenBudget":  nil,
			"nonClaim":        "Compatibility bounds declare item counts only; they do not prove tokenizer-specific budget coverage.",
			"omittedCount":    omittedCount,
		}
	}
	truncated := false
	actionPlan, omitted, truncated = limitActionPlan(actionPlan, omitted, bounds)
	blockedPreconditions, omitted, truncated = limitList(blockedPreconditions, "blockedPrecondition", "preconditionId", "maxBlockedPreconditions", hardMaxBlockedPreconditions, omitted, bounds, truncated)
	clarificationQuestions, omitted, truncated = limitList(clarificationQuestions, "clarificationQuestion", "questionId", "maxClarificationQuestions", hardMaxClarificationQuestions, omitted, bounds, truncated)
	commands, omitted, truncated = limitList(commands, "commandRef", "commandId", "maxCommandRefs", hardMaxCommandRefs, omitted, bounds, truncated)
	contextRefs, omitted, truncated = limitList(contextRefs, "contextRef", "refId", "maxContextRefs", hardMaxContextRefs, omitted, bounds, truncated)
	receiptRefs, omitted, truncated = limitList(receiptRefs, "receiptRef", "receiptRefId", "maxReceiptRefs", hardMaxReceiptRefs, omitted, bounds, truncated)
	routeQuestions, omitted, truncated = limitList(routeQuestions, "routeQuestion", "questionId", "maxRouteQuestions", hardMaxRouteQuestions, omitted, bounds, truncated)
	omitted, truncated = limitOmitted(omitted, bounds, truncated)
	sourceReport := projectSourceReport(sanitizeMap(input.SourceReport))
	omittedCount = 0
	for _, item := range omitted {
		if count, ok := item["omittedCount"].(int); ok {
			omittedCount += count
		}
	}
	bounds["omittedCount"] = omittedCount
	if truncated || omittedCount > 0 {
		bounds["fanout"] = "wide_or_full_gate_required"
		bounds["truncated"] = true
	}
	actionEvidenceRefCount := countNestedRefs(actionPlan, "evidenceRefs")
	boundsViolations := boundViolations(bounds, envelopeCounts{
		ActionEvidenceRefs:     actionEvidenceRefCount,
		ActionItems:            len(actionPlan),
		BlockedPreconditions:   len(blockedPreconditions),
		ClarificationQuestions: len(clarificationQuestions),
		CommandRefs:            len(commands),
		ContextRefs:            len(contextRefs),
		OmittedItems:           len(omitted),
		ReceiptRefs:            len(receiptRefs),
		RouteQuestions:         len(routeQuestions),
	})
	if len(boundsViolations) > 0 {
		bounds["fanout"] = "wide_or_full_gate_required"
		bounds["boundsViolationCount"] = len(boundsViolations)
		bounds["boundsViolations"] = stringsToAny(boundsViolations)
	}
	costContract := map[string]any{
		"affectedRequirementCount":   nil,
		"actionEvidenceRefCount":     actionEvidenceRefCount,
		"actionItemCount":            len(actionPlan),
		"blockedPreconditionCount":   len(blockedPreconditions),
		"clarificationQuestionCount": len(clarificationQuestions),
		"commandRefCount":            len(commands),
		"escalation":                 bounds["escalation"],
		"graphQueryCount":            0,
		"loadedRefCount":             len(contextRefs),
		"maxTokenBudget":             bounds["maxTokenBudget"],
		"nonClaim":                   "Compatibility cost contracts do not prove tokenizer-specific cost, proof completeness, native witness execution, receipt freshness, or merge satisfaction.",
		"omittedEdgeCount":           omittedCount,
		"omittedEdgesCounted":        true,
		"receiptRecordCount":         len(receiptRefs),
		"routeQuestionCount":         len(routeQuestions),
		"boundsViolationCount":       len(boundsViolations),
		"stopReason":                 stopReason(sourceReport, bounds, len(blockedPreconditions), omittedCount, len(boundsViolations)),
		"sufficiencyBasis":           "Compatibility cost contract records declared envelope counts only; caller must inspect the source report before treating the envelope as sufficient.",
	}
	return map[string]any{
		"actionPlan":             mapsToAny(actionPlan),
		"blockedPreconditions":   mapsToAny(blockedPreconditions),
		"bounds":                 bounds,
		"clarificationQuestions": mapsToAny(clarificationQuestions),
		"commands":               mapsToAny(commands),
		"contextRefs":            mapsToAny(contextRefs),
		"costContract":           costContract,
		"envelopeId":             admit.RedactDiagnosticValue(input.EnvelopeID),
		"nonClaims":              sortedUnique(sanitizeStringList(append(append([]string{}, baseNonClaims...), input.NonClaims...))),
		"omitted":                mapsToAny(omitted),
		"receiptRefs":            mapsToAny(receiptRefs),
		"routeQuestions":         mapsToAny(routeQuestions),
		"schemaVersion":          1,
		"sourceReport":           sourceReport,
	}
}

func InvalidInput(message string) map[string]any {
	message = admit.RedactDiagnosticValue(message)
	return Build(Input{
		EnvelopeID: "proofkit.agent-envelope.invalid-input",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Invalid input reporting does not prove source report freshness or native witness execution.",
			"reportId":    "proofkit.agent-envelope.invalid-input",
			"reportKind":  "proofkit.agent-envelope.invalid-input",
			"stableHash":  nil,
			"state":       "failed",
		},
		Bounds: map[string]any{
			"escalation":      "Caller must repair input before using proofkit guidance.",
			"fanout":          "bounded",
			"maxActionItems":  1,
			"maxCommandRefs":  0,
			"maxContextRefs":  0,
			"maxOmittedItems": 0,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Invalid-input bounds describe this diagnostic envelope only and do not prove repository scope coverage.",
			"omittedCount":    0,
		},
		ContextRefs: []map[string]any{},
		RouteQuestions: []map[string]any{
			routeQuestion("proofkit.agent.question.what-changed", "what changed", []any{}, "Invalid input prevents proofkit from determining changed caller context."),
			routeQuestion("proofkit.agent.question.what-proves-it", "what proves it", []any{}, "Invalid input prevents proofkit from determining proof obligations."),
			routeQuestion("proofkit.agent.question.who-owns-it", "who owns it", []any{}, "Input repair remains owned by the consuming repository."),
		},
		ClarificationQuestion: []map[string]any{
			{
				"askWhen":            "Proofkit cannot build the requested agent envelope from caller-provided input.",
				"blocking":           true,
				"evidenceRefs":       []any{"proofkit.agent-envelope.invalid-input"},
				"expectedAnswerKind": "missing_context_ref",
				"nonClaim":           "This question does not approve the corrected input.",
				"owner":              "consumer_repository",
				"question":           "Which caller-owned input field should be corrected before rebuilding the agent envelope?",
				"questionId":         "proofkit.agent.clarify.invalid-input",
			},
		},
		ActionPlan: []map[string]any{
			{
				"commandIds":   []any{},
				"evidenceRefs": []any{"proofkit.agent-envelope.invalid-input"},
				"instruction":  "Repair the caller-provided proofkit input before using agent guidance.",
				"nonClaims": []any{
					"Invalid input guidance does not execute native witnesses.",
					"Invalid input guidance does not prove repository proof truth.",
				},
				"owner":     "consumer_repository",
				"phase":     "route",
				"rationale": message,
				"stepId":    "proofkit.agent.repair-invalid-input",
			},
		},
		Commands: []map[string]any{},
		BlockedPreconditions: []map[string]any{
			{
				"description":    message,
				"evidenceRefs":   []any{"proofkit.agent-envelope.invalid-input"},
				"nonClaim":       "Proofkit reports invalid input but does not repair caller-owned files.",
				"owner":          "consumer_repository",
				"preconditionId": "proofkit.agent.blocked-precondition.invalid-input",
			},
		},
		Omitted:     []map[string]any{},
		ReceiptRefs: []map[string]any{},
		NonClaims: []string{
			"Invalid input envelopes do not approve edits, rollout, or repository policy.",
			"Invalid input envelopes do not execute native witnesses.",
			"Invalid input envelopes do not prove report freshness.",
		},
	})
}

func routeQuestion(id string, question string, evidenceRefs []any, nonClaim string) map[string]any {
	return map[string]any{
		"evidenceRefs": evidenceRefs,
		"nonClaim":     nonClaim,
		"question":     question,
		"questionId":   id,
	}
}

func stopReason(sourceReport map[string]any, bounds map[string]any, blockedPreconditions int, omittedCount int, boundsViolationCount int) string {
	if sourceReport["state"] != "passed" || blockedPreconditions > 0 {
		return "blocked_precondition"
	}
	if bounds["fanout"] != "bounded" || omittedCount > 0 || boundsViolationCount > 0 {
		return "wide_or_full_gate_required"
	}
	return "caller_review_required"
}

type envelopeCounts struct {
	ActionEvidenceRefs     int
	ActionItems            int
	BlockedPreconditions   int
	ClarificationQuestions int
	CommandRefs            int
	ContextRefs            int
	OmittedItems           int
	ReceiptRefs            int
	RouteQuestions         int
}

func boundViolations(bounds map[string]any, counts envelopeCounts) []string {
	checks := []struct {
		name     string
		actual   int
		declared string
		hardMax  int
	}{
		{name: "actionItems", actual: counts.ActionItems, declared: "maxActionItems", hardMax: hardMaxActionItems},
		{name: "actionEvidenceRefs", actual: counts.ActionEvidenceRefs, declared: "maxActionEvidenceRefs", hardMax: hardMaxActionEvidenceRefs},
		{name: "blockedPreconditions", actual: counts.BlockedPreconditions, declared: "maxBlockedPreconditions", hardMax: hardMaxBlockedPreconditions},
		{name: "clarificationQuestions", actual: counts.ClarificationQuestions, declared: "maxClarificationQuestions", hardMax: hardMaxClarificationQuestions},
		{name: "commandRefs", actual: counts.CommandRefs, declared: "maxCommandRefs", hardMax: hardMaxCommandRefs},
		{name: "contextRefs", actual: counts.ContextRefs, declared: "maxContextRefs", hardMax: hardMaxContextRefs},
		{name: "omittedItems", actual: counts.OmittedItems, declared: "maxOmittedItems", hardMax: hardMaxOmittedItems},
		{name: "receiptRefs", actual: counts.ReceiptRefs, declared: "maxReceiptRefs", hardMax: hardMaxReceiptRefs},
		{name: "routeQuestions", actual: counts.RouteQuestions, declared: "maxRouteQuestions", hardMax: hardMaxRouteQuestions},
	}
	violations := []string{}
	for _, check := range checks {
		if max, ok := intValue(bounds[check.declared]); ok && check.actual > max {
			violations = append(violations, check.name+" exceeds declared bound")
			continue
		}
		if check.actual > check.hardMax {
			violations = append(violations, check.name+" exceeds hard envelope bound")
		}
	}
	sort.Strings(violations)
	return violations
}

func limitActionPlan(values []map[string]any, omitted []map[string]any, bounds map[string]any) ([]map[string]any, []map[string]any, bool) {
	limit := itemLimit(bounds, "maxActionItems", hardMaxActionItems)
	result, omitted, truncated := limitList(values, "actionItem", "stepId", "maxActionItems", hardMaxActionItems, omitted, bounds, false)
	evidenceLimit := itemLimit(bounds, "maxActionEvidenceRefs", hardMaxActionEvidenceRefs)
	remainingEvidenceRefs := evidenceLimit
	for index, item := range result {
		refs, ok := item["evidenceRefs"].([]any)
		if !ok {
			continue
		}
		if remainingEvidenceRefs >= len(refs) {
			remainingEvidenceRefs -= len(refs)
			continue
		}
		cloned := copyMap(item)
		cloned["evidenceRefs"] = append([]any{}, refs[:max(remainingEvidenceRefs, 0)]...)
		result[index] = cloned
		omitted = append(omitted, omissionRecord("actionEvidenceRefs", "evidenceRefs", len(refs)-max(remainingEvidenceRefs, 0)))
		truncated = true
		remainingEvidenceRefs = 0
	}
	if len(values) > limit {
		truncated = true
	}
	return result, omitted, truncated
}

func limitList(values []map[string]any, kind string, idKey string, limitKey string, hardMax int, omitted []map[string]any, bounds map[string]any, truncated bool) ([]map[string]any, []map[string]any, bool) {
	limit := itemLimit(bounds, limitKey, hardMax)
	if len(values) <= limit {
		return values, omitted, truncated
	}
	omitted = append(omitted, omissionRecord(kind, idKey, len(values)-limit))
	return values[:limit], omitted, true
}

func limitOmitted(values []map[string]any, bounds map[string]any, truncated bool) ([]map[string]any, bool) {
	limit := itemLimit(bounds, "maxOmittedItems", hardMaxOmittedItems)
	if limit < 1 && len(values) > 0 {
		limit = 1
	}
	if len(values) <= limit {
		return sortMaps(values, "omissionId"), truncated
	}
	capped := append([]map[string]any{}, values[:limit]...)
	overflowCount := omittedRecordCount(values[limit-1:])
	capped[limit-1] = map[string]any{
		"escalation":   "Inspect the source report for omitted overflow details.",
		"nonClaim":     "This omission record summarizes additional omitted envelope records only.",
		"omissionId":   "proofkit.agent-envelope.omitted.overflow",
		"omittedCount": overflowCount,
		"omittedKind":  "omissionRecord",
		"reason":       "Additional omission records were suppressed to keep the envelope bounded.",
		"sourceField":  "omitted",
	}
	return sortMaps(capped, "omissionId"), true
}

func omittedRecordCount(values []map[string]any) int {
	total := 0
	for _, value := range values {
		if count, ok := value["omittedCount"].(int); ok {
			total += count
		}
	}
	return total
}

func itemLimit(bounds map[string]any, key string, hardMax int) int {
	limit := hardMax
	if value, ok := intValue(bounds[key]); ok && value >= 0 && value < limit {
		limit = value
	}
	return limit
}

func omissionRecord(kind string, sourceField string, count int) map[string]any {
	if count < 0 {
		count = 0
	}
	return map[string]any{
		"escalation":   "Inspect the source report for full values before using this envelope as a complete proof route.",
		"nonClaim":     "Omitted envelope values remain in the source report and do not prove proof completeness.",
		"omissionId":   "proofkit.agent-envelope.omitted." + kind,
		"omittedCount": count,
		"omittedKind":  kind,
		"reason":       "Envelope hard or declared bounds suppressed additional values.",
		"sourceField":  sourceField,
	}
}

func projectSourceReport(source map[string]any) map[string]any {
	return map[string]any{
		"artifactRef": source["artifactRef"],
		"nonClaim":    "Source report is projected because agent guidance envelopes do not carry full caller-owned report payloads.",
		"reportId":    source["reportId"],
		"reportKind":  source["reportKind"],
		"stableHash":  source["stableHash"],
		"state":       source["state"],
	}
}

func countNestedRefs(values []map[string]any, key string) int {
	count := 0
	for _, value := range values {
		if refs, ok := value[key].([]any); ok {
			count += len(refs)
		}
		if refs, ok := value[key].([]string); ok {
			count += len(refs)
		}
	}
	return count
}

func copyMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func sanitizeMapList(values []map[string]any) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, sanitizeMap(value))
	}
	return result
}

func sanitizeMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[admit.RedactDiagnosticValue(key)] = sanitizeValue(item)
	}
	return result
}

func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case bool:
		return typed
	case int:
		return typed
	case int64:
		return typed
	case float64:
		return typed
	case json.Number:
		return typed
	case string:
		return admit.RedactDiagnosticValue(typed)
	case []any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, sanitizeValue(item))
		}
		return result
	case []string:
		return stringsToAny(sanitizeStringList(typed))
	case map[string]any:
		return sanitizeMap(typed)
	case map[string]string:
		return sanitizeStringMap(typed)
	case []map[string]any:
		return mapsToAny(sanitizeMapList(typed))
	case []map[string]string:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, sanitizeStringMap(item))
		}
		return result
	default:
		return sanitizeReflectedValue(reflect.ValueOf(value))
	}
}

func sanitizeReflectedValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return nil
		}
		return sanitizeReflectedValue(value.Elem())
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return "<unsupported-report-visible-value>"
		}
		result := make(map[string]any, value.Len())
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key().String()
			result[admit.RedactDiagnosticValue(key)] = sanitizeReflectedValue(iter.Value())
		}
		return result
	case reflect.Slice, reflect.Array:
		result := make([]any, 0, value.Len())
		for index := 0; index < value.Len(); index++ {
			result = append(result, sanitizeReflectedValue(value.Index(index)))
		}
		return result
	case reflect.String:
		return admit.RedactDiagnosticValue(value.String())
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint()
	case reflect.Float32, reflect.Float64:
		return value.Float()
	default:
		return "<unsupported-report-visible-value>"
	}
}

func sanitizeStringMap(value map[string]string) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[admit.RedactDiagnosticValue(key)] = admit.RedactDiagnosticValue(item)
	}
	return result
}

func sanitizeStringList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, admit.RedactDiagnosticValue(value))
	}
	return result
}

func intValue(raw any) (int, bool) {
	value, ok := raw.(int)
	return value, ok
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func sortMaps(values []map[string]any, key string) []map[string]any {
	result := append([]map[string]any{}, values...)
	sort.Slice(result, func(left int, right int) bool {
		leftValue, _ := result[left][key].(string)
		rightValue, _ := result[right][key].(string)
		return leftValue < rightValue
	})
	return result
}

func sortedUnique(values []string) []any {
	sort.Strings(values)
	result := []any{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, sanitizeMap(value))
	}
	return result
}
