package readinesscloseout

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const invalidReportKind = "proofkit.readiness-closeout"

var classifications = []string{"blocked", "failed", "out_of_scope", "passed"}
var classificationSet = toSet(classifications)

var statusPattern = regexp.MustCompile(`^[A-Z]+(?:-[A-Z]+)?$`)
var rowIDPattern = regexp.MustCompile(`^[A-Z]+(?:-[A-Z]+)*-\d+[A-Z]?$`)
var splitSegmentPattern = regexp.MustCompile(`[\n.;|]+`)
var nonAlphaNumericPattern = regexp.MustCompile(`[^a-z0-9]+`)
var whitespacePattern = regexp.MustCompile(`\s+`)

var unsafeNegatedNonClaimPhraseSet = map[string]struct{}{
	"blocked":                     {},
	"blocked on":                  {},
	"blocked until":               {},
	"cannot":                      {},
	"classification honesty only": {},
	"do not":                      {},
	"does not":                    {},
	"explicit non claims":         {},
	"is blocked":                  {},
	"later row":                   {},
	"later rows":                  {},
	"must not":                    {},
	"no":                          {},
	"non claim":                   {},
	"non claims":                  {},
	"not":                         {},
	"remain blocked":              {},
	"remains blocked":             {},
}

var unsafeBlockedScopeTailSet = map[string]struct{}{
	"backlog":     {},
	"future row":  {},
	"future rows": {},
	"future work": {},
	"later row":   {},
	"later rows":  {},
	"non claim":   {},
	"non claims":  {},
	"open work":   {},
	"other row":   {},
	"other rows":  {},
	"todo":        {},
	"unknown":     {},
	"unspecified": {},
}

var nonClaimActionTokenSet = map[string]struct{}{
	"claim":      {},
	"claimed":    {},
	"claiming":   {},
	"claims":     {},
	"convert":    {},
	"converted":  {},
	"converting": {},
	"converts":   {},
	"implied":    {},
	"implies":    {},
	"imply":      {},
	"implying":   {},
	"promote":    {},
	"promoted":   {},
	"promotes":   {},
	"promoting":  {},
	"prove":      {},
	"proved":     {},
	"proves":     {},
	"proving":    {},
}

var blockedNonClaimPrefixes = []string{
	"blocked on ",
	"blocked until ",
	"remain blocked on ",
	"remain blocked until ",
	"remains blocked on ",
	"remains blocked until ",
}

type backlogRow struct {
	CompletionCondition string
	LineNumber          int
	OwnerScope          string
	RowID               string
	Section             string
	Status              string
}

type parsedRows struct {
	DuplicateFailures []string
	Rows              []backlogRow
}

type inputDefinition struct {
	Classification string
	EvidenceClass  string
	ExpectedStatus string
	ForbiddenText  []string
	Reason         string
	RequiredText   []string
	RowID          string
}

type phraseRule struct {
	DirectClaimPhrases []string
	EvidencePhrases    []string
	FailureMessage     string
	PredicatePhrases   []string
	RuleID             string
	SubjectPhrases     []string
}

type frontierPolicy struct {
	ClosedRequiredText    []string
	ClosedRowRequiredText []string
	ClosedStatus          string
	OpenRequiredText      []string
	OpenStatus            string
	RowID                 string
}

type closeoutInput struct {
	EnvironmentPreconditions []string
	ExactCommand             string
	Frontier                 frontierPolicy
	InputDefinitions         []inputDefinition
	MarkdownText             string
	NegatedNonClaimPhrases   []string
	NonClaims                []string
	PhraseRules              []phraseRule
	ReadinessRowPrefixes     []string
	ReadinessSections        []string
	ReportID                 string
	ReportKind               string
	RunIdentity              string
}

type classification struct {
	Classification string
	EvidenceClass  string
	Reason         string
	RowID          string
	Status         string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		result := invalidInputReport(err.Error())
		return result, 1, nil
	}
	return buildReport(input)
}

func buildReport(input closeoutInput) (report.Record, int, error) {
	parsed := parseRows(input.MarkdownText)
	rowsByID := map[string]backlogRow{}
	for _, row := range parsed.Rows {
		rowsByID[row.RowID] = row
	}
	failures := append([]string{}, parsed.DuplicateFailures...)
	classifications := []classification{}
	rules := []report.RuleResult{}
	classified := map[string]struct{}{}

	rules = append(rules, report.RuleResult{
		Diagnostics: sortDiagnostics([]report.Diagnostic{
			{Key: "duplicateFailures", Value: admit.StringSliceToAny(parsed.DuplicateFailures)},
			{Key: "exactCommand", Value: input.ExactCommand},
			{Key: "environmentPreconditions", Value: admit.StringSliceToAny(input.EnvironmentPreconditions)},
			{Key: "runIdentity", Value: input.RunIdentity},
		}),
		Message: passedOrFailures(parsed.DuplicateFailures, "backlog row ids are unique"),
		RuleID:  fmt.Sprintf("%s.backlog_rows.unique", input.Frontier.RowID),
		Status:  statusFailedIf(len(parsed.DuplicateFailures) > 0),
	})

	for _, definition := range input.InputDefinitions {
		row, ok := rowsByID[definition.RowID]
		rowFailures := []string{}
		if !ok {
			rowFailures = append(rowFailures, fmt.Sprintf("%s row is missing from backlog", definition.RowID))
		} else {
			if row.Status != definition.ExpectedStatus {
				rowFailures = append(rowFailures, fmt.Sprintf("%s must be %s, got %s", definition.RowID, definition.ExpectedStatus, row.Status))
			}
			searchable := row.OwnerScope + " " + row.CompletionCondition
			for _, required := range definition.RequiredText {
				if !strings.Contains(searchable, required) {
					rowFailures = append(rowFailures, fmt.Sprintf("%s must include readiness phrase: %s", definition.RowID, required))
				}
			}
			for _, forbidden := range definition.ForbiddenText {
				if strings.Contains(searchable, forbidden) {
					rowFailures = append(rowFailures, fmt.Sprintf("%s must not include readiness overclaim: %s", definition.RowID, forbidden))
				}
			}
			classifications = append(classifications, classification{
				Classification: definition.Classification,
				EvidenceClass:  definition.EvidenceClass,
				Reason:         definition.Reason,
				RowID:          definition.RowID,
				Status:         row.Status,
			})
			classified[definition.RowID] = struct{}{}
		}
		failures = append(failures, rowFailures...)
		rules = append(rules, report.RuleResult{
			Diagnostics: sortDiagnostics(classificationDiagnostics(input, definition)),
			Message:     passedOrFailures(rowFailures, fmt.Sprintf("%s readiness input is correctly classified", definition.RowID)),
			RuleID:      fmt.Sprintf("%s.%s.classification", input.Frontier.RowID, definition.RowID),
			Status:      statusFailedIf(len(rowFailures) > 0),
		})
	}

	scopeFailures := []string{}
	for _, row := range parsed.Rows {
		if !contains(input.ReadinessSections, row.Section) || row.RowID == input.Frontier.RowID {
			continue
		}
		if _, ok := classified[row.RowID]; ok {
			continue
		}
		if hasPrefix(row.RowID, input.ReadinessRowPrefixes) {
			scopeFailures = append(scopeFailures, fmt.Sprintf("%s appears in %s without an explicit %s classification", row.RowID, row.Section, input.Frontier.RowID))
			continue
		}
		classifications = append(classifications, classification{
			Classification: "out_of_scope",
			EvidenceClass:  "non_readiness_section_row",
			Reason:         fmt.Sprintf("row in %s is outside the readiness closeout input set", row.Section),
			RowID:          row.RowID,
			Status:         row.Status,
		})
		classified[row.RowID] = struct{}{}
	}
	failures = append(failures, scopeFailures...)
	rules = append(rules, report.RuleResult{
		Diagnostics: sortDiagnostics([]report.Diagnostic{
			{Key: "classifiedRows", Value: admit.StringSliceToAny(sortedKeys(classified))},
			{Key: "exactCommand", Value: input.ExactCommand},
			{Key: "environmentPreconditions", Value: admit.StringSliceToAny(input.EnvironmentPreconditions)},
			{Key: "runIdentity", Value: input.RunIdentity},
		}),
		Message: passedOrFailures(scopeFailures, "all readiness section rows are explicitly classified or out of scope"),
		RuleID:  fmt.Sprintf("%s.section_scope.classification", input.Frontier.RowID),
		Status:  statusFailedIf(len(scopeFailures) > 0),
	})

	frontierFailures := frontierChecks(input, parsed.Rows, rowsByID)
	failures = append(failures, frontierFailures...)
	rules = append(rules, report.RuleResult{
		Diagnostics: sortDiagnostics([]report.Diagnostic{
			{Key: "closeoutRow", Value: input.Frontier.RowID},
			{Key: "exactCommand", Value: input.ExactCommand},
			{Key: "environmentPreconditions", Value: admit.StringSliceToAny(input.EnvironmentPreconditions)},
			{Key: "runIdentity", Value: input.RunIdentity},
		}),
		Message: passedOrFailures(frontierFailures, fmt.Sprintf("%s closeout and non-claim language are present", input.Frontier.RowID)),
		RuleID:  fmt.Sprintf("%s.frontier.non_claims", input.Frontier.RowID),
		Status:  statusFailedIf(len(frontierFailures) > 0),
	})

	sort.Slice(classifications, func(left int, right int) bool {
		return classifications[left].RowID < classifications[right].RowID
	})
	uniqueFailures := uniqueSorted(failures)
	sort.Slice(rules, func(left int, right int) bool {
		return jsLocaleLess(rules[left].RuleID, rules[right].RuleID)
	})
	state := "passed"
	exitCode := 0
	if len(uniqueFailures) > 0 {
		state = "failed"
		exitCode = 1
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    input.ReportKind,
		ReportID:      input.ReportID,
		State:         state,
		Summary: map[string]any{
			"blocked":        countClassifications(classifications, "blocked"),
			"failed":         len(uniqueFailures),
			"outOfScope":     countClassifications(classifications, "out_of_scope"),
			"passed":         countClassifications(classifications, "passed"),
			"readinessClaim": "classification_honesty_only",
			"rowCount":       len(classifications),
			"runIdentity":    input.RunIdentity,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "blockedRowIds", Value: admit.StringSliceToAny(rowIDsByClassification(classifications, "blocked"))},
			{Key: "outOfScopeRowIds", Value: admit.StringSliceToAny(rowIDsByClassification(classifications, "out_of_scope"))},
			{Key: "passedRowIds", Value: admit.StringSliceToAny(rowIDsByClassification(classifications, "passed"))},
		},
		RuleResults: rules,
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
	return record, exitCode, nil
}

func parseRows(markdownText string) parsedRows {
	rowsByID := map[string]backlogRow{}
	order := []string{}
	duplicates := []string{}
	currentSection := ""
	lines := strings.Split(markdownText, "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "### ") {
			currentSection = strings.TrimSpace(strings.TrimPrefix(trimmed, "### "))
		}
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(trimmed, "|")
		for cellIndex := range cells {
			cells[cellIndex] = strings.TrimSpace(cells[cellIndex])
		}
		if len(cells) < 6 {
			continue
		}
		status := cells[1]
		rowID := cells[2]
		ownerScope := cells[3]
		completionCondition := cells[4]
		if !statusPattern.MatchString(status) || !rowIDPattern.MatchString(rowID) {
			continue
		}
		lineNumber := index + 1
		if existing, ok := rowsByID[rowID]; ok {
			duplicates = append(duplicates, fmt.Sprintf("%s appears more than once in backlog tables at lines %d and %d", rowID, existing.LineNumber, lineNumber))
			continue
		}
		rowsByID[rowID] = backlogRow{
			CompletionCondition: completionCondition,
			LineNumber:          lineNumber,
			OwnerScope:          ownerScope,
			RowID:               rowID,
			Section:             currentSection,
			Status:              status,
		}
		order = append(order, rowID)
	}
	rows := make([]backlogRow, 0, len(order))
	for _, rowID := range order {
		rows = append(rows, rowsByID[rowID])
	}
	sort.Slice(rows, func(left int, right int) bool {
		return rows[left].RowID < rows[right].RowID
	})
	sort.Strings(duplicates)
	return parsedRows{DuplicateFailures: duplicates, Rows: rows}
}

func frontierChecks(input closeoutInput, rows []backlogRow, rowsByID map[string]backlogRow) []string {
	failures := []string{}
	closeoutRow, ok := rowsByID[input.Frontier.RowID]
	if !ok {
		failures = append(failures, fmt.Sprintf("%s closeout row is missing from backlog", input.Frontier.RowID))
	} else if closeoutRow.Status == input.Frontier.OpenStatus {
		failures = append(failures, missingRequiredMarkdownText(input.MarkdownText, input.Frontier.OpenRequiredText, "frontier")...)
	} else if closeoutRow.Status == input.Frontier.ClosedStatus {
		failures = append(failures, missingRequiredMarkdownText(input.MarkdownText, input.Frontier.ClosedRequiredText, "closed-frontier")...)
		closeoutText := closeoutRow.OwnerScope + " " + closeoutRow.CompletionCondition
		for _, phrase := range input.Frontier.ClosedRowRequiredText {
			if !strings.Contains(closeoutText, phrase) {
				failures = append(failures, fmt.Sprintf("%s closed row must include closure phrase: %s", input.Frontier.RowID, phrase))
			}
		}
		for _, row := range rows {
			if contains(input.ReadinessSections, row.Section) && row.Status == input.Frontier.OpenStatus {
				failures = append(failures, fmt.Sprintf("%s must not remain %s in readiness sections after %s closure", row.RowID, input.Frontier.OpenStatus, input.Frontier.RowID))
			}
		}
	} else {
		failures = append(failures, fmt.Sprintf("%s must be %s or %s, got %s", input.Frontier.RowID, input.Frontier.OpenStatus, input.Frontier.ClosedStatus, closeoutRow.Status))
	}
	failures = append(failures, frontierOverclaimFailures(input)...)
	return uniqueSorted(failures)
}

func missingRequiredMarkdownText(markdownText string, requiredText []string, context string) []string {
	failures := []string{}
	for _, phrase := range requiredText {
		if !strings.Contains(markdownText, phrase) {
			failures = append(failures, fmt.Sprintf("backlog must include %s phrase: %s", context, phrase))
		}
	}
	return failures
}

func frontierOverclaimFailures(input closeoutInput) []string {
	failures := []string{}
	for _, segment := range normalizedSegments(input.MarkdownText) {
		if includesAny(segment, input.NegatedNonClaimPhrases) {
			continue
		}
		for _, rule := range input.PhraseRules {
			if matchesPhraseRule(segment, rule) {
				failures = append(failures, fmt.Sprintf("backlog must not include frontier overclaim: %s", rule.FailureMessage))
			}
		}
	}
	return uniqueSorted(failures)
}

func matchesPhraseRule(segment string, rule phraseRule) bool {
	return includesAny(segment, rule.SubjectPhrases) &&
		includesAny(segment, rule.EvidencePhrases) &&
		(includesAny(segment, rule.PredicatePhrases) || includesAny(segment, rule.DirectClaimPhrases))
}

func normalizedSegments(text string) []string {
	parts := splitSegmentPattern.Split(text, -1)
	result := []string{}
	for _, part := range parts {
		normalized := normalizeForPhraseScan(part)
		if len(normalized) > 0 {
			result = append(result, normalized)
		}
	}
	return result
}

func normalizeForPhraseScan(value string) string {
	normalized := strings.ToLower(value)
	normalized = nonAlphaNumericPattern.ReplaceAllString(normalized, " ")
	normalized = whitespacePattern.ReplaceAllString(normalized, " ")
	normalized = strings.TrimSpace(normalized)
	if normalized == "" {
		return ""
	}
	return " " + normalized + " "
}

func includesAny(segment string, phrases []string) bool {
	for _, phrase := range phrases {
		if strings.Contains(segment, normalizeForPhraseScan(phrase)) {
			return true
		}
	}
	return false
}

func admitInput(raw any) (closeoutInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return closeoutInput{}, fmt.Errorf("readiness closeout input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"environmentPreconditions", "exactCommand", "frontier", "inputDefinitions", "markdownText", "negatedNonClaimPhrases", "nonClaims", "phraseRules", "readinessRowPrefixes", "readinessSections", "reportId", "reportKind", "runIdentity", "schemaVersion"}, "readiness closeout input"); err != nil {
		return closeoutInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return closeoutInput{}, fmt.Errorf("readiness closeout input schemaVersion must be 1")
	}
	frontier, err := admitFrontier(record["frontier"])
	if err != nil {
		return closeoutInput{}, err
	}
	inputDefinitions, err := admitInputDefinitions(record["inputDefinitions"])
	if err != nil {
		return closeoutInput{}, err
	}
	definitionIDs := make([]string, 0, len(inputDefinitions))
	for _, definition := range inputDefinitions {
		definitionIDs = append(definitionIDs, definition.RowID)
	}
	if err := assertUnique(definitionIDs, "readiness closeout inputDefinitions.rowId"); err != nil {
		return closeoutInput{}, err
	}
	phraseRules, err := admitPhraseRules(record["phraseRules"])
	if err != nil {
		return closeoutInput{}, err
	}
	phraseRuleIDs := make([]string, 0, len(phraseRules))
	for _, rule := range phraseRules {
		phraseRuleIDs = append(phraseRuleIDs, rule.RuleID)
	}
	if err := assertUnique(phraseRuleIDs, "readiness closeout phraseRules.ruleId"); err != nil {
		return closeoutInput{}, err
	}
	markdownText, err := textValue(record["markdownText"], "readiness closeout markdownText", true, true)
	if err != nil {
		return closeoutInput{}, err
	}
	reportID, err := admit.RuleID(record["reportId"], "readiness closeout reportId")
	if err != nil {
		return closeoutInput{}, err
	}
	reportKind, err := admit.RuleID(record["reportKind"], "readiness closeout reportKind")
	if err != nil {
		return closeoutInput{}, err
	}
	exactCommand, err := admit.DisplayOnlyCommandText(record["exactCommand"], "readiness closeout exactCommand")
	if err != nil {
		return closeoutInput{}, err
	}
	runIdentity, err := admit.RuleID(record["runIdentity"], "readiness closeout runIdentity")
	if err != nil {
		return closeoutInput{}, err
	}
	environmentPreconditions, err := uniqueTextArray(record["environmentPreconditions"], "readiness closeout environmentPreconditions")
	if err != nil {
		return closeoutInput{}, err
	}
	readinessSections, err := sortedTextArray(record["readinessSections"], "readiness closeout readinessSections")
	if err != nil {
		return closeoutInput{}, err
	}
	readinessRowPrefixes, err := uniqueTextArray(record["readinessRowPrefixes"], "readiness closeout readinessRowPrefixes")
	if err != nil {
		return closeoutInput{}, err
	}
	negatedNonClaimPhrases, err := admitNegatedNonClaimPhrases(record["negatedNonClaimPhrases"])
	if err != nil {
		return closeoutInput{}, err
	}
	nonClaims, err := textArray(record["nonClaims"], "readiness closeout nonClaims")
	if err != nil {
		return closeoutInput{}, err
	}
	return closeoutInput{
		EnvironmentPreconditions: environmentPreconditions,
		ExactCommand:             exactCommand,
		Frontier:                 frontier,
		InputDefinitions:         inputDefinitions,
		MarkdownText:             markdownText,
		NegatedNonClaimPhrases:   negatedNonClaimPhrases,
		NonClaims:                nonClaims,
		PhraseRules:              phraseRules,
		ReadinessRowPrefixes:     readinessRowPrefixes,
		ReadinessSections:        readinessSections,
		ReportID:                 reportID,
		ReportKind:               reportKind,
		RunIdentity:              runIdentity,
	}, nil
}

func admitInputDefinitions(raw any) ([]inputDefinition, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("readiness closeout inputDefinitions must be an array")
	}
	result := make([]inputDefinition, 0, len(values))
	for index, value := range values {
		item, err := admitInputDefinition(value, fmt.Sprintf("readiness closeout inputDefinitions[%d]", index))
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].RowID < result[right].RowID
	})
	return result, nil
}

func admitInputDefinition(raw any, context string) (inputDefinition, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return inputDefinition{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"classification", "evidenceClass", "expectedStatus", "forbiddenText", "reason", "requiredText", "rowId"}, context); err != nil {
		return inputDefinition{}, err
	}
	rowID, err := rowID(record["rowId"], context+".rowId")
	if err != nil {
		return inputDefinition{}, err
	}
	expectedStatus, err := statusText(record["expectedStatus"], context+".expectedStatus")
	if err != nil {
		return inputDefinition{}, err
	}
	classification, err := enum(record["classification"], classificationSet, classifications, context+".classification")
	if err != nil {
		return inputDefinition{}, err
	}
	evidenceClass, err := admit.RuleID(record["evidenceClass"], context+".evidenceClass")
	if err != nil {
		return inputDefinition{}, err
	}
	reason, err := textValue(record["reason"], context+".reason", false, false)
	if err != nil {
		return inputDefinition{}, err
	}
	requiredText, err := textArray(record["requiredText"], context+".requiredText")
	if err != nil {
		return inputDefinition{}, err
	}
	forbiddenText := []string{}
	if rawForbiddenText, ok := record["forbiddenText"]; ok {
		forbiddenText, err = textArray(rawForbiddenText, context+".forbiddenText")
		if err != nil {
			return inputDefinition{}, err
		}
	}
	return inputDefinition{
		Classification: classification,
		EvidenceClass:  evidenceClass,
		ExpectedStatus: expectedStatus,
		ForbiddenText:  forbiddenText,
		Reason:         reason,
		RequiredText:   requiredText,
		RowID:          rowID,
	}, nil
}

func admitFrontier(raw any) (frontierPolicy, error) {
	context := "readiness closeout frontier"
	record, ok := raw.(map[string]any)
	if !ok {
		return frontierPolicy{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"closedRequiredText", "closedRowRequiredText", "closedStatus", "openRequiredText", "openStatus", "rowId"}, context); err != nil {
		return frontierPolicy{}, err
	}
	rowID, err := rowID(record["rowId"], context+".rowId")
	if err != nil {
		return frontierPolicy{}, err
	}
	openStatus, err := statusText(record["openStatus"], context+".openStatus")
	if err != nil {
		return frontierPolicy{}, err
	}
	closedStatus, err := statusText(record["closedStatus"], context+".closedStatus")
	if err != nil {
		return frontierPolicy{}, err
	}
	openRequiredText, err := textArray(record["openRequiredText"], context+".openRequiredText")
	if err != nil {
		return frontierPolicy{}, err
	}
	closedRequiredText, err := textArray(record["closedRequiredText"], context+".closedRequiredText")
	if err != nil {
		return frontierPolicy{}, err
	}
	closedRowRequiredText, err := textArray(record["closedRowRequiredText"], context+".closedRowRequiredText")
	if err != nil {
		return frontierPolicy{}, err
	}
	return frontierPolicy{
		ClosedRequiredText:    closedRequiredText,
		ClosedRowRequiredText: closedRowRequiredText,
		ClosedStatus:          closedStatus,
		OpenRequiredText:      openRequiredText,
		OpenStatus:            openStatus,
		RowID:                 rowID,
	}, nil
}

func admitPhraseRules(raw any) ([]phraseRule, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("readiness closeout phraseRules must be an array")
	}
	result := make([]phraseRule, 0, len(values))
	for index, value := range values {
		item, err := admitPhraseRule(value, fmt.Sprintf("readiness closeout phraseRules[%d]", index))
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].RuleID < result[right].RuleID
	})
	return result, nil
}

func admitPhraseRule(raw any, context string) (phraseRule, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return phraseRule{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"directClaimPhrases", "evidencePhrases", "failureMessage", "predicatePhrases", "ruleId", "subjectPhrases"}, context); err != nil {
		return phraseRule{}, err
	}
	ruleID, err := admit.RuleID(record["ruleId"], context+".ruleId")
	if err != nil {
		return phraseRule{}, err
	}
	failureMessage, err := textValue(record["failureMessage"], context+".failureMessage", false, false)
	if err != nil {
		return phraseRule{}, err
	}
	subjectPhrases, err := textArray(record["subjectPhrases"], context+".subjectPhrases")
	if err != nil {
		return phraseRule{}, err
	}
	evidencePhrases, err := textArray(record["evidencePhrases"], context+".evidencePhrases")
	if err != nil {
		return phraseRule{}, err
	}
	predicatePhrases, err := textArray(record["predicatePhrases"], context+".predicatePhrases")
	if err != nil {
		return phraseRule{}, err
	}
	directClaimPhrases := []string{}
	if rawDirect, ok := record["directClaimPhrases"]; ok {
		directClaimPhrases, err = textArray(rawDirect, context+".directClaimPhrases")
		if err != nil {
			return phraseRule{}, err
		}
	}
	return phraseRule{
		DirectClaimPhrases: directClaimPhrases,
		EvidencePhrases:    evidencePhrases,
		FailureMessage:     failureMessage,
		PredicatePhrases:   predicatePhrases,
		RuleID:             ruleID,
		SubjectPhrases:     subjectPhrases,
	}, nil
}

func admitNegatedNonClaimPhrases(raw any) ([]string, error) {
	const context = "readiness closeout negatedNonClaimPhrases"
	values, err := uniqueTextArray(raw, context)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		if !isScopedNonClaimSuppressor(value) {
			return nil, fmt.Errorf("%s[%d] must include a scoped non-claim predicate, got %q", context, index, value)
		}
	}
	return values, nil
}

func isScopedNonClaimSuppressor(value string) bool {
	normalized := strings.TrimSpace(normalizeForPhraseScan(value))
	if _, ok := unsafeNegatedNonClaimPhraseSet[normalized]; ok {
		return false
	}
	if hasBlockedScope(normalized) {
		return true
	}
	return hasNegationToken(normalized) && hasNonClaimActionToken(normalized)
}

func hasBlockedScope(normalized string) bool {
	for _, prefix := range blockedNonClaimPrefixes {
		if !strings.HasPrefix(normalized, prefix) {
			continue
		}
		tail := strings.TrimSpace(strings.TrimPrefix(normalized, prefix))
		if _, ok := unsafeBlockedScopeTailSet[tail]; ok {
			return false
		}
		if _, ok := unsafeNegatedNonClaimPhraseSet[tail]; ok {
			return false
		}
		return len(strings.Fields(tail)) > 0
	}
	return false
}

func hasNegationToken(normalized string) bool {
	padded := " " + normalized + " "
	return strings.Contains(padded, " cannot ") ||
		strings.Contains(padded, " do not ") ||
		strings.Contains(padded, " does not ") ||
		strings.Contains(padded, " must not ") ||
		strings.Contains(padded, " no ") ||
		strings.Contains(padded, " not ")
}

func hasNonClaimActionToken(normalized string) bool {
	for _, token := range strings.Fields(normalized) {
		if _, ok := nonClaimActionTokenSet[token]; ok {
			return true
		}
	}
	return false
}

func invalidInputReport(failure string) report.Record {
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    invalidReportKind,
		ReportID:      "invalid-input",
		State:         "failed",
		Summary: map[string]any{
			"blocked":        0,
			"failed":         1,
			"outOfScope":     0,
			"passed":         0,
			"readinessClaim": "classification_honesty_only",
			"rowCount":       0,
			"runIdentity":    "invalid-input",
		},
		Diagnostics: []report.Diagnostic{},
		RuleResults: []report.RuleResult{
			{
				Diagnostics: []report.Diagnostic{},
				Message:     failure,
				RuleID:      "readiness_closeout.input",
				Status:      "failed",
			},
		},
		NonClaims: []any{"invalid input does not prove readiness closeout state"},
	}
}

func classificationDiagnostics(input closeoutInput, definition inputDefinition) []report.Diagnostic {
	return []report.Diagnostic{
		{Key: "classification", Value: definition.Classification},
		{Key: "exactCommand", Value: input.ExactCommand},
		{Key: "evidenceClass", Value: definition.EvidenceClass},
		{Key: "environmentPreconditions", Value: admit.StringSliceToAny(input.EnvironmentPreconditions)},
		{Key: "expectedStatus", Value: definition.ExpectedStatus},
		{Key: "reason", Value: definition.Reason},
		{Key: "rowId", Value: definition.RowID},
		{Key: "runIdentity", Value: input.RunIdentity},
	}
}

func sortDiagnostics(values []report.Diagnostic) []report.Diagnostic {
	sort.Slice(values, func(left int, right int) bool {
		return jsLocaleLess(values[left].Key, values[right].Key)
	})
	return values
}

func jsLocaleLess(left string, right string) bool {
	leftFolded := strings.ToLower(left)
	rightFolded := strings.ToLower(right)
	if leftFolded == rightFolded {
		return left < right
	}
	return leftFolded < rightFolded
}

func textArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for index, value := range values {
		text, err := textValue(value, fmt.Sprintf("%s[%d]", context, index), false, false)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}

func sortedTextArray(raw any, context string) ([]string, error) {
	values, err := uniqueTextArray(raw, context)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return values, nil
}

func uniqueTextArray(raw any, context string) ([]string, error) {
	values, err := textArray(raw, context)
	if err != nil {
		return nil, err
	}
	if err := assertUnique(values, context); err != nil {
		return nil, err
	}
	sort.Strings(values)
	return values, nil
}

func textValue(raw any, context string, allowEmpty bool, allowSecretLike bool) (string, error) {
	value, ok := raw.(string)
	if !ok || (!allowEmpty && value == "") {
		return "", fmt.Errorf("%s must be non-empty text", context)
	}
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("%s must not contain NUL bytes", context)
	}
	if !allowSecretLike && admit.ContainsSecretLikeValue(value) {
		return "", fmt.Errorf("%s must not contain secret-like values", context)
	}
	return value, nil
}

func statusText(raw any, context string) (string, error) {
	value, err := textValue(raw, context, false, false)
	if err != nil {
		return "", err
	}
	if !statusPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be stable status text", context)
	}
	return value, nil
}

func rowID(raw any, context string) (string, error) {
	value, err := textValue(raw, context, false, false)
	if err != nil {
		return "", err
	}
	if !rowIDPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be stable backlog row id text", context)
	}
	return value, nil
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, strings.Join(ordered, ", "))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, strings.Join(ordered, ", "))
	}
	return value, nil
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

func passedOrFailures(failures []string, passed string) string {
	if len(failures) == 0 {
		return passed
	}
	return strings.Join(failures, "; ")
}

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func rowIDsByClassification(classifications []classification, value string) []string {
	result := []string{}
	for _, item := range classifications {
		if item.Classification == value {
			result = append(result, item.RowID)
		}
	}
	sort.Strings(result)
	return result
}

func countClassifications(classifications []classification, value string) int {
	count := 0
	for _, item := range classifications {
		if item.Classification == value {
			count++
		}
	}
	return count
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
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
