package testevidenceinventory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const discoveryDraftReportKind = "proofkit.test-inventory-discovery-draft"
const discoveryAuthority = "caller_owned_test_discovery"
const discoveryCandidateInventoryAuthority = "caller_owned_test_discovery_candidate_inventory"
const discoveryCandidateInventoryKind = "proofkit.test-inventory-discovery-draft.candidate-inventory"

var runnerKindSet = map[string]struct{}{
	"generic":    {},
	"go_test":    {},
	"node_test":  {},
	"playwright": {},
	"pytest":     {},
	"vitest":     {},
}

var oracleSignalSet = map[string]struct{}{
	"assertion_present":        {},
	"expected_exception":       {},
	"no_assertion_observed":    {},
	"snapshot_only":            {},
	"status_or_exit_assertion": {},
	"unknown":                  {},
}

var selectorSignalSet = map[string]struct{}{
	"first_or_last_selector": {},
	"nth_selector":           {},
	"raw_css_selector":       {},
	"role_selector":          {},
	"structured_selector":    {},
	"test_id_selector":       {},
	"text_selector":          {},
	"unknown":                {},
	"xpath_selector":         {},
}

type discoveryDraftInput struct {
	Authority       string
	DiscoveredTests []discoveredTest
	DraftID         string
	NonClaims       []string
	Repository      discoveryRepository
	Runner          discoveryRunner
}

type discoveryRepository struct {
	NonClaims    []string
	RepositoryID string
}

type discoveryRunner struct {
	CommandRef       string
	EnvironmentClass string
	NonClaims        []string
	RunnerID         string
	RunnerKind       string
}

type discoveredTest struct {
	CandidateRequirementRefs []string
	NonClaims                []string
	OracleSignals            []string
	OwnerID                  string
	OwnerInvariantRefs       []string
	Selector                 string
	SelectorSignals          []string
	SourcePath               string
	TestID                   string
	Title                    string
}

func BuildDiscoveryDraft(raw any) (report.Record, int, error) {
	input, err := admitDiscoveryDraftInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	warnings := discoveryWarnings(input)
	sort.Strings(warnings)
	actions := discoveryActions(input, warnings)
	candidateInventory := discoveryCandidateInventory(input)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    discoveryDraftReportKind,
		ReportID:      input.DraftID,
		State:         "passed",
		Summary: map[string]any{
			"agentActionCount":             len(actions),
			"candidateInventoryEntryCount": len(input.DiscoveredTests),
			"discoveredTestCount":          len(input.DiscoveredTests),
			"fragileSelectorWarningCount":  countPrefix(warnings, "selector_fragility:"),
			"missingAnchorWarningCount":    countPrefix(warnings, "missing_semantic_anchor:"),
			"runnerKind":                   input.Runner.RunnerKind,
			"weakOracleWarningCount":       countPrefix(warnings, "weak_or_empty_oracle:"),
			"warningCount":                 len(warnings),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "agentActionPlan", Value: mapsToAny(actions)},
			{Key: "candidateInventory", Value: candidateInventory},
			{Key: "warningClassifications", Value: mapsToAny(diagnosticClassifications(warnings, "warning"))},
			{Key: "warnings", Value: admit.StringSliceToAny(warnings)},
		},
		RuleResults: []report.RuleResult{
			rule("test_inventory.discovery_draft.input_admitted", "passed", "Discovery draft input used explicit caller-owned facts only."),
			rule("test_inventory.discovery_draft.candidate_only", "passed", "Discovery draft projection emits candidate route-only inventory rows that cannot close semantic coverage."),
		},
		NonClaims: admit.StringSliceToAny(discoveryScopeNonClaims(input)),
	}
	return record, 0, nil
}

func admitDiscoveryDraftInput(raw any) (discoveryDraftInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return discoveryDraftInput{}, fmt.Errorf("test inventory discovery draft input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authority", "discoveredTests", "draftId", "nonClaims", "repository", "runner", "schemaVersion"}, "test inventory discovery draft input"); err != nil {
		return discoveryDraftInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return discoveryDraftInput{}, fmt.Errorf("test inventory discovery draft schemaVersion must be 1")
	}
	authority, err := literal(record["authority"], discoveryAuthority, "test inventory discovery draft authority")
	if err != nil {
		return discoveryDraftInput{}, err
	}
	draftID, err := admit.RuleID(record["draftId"], "test inventory discovery draft draftId")
	if err != nil {
		return discoveryDraftInput{}, err
	}
	repository, err := admitDiscoveryRepository(record["repository"])
	if err != nil {
		return discoveryDraftInput{}, err
	}
	runner, err := admitDiscoveryRunner(record["runner"])
	if err != nil {
		return discoveryDraftInput{}, err
	}
	tests, err := admitDiscoveredTests(record["discoveredTests"])
	if err != nil {
		return discoveryDraftInput{}, err
	}
	nonClaims, err := optionalSortedText(record["nonClaims"], "test inventory discovery draft nonClaims")
	if err != nil {
		return discoveryDraftInput{}, err
	}
	return discoveryDraftInput{
		Authority:       authority,
		DiscoveredTests: tests,
		DraftID:         draftID,
		NonClaims:       nonClaims,
		Repository:      repository,
		Runner:          runner,
	}, nil
}

func admitDiscoveryRepository(raw any) (discoveryRepository, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return discoveryRepository{}, fmt.Errorf("test inventory discovery draft repository must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "repositoryId"}, "test inventory discovery draft repository"); err != nil {
		return discoveryRepository{}, err
	}
	repositoryID, err := admit.RuleID(record["repositoryId"], "test inventory discovery draft repositoryId")
	if err != nil {
		return discoveryRepository{}, err
	}
	nonClaims, err := optionalSortedText(record["nonClaims"], "test inventory discovery draft repository nonClaims")
	if err != nil {
		return discoveryRepository{}, err
	}
	return discoveryRepository{NonClaims: nonClaims, RepositoryID: repositoryID}, nil
}

func admitDiscoveryRunner(raw any) (discoveryRunner, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return discoveryRunner{}, fmt.Errorf("test inventory discovery draft runner must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandRef", "environmentClass", "nonClaims", "runnerId", "runnerKind"}, "test inventory discovery draft runner"); err != nil {
		return discoveryRunner{}, err
	}
	runnerID, err := admit.RuleID(record["runnerId"], "test inventory discovery draft runnerId")
	if err != nil {
		return discoveryRunner{}, err
	}
	runnerKind, err := admit.Enum(record["runnerKind"], runnerKindSet, "test inventory discovery draft runnerKind")
	if err != nil {
		return discoveryRunner{}, err
	}
	commandRef, err := admit.RuleID(record["commandRef"], "test inventory discovery draft commandRef")
	if err != nil {
		return discoveryRunner{}, err
	}
	environmentClass, err := admit.RuleID(record["environmentClass"], "test inventory discovery draft environmentClass")
	if err != nil {
		return discoveryRunner{}, err
	}
	nonClaims, err := optionalSortedText(record["nonClaims"], "test inventory discovery draft runner nonClaims")
	if err != nil {
		return discoveryRunner{}, err
	}
	return discoveryRunner{CommandRef: commandRef, EnvironmentClass: environmentClass, NonClaims: nonClaims, RunnerID: runnerID, RunnerKind: runnerKind}, nil
}

func admitDiscoveredTests(raw any) ([]discoveredTest, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("test inventory discovery draft discoveredTests must be a non-empty array")
	}
	tests := make([]discoveredTest, 0, len(values))
	for index, value := range values {
		test, err := admitDiscoveredTest(value, index)
		if err != nil {
			return nil, err
		}
		tests = append(tests, test)
	}
	sort.Slice(tests, func(left, right int) bool { return tests[left].TestID < tests[right].TestID })
	if err := assertUnique(discoveredTestIDs(tests), "test inventory discovery draft testIds"); err != nil {
		return nil, err
	}
	return tests, nil
}

func admitDiscoveredTest(raw any, index int) (discoveredTest, error) {
	context := fmt.Sprintf("test inventory discovery draft discoveredTests[%d]", index)
	record, ok := raw.(map[string]any)
	if !ok {
		return discoveredTest{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"candidateRequirementRefs", "nonClaims", "oracleSignals", "ownerId", "ownerInvariantRefs", "selector", "selectorSignals", "sourcePath", "testId", "title"}, context); err != nil {
		return discoveredTest{}, err
	}
	testID, err := admit.RuleID(record["testId"], context+" testId")
	if err != nil {
		return discoveredTest{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], context+" ownerId")
	if err != nil {
		return discoveredTest{}, err
	}
	selector, err := admit.DisplayOnlyCommandText(record["selector"], context+" selector")
	if err != nil {
		return discoveredTest{}, err
	}
	sourceText, err := admit.NonEmptyText(record["sourcePath"], context+" sourcePath")
	if err != nil {
		return discoveredTest{}, err
	}
	sourcePath, err := admit.SafeRepoRelativePath(sourceText, context+" sourcePath")
	if err != nil {
		return discoveredTest{}, err
	}
	if err := admit.StructuredSelectorSourcePath(selector, sourcePath, context+" selector"); err != nil {
		return discoveredTest{}, err
	}
	title, err := admit.NonEmptyText(record["title"], context+" title")
	if err != nil {
		return discoveredTest{}, err
	}
	requirementRefs, err := sortedRequirementRefs(record["candidateRequirementRefs"], context+" candidateRequirementRefs")
	if err != nil {
		return discoveredTest{}, err
	}
	invariantRefs, err := sortedRuleIDs(record["ownerInvariantRefs"], context+" ownerInvariantRefs", true)
	if err != nil {
		return discoveredTest{}, err
	}
	oracleSignals, err := sortedEnums(record["oracleSignals"], oracleSignalSet, context+" oracleSignals")
	if err != nil {
		return discoveredTest{}, err
	}
	selectorSignals, err := sortedEnums(record["selectorSignals"], selectorSignalSet, context+" selectorSignals")
	if err != nil {
		return discoveredTest{}, err
	}
	nonClaims, err := optionalSortedText(record["nonClaims"], context+" nonClaims")
	if err != nil {
		return discoveredTest{}, err
	}
	return discoveredTest{
		CandidateRequirementRefs: requirementRefs,
		NonClaims:                nonClaims,
		OracleSignals:            oracleSignals,
		OwnerID:                  ownerID,
		OwnerInvariantRefs:       invariantRefs,
		Selector:                 selector,
		SelectorSignals:          selectorSignals,
		SourcePath:               sourcePath,
		TestID:                   testID,
		Title:                    title,
	}, nil
}

func sortedRequirementRefs(raw any, context string) ([]string, error) {
	refs, err := sortedRuleIDs(raw, context, true)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref, "REQ-") {
			return nil, fmt.Errorf("%s entries must use REQ-* identifiers", context)
		}
	}
	return refs, nil
}

func optionalSortedText(raw any, context string) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	return sortedText(raw, context, true)
}

func sortedEnums(raw any, values map[string]struct{}, context string) ([]string, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		value, err := admit.Enum(item, values, context)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return admit.SortedText(result, context, true)
}

func discoveryWarnings(input discoveryDraftInput) []string {
	warnings := []string{}
	for _, test := range input.DiscoveredTests {
		if len(test.CandidateRequirementRefs) == 0 && len(test.OwnerInvariantRefs) == 0 {
			warnings = append(warnings, "missing_semantic_anchor:"+test.TestID)
		}
		if weakOracleSignals(test.OracleSignals) {
			warnings = append(warnings, "weak_or_empty_oracle:"+test.TestID)
		}
		if fragileSelectorSignals(test.SelectorSignals) {
			warnings = append(warnings, "selector_fragility:"+test.TestID)
		}
		warnings = append(warnings, "candidate_only:"+test.TestID)
	}
	return sortedUnique(warnings)
}

func discoveryActions(input discoveryDraftInput, warnings []string) []map[string]any {
	actions := []map[string]any{}
	for _, warning := range warnings {
		parts := strings.SplitN(warning, ":", 2)
		if len(parts) != 2 {
			continue
		}
		testID := parts[1]
		actionType := parts[0]
		message := discoveryActionMessage(actionType)
		actions = append(actions, map[string]any{
			"actionId":   "proofkit.test-inventory-draft." + testID + "." + strings.ReplaceAll(actionType, "_", "-"),
			"commandRef": input.Runner.CommandRef,
			"message":    message,
			"severity":   "review",
			"testId":     testID,
			"type":       actionType,
		})
	}
	sort.Slice(actions, func(left, right int) bool {
		return actions[left]["actionId"].(string) < actions[right]["actionId"].(string)
	})
	return actions
}

func discoveryActionMessage(actionType string) string {
	switch actionType {
	case "candidate_only":
		return "Materialize owner-reviewed strict test-evidence-inventory before using this test as coverage evidence."
	case "missing_semantic_anchor":
		return "Attach the test to a stable requirement or owner invariant before claiming semantic coverage."
	case "selector_fragility":
		return "Review selector stability before materializing this test as durable evidence."
	case "weak_or_empty_oracle":
		return "Add a falsifiable oracle or demote the test to route-only evidence."
	default:
		return "Review discovered test before materializing strict inventory."
	}
}

func discoveryCandidateInventory(input discoveryDraftInput) map[string]any {
	entries := []any{}
	scopeNonClaims := discoveryScopeNonClaims(input)
	for _, test := range input.DiscoveredTests {
		entryNonClaims := []string{
			"Discovery draft rows are candidate-only and cannot close semantic coverage.",
		}
		entryNonClaims = append(entryNonClaims, scopeNonClaims...)
		entryNonClaims = append(entryNonClaims, test.NonClaims...)
		entries = append(entries, map[string]any{
			"commandRefs":        admit.StringSliceToAny([]string{input.Runner.CommandRef}),
			"evidenceClass":      "routing_smoke_nonclaim",
			"falsifier":          nil,
			"nonClaims":          admit.StringSliceToAny(sortedUnique(entryNonClaims)),
			"oracle":             nil,
			"ownerId":            test.OwnerID,
			"ownerInvariantRefs": admit.StringSliceToAny(test.OwnerInvariantRefs),
			"qualityFindings":    discoveryQualityFindings(test),
			"requirementRefs":    admit.StringSliceToAny(test.CandidateRequirementRefs),
			"selector":           test.Selector,
			"sourcePath":         test.SourcePath,
			"testId":             test.TestID,
			"witnessRefs":        []any{},
		})
	}
	return map[string]any{
		"authority":     discoveryCandidateInventoryAuthority,
		"candidateKind": discoveryCandidateInventoryKind,
		"entries":       entries,
		"inventoryId":   input.DraftID + ".candidate_inventory",
		"nonClaims":     admit.StringSliceToAny(scopeNonClaims),
		"schemaVersion": 1,
	}
}

func discoveryScopeNonClaims(input discoveryDraftInput) []string {
	nonClaims := discoveryDefaultNonClaims()
	nonClaims = append(nonClaims, input.NonClaims...)
	nonClaims = append(nonClaims, input.Repository.NonClaims...)
	nonClaims = append(nonClaims, input.Runner.NonClaims...)
	return sortedUnique(nonClaims)
}

func discoveryQualityFindings(test discoveredTest) []any {
	findings := []any{
		discoveryQualityFinding(test.TestID, "candidate_only", "wrong_boundary", "warning"),
	}
	if len(test.CandidateRequirementRefs) == 0 && len(test.OwnerInvariantRefs) == 0 {
		findings = append(findings, discoveryQualityFinding(test.TestID, "missing-semantic-anchor", "missing_edge", "warning"))
	}
	if weakOracleSignals(test.OracleSignals) {
		findings = append(findings, discoveryQualityFinding(test.TestID, "weak-oracle", "empty_oracle", "warning"))
	}
	if fragileSelectorSignals(test.SelectorSignals) {
		findings = append(findings, discoveryQualityFinding(test.TestID, "selector-fragility", "wrong_boundary", "warning"))
	}
	return findings
}

func discoveryQualityFinding(testID string, suffix string, class string, severity string) map[string]any {
	return map[string]any{
		"class":            class,
		"evidenceRefs":     []any{testID},
		"findingId":        "finding." + testID + "." + suffix,
		"nonClaims":        []any{"Discovery draft quality findings are candidate owner-review guidance only."},
		"ownerReviewState": "candidate",
		"severity":         severity,
	}
}

func weakOracleSignals(signals []string) bool {
	if len(signals) == 0 {
		return true
	}
	strong := map[string]struct{}{
		"assertion_present":        {},
		"expected_exception":       {},
		"status_or_exit_assertion": {},
	}
	for _, signal := range signals {
		if _, ok := strong[signal]; ok {
			return false
		}
	}
	return true
}

func fragileSelectorSignals(signals []string) bool {
	fragile := map[string]struct{}{
		"first_or_last_selector": {},
		"nth_selector":           {},
		"raw_css_selector":       {},
		"text_selector":          {},
		"unknown":                {},
		"xpath_selector":         {},
	}
	for _, signal := range signals {
		if _, ok := fragile[signal]; ok {
			return true
		}
	}
	return false
}

func discoveredTestIDs(tests []discoveredTest) []string {
	ids := make([]string, 0, len(tests))
	for _, test := range tests {
		ids = append(ids, test.TestID)
	}
	return ids
}

func discoveryDefaultNonClaims() []string {
	return []string{
		"Discovery draft reports do not discover repository files or execute native tests.",
		"Discovery draft reports do not infer semantic test intent from names, paths, prose, mocks, or snapshots.",
		"Discovery draft candidate inventory rows do not prove coverage, freshness, merge readiness, rollout, or repository policy.",
	}
}
