package testevidenceinventory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const ReportKind = "proofkit.test-evidence-inventory"
const NormalizedInventoryKind = "proofkit.test-evidence-inventory.normalized"
const directAuthority = "caller_owned_inventory"
const sourceSetAuthority = "caller_owned_inventory_source_set"
const wrappedInventorySchema = "proofkit.requirement-test-inventory.v1"

var evidenceClassSet = map[string]struct{}{
	"benchmark":              {},
	"contract_admission":     {},
	"governance_or_release":  {},
	"helper_or_testkit":      {},
	"property_or_fuzz":       {},
	"routing_smoke_nonclaim": {},
	"semantic_falsifier":     {},
}

var qualityFindingClassSet = map[string]struct{}{
	"duplicate_falsifier_candidate": {},
	"empty_oracle":                  {},
	"fixture_leak_risk":             {},
	"flaky_time":                    {},
	"implementation_mirror":         {},
	"import_cost_leak":              {},
	"missing_edge":                  {},
	"mock_tests_mock":               {},
	"over_broad_integration":        {},
	"snapshot_without_oracle":       {},
	"tautology":                     {},
	"unasserted_diagnostic":         {},
	"wrong_boundary":                {},
}

var qualityFindingSeveritySet = map[string]struct{}{
	"failure": {},
	"warning": {},
}

var qualityFindingReviewStateSet = map[string]struct{}{
	"candidate": {},
	"confirmed": {},
}

var defaultNonClaims = []string{
	"Test evidence inventory reports do not execute native tests.",
	"Test evidence inventory reports do not prove repository inventory completeness.",
	"Test evidence inventory reports do not authenticate runner output or receipt producers.",
	"Test evidence inventory reports do not approve merge, release, rollout, or repository policy.",
}

type Inventory struct {
	Authority    string
	Entries      []Entry
	EntrySources []EntrySourceMetadata
	InputPaths   []string
	InventoryID  string
	NonClaims    []string
	OwnerID      string
	SourceRows   []SourceMetadata
	SourceCount  int
	SourceID     string
}

type Entry struct {
	CommandRefs        []string
	EvidenceClass      string
	Falsifier          *Falsifier
	NonClaims          []string
	Oracle             *Oracle
	OwnerID            string
	OwnerInvariantRefs []string
	QualityFindings    []QualityFinding
	RequirementRefs    []string
	Selector           string
	SourcePath         string
	TestID             string
	WitnessRefs        []string
}

type QualityFinding struct {
	Class            string
	EvidenceRefs     []string
	FindingID        string
	NonClaims        []string
	OwnerReviewState string
	Severity         string
}

type SourceMetadata struct {
	NonClaims []string
	Path      string
	Role      string
	SHA256    string
	SourceID  string
}

type EntrySourceMetadata struct {
	Path     string
	SourceID string
	TestID   string
}

type Falsifier struct {
	DominanceGroup             string
	FalsifierID                string
	NegativeCaseID             string
	Supersedes                 []string
	WrongImplementationClassID string
}

type Oracle struct {
	AssertionSummary string
	OracleID         string
	OracleKind       string
}

type Result struct {
	ExitCode  int
	Failures  []string
	Inventory Inventory
	Report    report.Record
	Warnings  []string
}

func Build(raw any) (report.Record, int, error) {
	result, err := Evaluate(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	return result.Report, result.ExitCode, nil
}

func BuildNormalized(raw any) (map[string]any, int, error) {
	result, err := Evaluate(raw)
	if err != nil {
		return nil, 1, err
	}
	if result.ExitCode != 0 {
		return result.Report.JSONValue(), result.ExitCode, nil
	}
	return normalizedInventoryValue(result.Inventory), 0, nil
}

func Evaluate(raw any) (Result, error) {
	inventory, err := admitInventory(raw)
	if err != nil {
		return Result{}, err
	}
	failures, warnings := classify(inventory)
	sort.Strings(failures)
	sort.Strings(warnings)
	state := "passed"
	exitCode := 0
	if len(failures) > 0 {
		state = "failed"
		exitCode = 1
	}
	nonClaims := sortedUnique(append(append([]string{}, defaultNonClaims...), inventory.NonClaims...))
	actionPlan := agentActionPlan(failures, warnings)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    ReportKind,
		ReportID:      inventory.InventoryID,
		State:         state,
		Summary: map[string]any{
			"agentActionCount":           len(actionPlan),
			"entryCount":                 len(inventory.Entries),
			"failureCount":               len(failures),
			"inputPathCount":             len(inventory.InputPaths),
			"qualityFindingFailureCount": countPrefix(failures, "quality_finding:"),
			"qualityFindingWarningCount": countPrefix(warnings, "quality_finding:"),
			"routeOnlyNonClaimCount":     countEvidenceClass(inventory.Entries, "routing_smoke_nonclaim"),
			"semanticFalsifierCount":     countEvidenceClass(inventory.Entries, "semantic_falsifier"),
			"sourceCount":                inventory.SourceCount,
			"weakOracleFailureCount":     countContains(failures, "weak_or_empty_oracle"),
			"wrongBoundaryFailureCount":  countContains(failures, "wrong_evidence_boundary"),
			"warningCount":               len(warnings),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "agentActionPlan", Value: mapsToAny(actionPlan)},
			{Key: "failureClassifications", Value: mapsToAny(diagnosticClassifications(failures, "failure"))},
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "warningClassifications", Value: mapsToAny(diagnosticClassifications(warnings, "warning"))},
			{Key: "warnings", Value: admit.StringSliceToAny(warnings)},
		},
		RuleResults: ruleResults(failures, warnings),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	return Result{ExitCode: exitCode, Failures: failures, Inventory: inventory, Report: record, Warnings: warnings}, nil
}

func normalizedInventoryValue(inventory Inventory) map[string]any {
	nonClaims := make([]string, 0, len(defaultNonClaims)+len(inventory.NonClaims))
	nonClaims = append(nonClaims, defaultNonClaims...)
	nonClaims = append(nonClaims, inventory.NonClaims...)
	nonClaims = sortedUnique(nonClaims)
	return map[string]any{
		"schemaVersion":         1,
		"normalizedInventoryId": inventory.InventoryID + ".normalized",
		"normalizedKind":        NormalizedInventoryKind,
		"sourceAuthority":       inventory.Authority,
		"sourceCount":           inventory.SourceCount,
		"sourceColumns":         admit.StringSliceToAny(sourceSetColumns),
		"sources":               sourceRowsToAny(inventory.SourceRows),
		"entrySources":          entrySourcesToAny(inventory.EntrySources),
		"inputPaths":            admit.StringSliceToAny(inventory.InputPaths),
		"inventory": map[string]any{
			"schemaVersion": 1,
			"inventoryId":   inventory.InventoryID,
			"authority":     directAuthority,
			"entries":       entriesToAny(inventory.Entries),
			"nonClaims":     admit.StringSliceToAny(nonClaims),
		},
		"nonClaims": admit.StringSliceToAny(sortedUnique([]string{
			"Normalized test evidence inventory is a deterministic projection over explicit caller-owned inventory input.",
			"Normalized test evidence inventory does not discover repository files, execute tests, authenticate receipts, or approve merge, release, rollout, or repository policy.",
		})),
	}
}

func sourceRowsToAny(rows []SourceMetadata) []any {
	result := make([]any, 0, len(rows))
	for _, row := range rows {
		result = append(result, []any{
			row.SourceID,
			row.Path,
			row.SHA256,
			row.Role,
			admit.StringSliceToAny(row.NonClaims),
		})
	}
	return result
}

func entrySourcesToAny(rows []EntrySourceMetadata) []any {
	result := make([]any, len(rows))
	for index, row := range rows {
		result[index] = map[string]any{
			"path":     row.Path,
			"sourceId": row.SourceID,
			"testId":   row.TestID,
		}
	}
	return result
}

func entriesToAny(entries []Entry) []any {
	result := make([]any, 0, len(entries))
	for _, entry := range entries {
		record := map[string]any{
			"commandRefs":        admit.StringSliceToAny(entry.CommandRefs),
			"evidenceClass":      entry.EvidenceClass,
			"falsifier":          falsifierToAny(entry.Falsifier),
			"nonClaims":          admit.StringSliceToAny(entry.NonClaims),
			"oracle":             oracleToAny(entry.Oracle),
			"ownerId":            entry.OwnerID,
			"ownerInvariantRefs": admit.StringSliceToAny(entry.OwnerInvariantRefs),
			"qualityFindings":    qualityFindingsToAny(entry.QualityFindings),
			"requirementRefs":    admit.StringSliceToAny(entry.RequirementRefs),
			"selector":           entry.Selector,
			"sourcePath":         entry.SourcePath,
			"testId":             entry.TestID,
			"witnessRefs":        admit.StringSliceToAny(entry.WitnessRefs),
		}
		result = append(result, record)
	}
	return result
}

func qualityFindingsToAny(findings []QualityFinding) []any {
	result := make([]any, 0, len(findings))
	for _, finding := range findings {
		result = append(result, map[string]any{
			"class":            finding.Class,
			"evidenceRefs":     admit.StringSliceToAny(finding.EvidenceRefs),
			"findingId":        finding.FindingID,
			"nonClaims":        admit.StringSliceToAny(finding.NonClaims),
			"ownerReviewState": finding.OwnerReviewState,
			"severity":         finding.Severity,
		})
	}
	return result
}

func falsifierToAny(falsifier *Falsifier) any {
	if falsifier == nil {
		return nil
	}
	return map[string]any{
		"dominanceGroup":             falsifier.DominanceGroup,
		"falsifierId":                falsifier.FalsifierID,
		"negativeCaseId":             falsifier.NegativeCaseID,
		"supersedes":                 admit.StringSliceToAny(falsifier.Supersedes),
		"wrongImplementationClassId": falsifier.WrongImplementationClassID,
	}
}

func oracleToAny(oracle *Oracle) any {
	if oracle == nil {
		return nil
	}
	return map[string]any{
		"assertionSummary": oracle.AssertionSummary,
		"oracleId":         oracle.OracleID,
		"oracleKind":       oracle.OracleKind,
	}
}

func admitInventory(raw any) (Inventory, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Inventory{}, fmt.Errorf("test evidence inventory input must be an object")
	}
	unwrapped, err := unwrapInventory(record, "test evidence inventory input")
	if err != nil {
		return Inventory{}, err
	}
	authority, ok := unwrapped["authority"].(string)
	if !ok {
		return Inventory{}, fmt.Errorf("test evidence inventory authority must be %s or %s", directAuthority, sourceSetAuthority)
	}
	if authority == sourceSetAuthority {
		return admitSourceSetInventory(unwrapped)
	}
	return admitDirectInventory(unwrapped, "test evidence inventory input")
}

func unwrapInventory(record map[string]any, context string) (map[string]any, error) {
	if _, hasSchema := record["schema"]; !hasSchema {
		return record, nil
	}
	if err := admit.KnownKeys(record, []string{"inventory", "schema"}, context); err != nil {
		return nil, err
	}
	if record["schema"] != wrappedInventorySchema {
		return nil, fmt.Errorf("%s schema must be %s", context, wrappedInventorySchema)
	}
	inventory, ok := record["inventory"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s inventory must be an object", context)
	}
	return inventory, nil
}

func admitDirectInventory(record map[string]any, context string) (Inventory, error) {
	if err := admit.KnownKeys(record, []string{"authority", "entries", "inventoryId", "nonClaims", "ownerId", "schemaVersion", "sourceId"}, context); err != nil {
		return Inventory{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Inventory{}, fmt.Errorf("%s schemaVersion must be 1", context)
	}
	authority, err := literal(record["authority"], directAuthority, context+" authority")
	if err != nil {
		return Inventory{}, err
	}
	inventoryID, err := admit.RuleID(record["inventoryId"], context+" inventoryId")
	if err != nil {
		return Inventory{}, err
	}
	entries, err := entries(record["entries"])
	if err != nil {
		return Inventory{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], context+" nonClaims", false)
	if err != nil {
		return Inventory{}, err
	}
	ownerID, err := optionalRuleID(record["ownerId"], context+" ownerId")
	if err != nil {
		return Inventory{}, err
	}
	sourceID, err := optionalRuleID(record["sourceId"], context+" sourceId")
	if err != nil {
		return Inventory{}, err
	}
	return Inventory{Authority: authority, Entries: entries, InventoryID: inventoryID, NonClaims: nonClaims, OwnerID: ownerID, SourceID: sourceID}, nil
}

func entries(raw any) ([]Entry, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("test evidence inventory entries must be an array")
	}
	result := make([]Entry, 0, len(values))
	for _, value := range values {
		entry, err := admitEntry(value)
		if err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].TestID < result[right].TestID })
	if err := assertUnique(entryIDs(result), "test evidence inventory testIds"); err != nil {
		return nil, err
	}
	return result, nil
}

func admitEntry(raw any) (Entry, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Entry{}, fmt.Errorf("test evidence inventory entry must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandRefs", "evidenceClass", "falsifier", "nonClaims", "oracle", "ownerId", "ownerInvariantRefs", "qualityFindings", "requirementRefs", "selector", "sourcePath", "testId", "witnessRefs"}, "test evidence inventory entry"); err != nil {
		return Entry{}, err
	}
	testID, err := admit.RuleID(record["testId"], "test evidence inventory testId")
	if err != nil {
		return Entry{}, err
	}
	selector, err := admit.DisplayOnlyCommandText(record["selector"], fmt.Sprintf("test evidence inventory %s selector", testID))
	if err != nil {
		return Entry{}, err
	}
	sourceText, err := admit.NonEmptyText(record["sourcePath"], fmt.Sprintf("test evidence inventory %s sourcePath", testID))
	if err != nil {
		return Entry{}, err
	}
	sourcePath, err := admit.SafeRepoRelativePath(sourceText, fmt.Sprintf("test evidence inventory %s sourcePath", testID))
	if err != nil {
		return Entry{}, err
	}
	if err := admitStructuredSelectorSourcePath(selector, sourcePath, fmt.Sprintf("test evidence inventory %s selector", testID)); err != nil {
		return Entry{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], fmt.Sprintf("test evidence inventory %s ownerId", testID))
	if err != nil {
		return Entry{}, err
	}
	evidenceClass, err := admit.Enum(record["evidenceClass"], evidenceClassSet, fmt.Sprintf("test evidence inventory %s evidenceClass", testID))
	if err != nil {
		return Entry{}, err
	}
	requirementRefs, err := sortedRuleIDs(record["requirementRefs"], fmt.Sprintf("test evidence inventory %s requirementRefs", testID), true)
	if err != nil {
		return Entry{}, err
	}
	ownerInvariantRefs, err := sortedRuleIDs(record["ownerInvariantRefs"], fmt.Sprintf("test evidence inventory %s ownerInvariantRefs", testID), true)
	if err != nil {
		return Entry{}, err
	}
	commandRefs, err := sortedRuleIDs(record["commandRefs"], fmt.Sprintf("test evidence inventory %s commandRefs", testID), true)
	if err != nil {
		return Entry{}, err
	}
	witnessRefs, err := sortedRuleIDs(record["witnessRefs"], fmt.Sprintf("test evidence inventory %s witnessRefs", testID), true)
	if err != nil {
		return Entry{}, err
	}
	falsifier, err := admitFalsifier(record["falsifier"], testID)
	if err != nil {
		return Entry{}, err
	}
	oracle, err := admitOracle(record["oracle"], testID)
	if err != nil {
		return Entry{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], fmt.Sprintf("test evidence inventory %s nonClaims", testID), true)
	if err != nil {
		return Entry{}, err
	}
	qualityFindings, err := admitQualityFindings(record["qualityFindings"], testID)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		CommandRefs: commandRefs, EvidenceClass: evidenceClass, Falsifier: falsifier,
		NonClaims: nonClaims, Oracle: oracle, OwnerID: ownerID, OwnerInvariantRefs: ownerInvariantRefs,
		QualityFindings: qualityFindings, RequirementRefs: requirementRefs, Selector: selector, SourcePath: sourcePath, TestID: testID,
		WitnessRefs: witnessRefs,
	}, nil
}

func admitStructuredSelectorSourcePath(selector string, sourcePath string, context string) error {
	if !strings.Contains(selector, "::") {
		return nil
	}
	parts := strings.Split(selector, "::")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%s must use repo/path::stable_anchor when it declares source identity", context)
	}
	selectorPath, err := admit.SafeRepoRelativePath(parts[0], context+" source path")
	if err != nil {
		return err
	}
	if _, err := admit.RuleID(parts[1], context+" anchor"); err != nil {
		return err
	}
	if selectorPath != sourcePath {
		return fmt.Errorf("%s sourcePath must match selector path: %s !== %s", context, sourcePath, selectorPath)
	}
	return nil
}

func admitFalsifier(raw any, testID string) (*Falsifier, error) {
	if raw == nil {
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("test evidence inventory %s falsifier must be an object or null", testID)
	}
	if err := admit.KnownKeys(record, []string{"dominanceGroup", "falsifierId", "negativeCaseId", "supersedes", "wrongImplementationClassId"}, "test evidence inventory falsifier"); err != nil {
		return nil, err
	}
	falsifierID, err := admit.RuleID(record["falsifierId"], fmt.Sprintf("test evidence inventory %s falsifierId", testID))
	if err != nil {
		return nil, err
	}
	negativeCaseID, err := admit.RuleID(record["negativeCaseId"], fmt.Sprintf("test evidence inventory %s negativeCaseId", testID))
	if err != nil {
		return nil, err
	}
	wrongImplementationClassID, err := admit.RuleID(record["wrongImplementationClassId"], fmt.Sprintf("test evidence inventory %s wrongImplementationClassId", testID))
	if err != nil {
		return nil, err
	}
	dominanceGroup, err := admit.RuleID(record["dominanceGroup"], fmt.Sprintf("test evidence inventory %s dominanceGroup", testID))
	if err != nil {
		return nil, err
	}
	supersedes, err := sortedRuleIDs(record["supersedes"], fmt.Sprintf("test evidence inventory %s supersedes", testID), true)
	if err != nil {
		return nil, err
	}
	return &Falsifier{
		DominanceGroup: dominanceGroup, FalsifierID: falsifierID,
		NegativeCaseID: negativeCaseID, Supersedes: supersedes,
		WrongImplementationClassID: wrongImplementationClassID,
	}, nil
}

func admitOracle(raw any, testID string) (*Oracle, error) {
	if raw == nil {
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("test evidence inventory %s oracle must be an object or null", testID)
	}
	if err := admit.KnownKeys(record, []string{"assertionSummary", "oracleId", "oracleKind"}, "test evidence inventory oracle"); err != nil {
		return nil, err
	}
	oracleID, err := admit.RuleID(record["oracleId"], fmt.Sprintf("test evidence inventory %s oracleId", testID))
	if err != nil {
		return nil, err
	}
	oracleKind, err := admit.RuleID(record["oracleKind"], fmt.Sprintf("test evidence inventory %s oracleKind", testID))
	if err != nil {
		return nil, err
	}
	assertionSummary, err := optionalText(record["assertionSummary"], fmt.Sprintf("test evidence inventory %s assertionSummary", testID))
	if err != nil {
		return nil, err
	}
	return &Oracle{AssertionSummary: assertionSummary, OracleID: oracleID, OracleKind: oracleKind}, nil
}

func admitQualityFindings(raw any, testID string) ([]QualityFinding, error) {
	if raw == nil {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("test evidence inventory %s qualityFindings must be an array", testID)
	}
	result := make([]QualityFinding, 0, len(values))
	for index, value := range values {
		finding, err := admitQualityFinding(value, testID, index)
		if err != nil {
			return nil, err
		}
		result = append(result, finding)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].FindingID < result[right].FindingID })
	if err := assertUnique(qualityFindingIDs(result), fmt.Sprintf("test evidence inventory %s qualityFindingIds", testID)); err != nil {
		return nil, err
	}
	return result, nil
}

func admitQualityFinding(raw any, testID string, index int) (QualityFinding, error) {
	record, ok := raw.(map[string]any)
	context := fmt.Sprintf("test evidence inventory %s qualityFinding #%d", testID, index+1)
	if !ok {
		return QualityFinding{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"class", "evidenceRefs", "findingId", "nonClaims", "ownerReviewState", "severity"}, context); err != nil {
		return QualityFinding{}, err
	}
	findingID, err := admit.RuleID(record["findingId"], context+" findingId")
	if err != nil {
		return QualityFinding{}, err
	}
	class, err := admit.Enum(record["class"], qualityFindingClassSet, context+" class")
	if err != nil {
		return QualityFinding{}, err
	}
	severity, err := admit.Enum(record["severity"], qualityFindingSeveritySet, context+" severity")
	if err != nil {
		return QualityFinding{}, err
	}
	reviewState, err := admit.Enum(record["ownerReviewState"], qualityFindingReviewStateSet, context+" ownerReviewState")
	if err != nil {
		return QualityFinding{}, err
	}
	evidenceRefs, err := sortedRuleIDs(record["evidenceRefs"], context+" evidenceRefs", false)
	if err != nil {
		return QualityFinding{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], context+" nonClaims", false)
	if err != nil {
		return QualityFinding{}, err
	}
	return QualityFinding{
		Class: class, EvidenceRefs: evidenceRefs, FindingID: findingID,
		NonClaims: nonClaims, OwnerReviewState: reviewState, Severity: severity,
	}, nil
}

func classify(inventory Inventory) ([]string, []string) {
	failures := []string{}
	warnings := []string{}
	falsifiers := inventoryFalsifiers(inventory.Entries)
	for _, entry := range inventory.Entries {
		if requiresSemanticAnchor(entry.EvidenceClass) && len(entry.RequirementRefs) == 0 && len(entry.OwnerInvariantRefs) == 0 {
			failures = append(failures, fmt.Sprintf("missing_semantic_anchor:%s", entry.TestID))
		}
		if requiresExecutableCommandRefs(entry.EvidenceClass) && len(entry.CommandRefs) == 0 {
			failures = append(failures, fmt.Sprintf("missing_executable_command_ref:%s", entry.TestID))
		}
		if requiresStrongOracle(entry.EvidenceClass) && !hasStrongOracle(entry) {
			failures = append(failures, fmt.Sprintf("weak_or_empty_oracle:%s", entry.TestID))
		}
		if entry.EvidenceClass == "routing_smoke_nonclaim" {
			if len(entry.RequirementRefs) > 0 || len(entry.OwnerInvariantRefs) > 0 {
				failures = append(failures, fmt.Sprintf("wrong_evidence_boundary:%s", entry.TestID))
			} else {
				warnings = append(warnings, fmt.Sprintf("route_only_nonclaim:%s", entry.TestID))
			}
		}
		for _, finding := range entry.QualityFindings {
			diagnostic := fmt.Sprintf("quality_finding:%s:%s:%s", finding.Class, entry.TestID, finding.FindingID)
			if finding.Severity == "failure" {
				failures = append(failures, diagnostic)
			} else {
				warnings = append(warnings, diagnostic)
			}
		}
	}
	failures = append(failures, classifyFalsifierSupersession(falsifiers)...)
	return sortedUnique(failures), sortedUnique(warnings)
}

type falsifierLedgerEntry struct {
	FalsifierID string
	Key         string
	Supersedes  []string
	TestID      string
}

func inventoryFalsifiers(entries []Entry) []falsifierLedgerEntry {
	out := []falsifierLedgerEntry{}
	for _, entry := range entries {
		if entry.Falsifier == nil || entry.Oracle == nil {
			continue
		}
		out = append(out, falsifierLedgerEntry{
			FalsifierID: entry.Falsifier.FalsifierID,
			Key:         falsifierEquivalenceKey(entry),
			Supersedes:  entry.Falsifier.Supersedes,
			TestID:      entry.TestID,
		})
	}
	return out
}

func falsifierEquivalenceKey(entry Entry) string {
	return strings.Join([]string{entry.Falsifier.DominanceGroup, entry.Falsifier.WrongImplementationClassID, entry.Falsifier.NegativeCaseID, entry.Oracle.OracleKind}, "\x00")
}

func classifyFalsifierSupersession(entries []falsifierLedgerEntry) []string {
	failures := []string{}
	byID := map[string]falsifierLedgerEntry{}
	byKey := map[string][]falsifierLedgerEntry{}
	for _, entry := range entries {
		byID[entry.FalsifierID] = entry
		byKey[entry.Key] = append(byKey[entry.Key], entry)
	}
	invalidFalsifierIDs := map[string]struct{}{}
	supersededByKey := map[string]map[string]struct{}{}
	for _, entry := range entries {
		for _, supersededID := range entry.Supersedes {
			superseded, ok := byID[supersededID]
			if !ok {
				failures = append(failures, fmt.Sprintf("invalid_falsifier_supersession:%s:unknown:%s", entry.TestID, supersededID))
				invalidFalsifierIDs[entry.FalsifierID] = struct{}{}
				continue
			}
			if superseded.Key != entry.Key {
				failures = append(failures, fmt.Sprintf("invalid_falsifier_supersession:%s:cross_equivalence:%s", entry.TestID, supersededID))
				invalidFalsifierIDs[entry.FalsifierID] = struct{}{}
				continue
			}
			if supersededByKey[entry.Key] == nil {
				supersededByKey[entry.Key] = map[string]struct{}{}
			}
			supersededByKey[entry.Key][supersededID] = struct{}{}
		}
	}
	for _, group := range byKey {
		active := []falsifierLedgerEntry{}
		for _, entry := range group {
			if _, invalid := invalidFalsifierIDs[entry.FalsifierID]; invalid {
				continue
			}
			if _, superseded := supersededByKey[entry.Key][entry.FalsifierID]; !superseded {
				active = append(active, entry)
			}
		}
		switch {
		case len(active) == 0 && len(group) > 0:
			failures = append(failures, fmt.Sprintf("invalid_falsifier_supersession:%s:no_active_equivalence_owner", group[0].TestID))
		case len(active) > 1:
			sort.Slice(active, func(left, right int) bool { return active[left].TestID < active[right].TestID })
			for index := 1; index < len(active); index++ {
				failures = append(failures, fmt.Sprintf("declared_duplicate_falsifier:%s:%s", active[0].TestID, active[index].TestID))
			}
		}
	}
	return failures
}

func requiresSemanticAnchor(evidenceClass string) bool {
	switch evidenceClass {
	case "semantic_falsifier", "contract_admission", "property_or_fuzz", "governance_or_release", "benchmark":
		return true
	default:
		return false
	}
}

func requiresStrongOracle(evidenceClass string) bool {
	switch evidenceClass {
	case "semantic_falsifier", "contract_admission", "property_or_fuzz":
		return true
	default:
		return false
	}
}

func requiresExecutableCommandRefs(evidenceClass string) bool {
	return evidenceClass == "semantic_falsifier"
}

func hasStrongOracle(entry Entry) bool {
	return entry.Falsifier != nil && entry.Oracle != nil && strings.TrimSpace(entry.Oracle.AssertionSummary) != ""
}

func ruleResults(failures []string, warnings []string) []report.RuleResult {
	return []report.RuleResult{
		rule("test_inventory.input_admitted", "passed", "Test inventory input used strict known-key admission."),
		ruleStatus("test_inventory.semantic_entries_have_anchors", !hasPrefix(failures, "missing_semantic_anchor"), "Semantic test inventory entries must cite requirement refs or stable owner invariant refs."),
		ruleStatus("test_inventory.semantic_falsifiers_have_commands", !hasPrefix(failures, "missing_executable_command_ref"), "Semantic falsifier entries must cite executable command refs."),
		ruleStatus("test_inventory.strong_oracles", !hasPrefix(failures, "weak_or_empty_oracle"), "Semantic falsifier entries must declare a falsifier and a non-empty assertion oracle."),
		ruleStatus("test_inventory.no_duplicate_falsifiers", !hasPrefix(failures, "declared_duplicate_falsifier") && !hasPrefix(failures, "invalid_falsifier_supersession"), "Duplicate falsifier equivalence keys require explicit same-equivalence supersession."),
		ruleStatus("test_inventory.route_only_boundaries", !hasPrefix(failures, "wrong_evidence_boundary"), "Route-only smoke evidence must remain a non-claim and cannot cite semantic requirement anchors."),
		ruleStatus("test_inventory.route_only_warnings", len(warnings) == 0, "Route-only entries are admitted as non-claim warnings only."),
	}
}

func ruleStatus(ruleID string, passed bool, message string) report.RuleResult {
	if passed {
		return rule(ruleID, "passed", message)
	}
	return rule(ruleID, "failed", message)
}

func rule(ruleID string, status string, message string) report.RuleResult {
	return report.RuleResult{RuleID: ruleID, Status: status, Message: message}
}

func diagnosticClassifications(diagnostics []string, severity string) []map[string]any {
	result := make([]map[string]any, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, map[string]any{
			"classificationId": diagnosticClassID(diagnostic),
			"diagnostic":       diagnostic,
			"severity":         severity,
		})
	}
	sort.Slice(result, func(left, right int) bool {
		leftKey := result[left]["classificationId"].(string) + "\x00" + result[left]["diagnostic"].(string)
		rightKey := result[right]["classificationId"].(string) + "\x00" + result[right]["diagnostic"].(string)
		return leftKey < rightKey
	})
	return result
}

func diagnosticClassID(diagnostic string) string {
	switch {
	case strings.HasPrefix(diagnostic, "declared_duplicate_falsifier:"):
		return "declared_duplicate_falsifier"
	case strings.HasPrefix(diagnostic, "invalid_falsifier_supersession:"):
		return "invalid_falsifier_supersession"
	case strings.HasPrefix(diagnostic, "missing_semantic_anchor:"):
		return "missing_semantic_anchor"
	case strings.HasPrefix(diagnostic, "missing_executable_command_ref:"):
		return "missing_executable_command_ref"
	case strings.HasPrefix(diagnostic, "quality_finding:"):
		parts := strings.SplitN(diagnostic, ":", 4)
		if len(parts) >= 2 {
			return parts[1]
		}
	case strings.HasPrefix(diagnostic, "route_only_nonclaim:"):
		return "routing_smoke_only"
	case strings.HasPrefix(diagnostic, "weak_or_empty_oracle:"):
		return "weak_or_empty_oracle"
	case strings.HasPrefix(diagnostic, "wrong_evidence_boundary:"):
		return "wrong_evidence_boundary"
	}
	return "unclassified_test_inventory_gap"
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func literal(raw any, expected string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || value != expected {
		return "", fmt.Errorf("%s must be %s", context, expected)
	}
	return value, nil
}

func optionalRuleID(raw any, context string) (string, error) {
	if raw == nil {
		return "", nil
	}
	return admit.RuleID(raw, context)
}

func optionalText(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be text", context)
	}
	if admit.ContainsSecretLikeValue(value) {
		return "", fmt.Errorf("%s must not contain secret-like values", context)
	}
	return strings.TrimSpace(value), nil
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		value, err := admit.RuleID(item, context)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return admit.PreserveSortedText(result, context, allowEmpty)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return admit.PreserveSortedText(values, context, allowEmpty)
}

func assertUnique(values []string, context string) error {
	_, err := admit.PreserveSortedText(values, context, true)
	return err
}

func entryIDs(entries []Entry) []string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry.TestID)
	}
	sort.Strings(values)
	return values
}

func qualityFindingIDs(findings []QualityFinding) []string {
	values := make([]string, 0, len(findings))
	for _, finding := range findings {
		values = append(values, finding.FindingID)
	}
	sort.Strings(values)
	return values
}

func countEvidenceClass(entries []Entry, evidenceClass string) int {
	count := 0
	for _, entry := range entries {
		if entry.EvidenceClass == evidenceClass {
			count++
		}
	}
	return count
}

func countContains(values []string, fragment string) int {
	count := 0
	for _, value := range values {
		if strings.Contains(value, fragment) {
			count++
		}
	}
	return count
}

func countPrefix(values []string, prefix string) int {
	count := 0
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			count++
		}
	}
	return count
}

func hasPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			result = append(result, value)
			previous = value
		}
	}
	return append([]string{}, result...)
}
