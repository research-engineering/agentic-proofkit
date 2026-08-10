package requirementcoverageview

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var projectedTestKeys = []string{
	"commandRefs", "dominanceGroup", "evidenceClass", "expectedPublicOutcome", "falsifierId",
	"negativeCaseId", "nonClaims", "oracleId", "oracleKind", "oracleSummary", "ownerId",
	"ownerInvariantRefs", "qualityFindings", "requirementRefs", "selector", "sourcePath",
	"supersedes", "supersessionDeclarationRef", "testId", "witnessRefs", "wrongImplementationClassId",
}

var projectedQualityFindingKeys = []string{
	"class", "evidenceRefs", "findingId", "nonClaims", "ownerReviewState", "severity",
}

func admitProjectedTestSemantics(raw any, context string) ([]testevidenceinventory.Entry, error) {
	tests, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	entries := make([]testevidenceinventory.Entry, 0, len(tests))
	previousID := ""
	for testIndex, rawTest := range tests {
		test, ok := rawTest.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, testIndex)
		}
		testContext := fmt.Sprintf("%s[%d]", context, testIndex)
		if err := admit.KnownKeys(test, projectedTestKeys, testContext); err != nil {
			return nil, err
		}
		testID, err := admit.RuleID(test["testId"], testContext+" testId")
		if err != nil {
			return nil, err
		}
		if previousID != "" && previousID >= testID {
			return nil, fmt.Errorf("%s must be sorted and unique by testId", context)
		}
		previousID = testID
		evidenceClass, err := testevidenceinventory.AdmitEvidenceClass(test["evidenceClass"], testContext+" evidenceClass")
		if err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(test["ownerId"], testContext+" ownerId")
		if err != nil {
			return nil, err
		}
		commandRefs, err := admitProjectedRuleIDs(test["commandRefs"], testContext+" commandRefs")
		if err != nil {
			return nil, err
		}
		ownerInvariantRefs, err := admitProjectedRuleIDs(test["ownerInvariantRefs"], testContext+" ownerInvariantRefs")
		if err != nil {
			return nil, err
		}
		requirementRefs, err := admitProjectedRuleIDs(test["requirementRefs"], testContext+" requirementRefs")
		if err != nil {
			return nil, err
		}
		witnessRefs, err := admitProjectedRuleIDs(test["witnessRefs"], testContext+" witnessRefs")
		if err != nil {
			return nil, err
		}
		selector, err := admit.DisplayOnlyCommandText(test["selector"], testContext+" selector")
		if err != nil {
			return nil, err
		}
		if err := requireCanonicalWireString(test["selector"], selector, testContext+" selector"); err != nil {
			return nil, err
		}
		sourceText, err := admit.NonEmptyText(test["sourcePath"], testContext+" sourcePath")
		if err != nil {
			return nil, err
		}
		sourcePath, err := admit.SafeRepoRelativePath(sourceText, testContext+" sourcePath")
		if err != nil {
			return nil, err
		}
		if sourcePath != sourceText {
			return nil, fmt.Errorf("%s sourcePath must be canonical", testContext)
		}
		if err := admit.StructuredSelectorSourcePath(selector, sourcePath, testContext+" selector"); err != nil {
			return nil, err
		}
		nonClaims, err := admit.PreserveSortedTextArray(test["nonClaims"], testContext+" nonClaims", true)
		if err != nil {
			return nil, err
		}
		expectedPublicOutcome, err := admitProjectedOptionalText(test["expectedPublicOutcome"], testContext+" expectedPublicOutcome")
		if err != nil {
			return nil, err
		}
		oracleSummary, err := admitProjectedOptionalText(test["oracleSummary"], testContext+" oracleSummary")
		if err != nil {
			return nil, err
		}
		oracleKind, err := admitProjectedOptionalRuleID(test["oracleKind"], testContext+" oracleKind")
		if err != nil {
			return nil, err
		}
		oracleID, err := admitProjectedOptionalRuleID(test["oracleId"], testContext+" oracleId")
		if err != nil {
			return nil, err
		}
		falsifierID, err := admitProjectedOptionalRuleID(test["falsifierId"], testContext+" falsifierId")
		if err != nil {
			return nil, err
		}
		dominanceGroup, err := admitProjectedOptionalRuleID(test["dominanceGroup"], testContext+" dominanceGroup")
		if err != nil {
			return nil, err
		}
		negativeCaseID, err := admitProjectedOptionalRuleID(test["negativeCaseId"], testContext+" negativeCaseId")
		if err != nil {
			return nil, err
		}
		wrongImplementationClassID, err := admitProjectedOptionalRuleID(test["wrongImplementationClassId"], testContext+" wrongImplementationClassId")
		if err != nil {
			return nil, err
		}
		supersedes, err := admitProjectedRuleIDs(test["supersedes"], testContext+" supersedes")
		if err != nil {
			return nil, err
		}
		supersessionDeclarationRef, err := admitProjectedOptionalRuleID(test["supersessionDeclarationRef"], testContext+" supersessionDeclarationRef")
		if err != nil {
			return nil, err
		}
		qualityFindings, err := admitProjectedQualityFindings(test["qualityFindings"], testContext+" qualityFindings")
		if err != nil {
			return nil, err
		}
		entry := testevidenceinventory.Entry{
			CommandRefs: commandRefs, EvidenceClass: evidenceClass, OwnerInvariantRefs: ownerInvariantRefs,
			NonClaims: nonClaims, OwnerID: ownerID, QualityFindings: qualityFindings, RequirementRefs: requirementRefs,
			Selector: selector, SourcePath: sourcePath, TestID: testID, WitnessRefs: witnessRefs,
		}
		if oracleID != "" || oracleKind != "" || oracleSummary != "" || expectedPublicOutcome != "" {
			if oracleID == "" || oracleKind == "" {
				return nil, fmt.Errorf("%s projected oracle must retain oracleId and oracleKind", testContext)
			}
			entry.Oracle = &testevidenceinventory.Oracle{
				AssertionSummary: oracleSummary, ExpectedPublicOutcome: expectedPublicOutcome,
				OracleID: oracleID, OracleKind: oracleKind,
			}
		}
		if falsifierID != "" || dominanceGroup != "" || negativeCaseID != "" || wrongImplementationClassID != "" || len(supersedes) > 0 || supersessionDeclarationRef != "" {
			if falsifierID == "" || dominanceGroup == "" || negativeCaseID == "" || wrongImplementationClassID == "" {
				return nil, fmt.Errorf("%s projected falsifier must retain all identity fields", testContext)
			}
			entry.Falsifier = &testevidenceinventory.Falsifier{
				DominanceGroup: dominanceGroup, FalsifierID: falsifierID, NegativeCaseID: negativeCaseID,
				Supersedes: supersedes, SupersessionDeclarationRef: supersessionDeclarationRef,
				WrongImplementationClassID: wrongImplementationClassID,
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func admitProjectedOptionalText(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be text", context)
	}
	if value == "" {
		return "", nil
	}
	canonical, err := admit.NonEmptyText(value, context)
	if err != nil {
		return "", err
	}
	if canonical != value {
		return "", fmt.Errorf("%s must be canonical text", context)
	}
	return value, nil
}

func admitProjectedOptionalRuleID(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be text", context)
	}
	if value == "" {
		return "", nil
	}
	return admit.RuleID(value, context)
}

func admitProjectedQualityFindings(raw any, context string) ([]testevidenceinventory.QualityFinding, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]testevidenceinventory.QualityFinding, 0, len(values))
	previousID := ""
	for index, rawFinding := range values {
		finding, ok := rawFinding.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		findingContext := fmt.Sprintf("%s[%d]", context, index)
		if err := admit.KnownKeys(finding, projectedQualityFindingKeys, findingContext); err != nil {
			return nil, err
		}
		findingID, err := admit.RuleID(finding["findingId"], findingContext+" findingId")
		if err != nil {
			return nil, err
		}
		if previousID != "" && previousID >= findingID {
			return nil, fmt.Errorf("%s must be sorted and unique by findingId", context)
		}
		previousID = findingID
		class, err := testevidenceinventory.AdmitQualityFindingClass(finding["class"], findingContext+" class")
		if err != nil {
			return nil, err
		}
		severity, err := testevidenceinventory.AdmitQualityFindingSeverity(finding["severity"], findingContext+" severity")
		if err != nil {
			return nil, err
		}
		reviewState, err := testevidenceinventory.AdmitQualityFindingReviewState(finding["ownerReviewState"], findingContext+" ownerReviewState")
		if err != nil {
			return nil, err
		}
		evidenceRefs, err := admitProjectedRuleIDs(finding["evidenceRefs"], findingContext+" evidenceRefs")
		if err != nil {
			return nil, err
		}
		if len(evidenceRefs) == 0 {
			return nil, fmt.Errorf("%s evidenceRefs must not be empty", findingContext)
		}
		nonClaims, err := admit.PreserveSortedTextArray(finding["nonClaims"], findingContext+" nonClaims", false)
		if err != nil {
			return nil, err
		}
		result = append(result, testevidenceinventory.QualityFinding{
			Class: class, EvidenceRefs: evidenceRefs, FindingID: findingID,
			NonClaims: nonClaims, OwnerReviewState: reviewState, Severity: severity,
		})
	}
	return result, nil
}

func admitProjectedRuleIDs(raw any, context string) ([]string, error) {
	values, err := admit.PreserveSortedTextArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		if _, err := admit.RuleID(value, fmt.Sprintf("%s[%d]", context, index)); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func requireProjectedParentRef(entries []testevidenceinventory.Entry, row map[string]any, rowsKey string, context string) error {
	var parentID string
	var selectRefs func(testevidenceinventory.Entry) []string
	switch rowsKey {
	case "requirementCoverage":
		parentID = stringValue(row["requirementId"])
		selectRefs = func(entry testevidenceinventory.Entry) []string { return entry.RequirementRefs }
	case "ownerInvariantCoverage":
		parentID = stringValue(row["ownerInvariantId"])
		selectRefs = func(entry testevidenceinventory.Entry) []string { return entry.OwnerInvariantRefs }
	case "commandCoverage":
		parentID = stringValue(row["commandId"])
		selectRefs = func(entry testevidenceinventory.Entry) []string { return entry.CommandRefs }
	default:
		return nil
	}
	for _, entry := range entries {
		if !slices.Contains(selectRefs(entry), parentID) {
			return fmt.Errorf("%s test %s does not reference its projected parent", context, entry.TestID)
		}
	}
	return nil
}

func admitExactProjectedTestIDs(raw any, entries []testevidenceinventory.Entry, context string) error {
	actual, err := admit.PreserveSortedTextArray(raw, context, true)
	if err != nil {
		return err
	}
	expected := entryIDs(entries)
	if !slices.Equal(actual, expected) {
		return fmt.Errorf("%s must equal projected test identities", context)
	}
	return nil
}

type projectedTestRecord struct {
	entry      testevidenceinventory.Entry
	projection []byte
}

func admitCoverageProjectedTestRegistry(record map[string]any) (map[string]projectedTestRecord, error) {
	registry := map[string]projectedTestRecord{}
	for _, descriptor := range coverageRowDescriptors {
		rowsKey := descriptor.rowsKey
		for rowIndex, rawRow := range record[rowsKey].([]any) {
			row := rawRow.(map[string]any)
			context := fmt.Sprintf("requirement coverage output %s[%d] tests", rowsKey, rowIndex)
			entries, err := admitProjectedTestSemantics(row["tests"], context)
			if err != nil {
				return nil, err
			}
			tests := row["tests"].([]any)
			for testIndex, entry := range entries {
				projection, err := stablejson.Marshal(tests[testIndex])
				if err != nil {
					return nil, fmt.Errorf("%s[%d] must be canonical JSON: %w", context, testIndex, err)
				}
				if previous, ok := registry[entry.TestID]; ok {
					if !bytes.Equal(previous.projection, projection) {
						return nil, fmt.Errorf("requirement coverage output test %s has inconsistent projections", entry.TestID)
					}
					continue
				}
				registry[entry.TestID] = projectedTestRecord{entry: entry, projection: projection}
			}
		}
	}
	unmappedEntries, err := admitProjectedTestSemantics(record["unmappedTests"], "requirement coverage output unmappedTests")
	if err != nil {
		return nil, err
	}
	for index, entry := range unmappedEntries {
		if _, exists := registry[entry.TestID]; exists {
			return nil, fmt.Errorf("requirement coverage output unmapped test %s is already projected under a retained parent", entry.TestID)
		}
		projection, err := stablejson.Marshal(record["unmappedTests"].([]any)[index])
		if err != nil {
			return nil, fmt.Errorf("requirement coverage output unmappedTests[%d] must be canonical JSON: %w", index, err)
		}
		registry[entry.TestID] = projectedTestRecord{entry: entry, projection: projection}
	}
	return registry, nil
}

func projectedRegistryEntries(registry map[string]projectedTestRecord) []testevidenceinventory.Entry {
	ids := make([]string, 0, len(registry))
	for testID := range registry {
		ids = append(ids, testID)
	}
	slices.Sort(ids)
	entries := make([]testevidenceinventory.Entry, 0, len(ids))
	for _, testID := range ids {
		entries = append(entries, registry[testID].entry)
	}
	return entries
}

func admitProjectedParentClosure(record map[string]any, registry map[string]projectedTestRecord) error {
	rowTests := map[string]map[string]map[string]struct{}{}
	for _, descriptor := range coverageRowDescriptors {
		byParent := map[string]map[string]struct{}{}
		for _, rawRow := range record[descriptor.rowsKey].([]any) {
			row := rawRow.(map[string]any)
			testIDs := map[string]struct{}{}
			for _, rawTest := range row["tests"].([]any) {
				testIDs[rawTest.(map[string]any)["testId"].(string)] = struct{}{}
			}
			byParent[row[descriptor.idKey].(string)] = testIDs
		}
		rowTests[descriptor.rowsKey] = byParent
	}
	for testID, projected := range registry {
		for _, relation := range []struct {
			rowsKey string
			refs    []string
		}{
			{rowsKey: "requirementCoverage", refs: projected.entry.RequirementRefs},
			{rowsKey: "ownerInvariantCoverage", refs: projected.entry.OwnerInvariantRefs},
			{rowsKey: "commandCoverage", refs: projected.entry.CommandRefs},
		} {
			for _, parentID := range relation.refs {
				testIDs, parentRetained := rowTests[relation.rowsKey][parentID]
				if !parentRetained {
					continue
				}
				if _, projectedUnderParent := testIDs[testID]; !projectedUnderParent {
					return fmt.Errorf("requirement coverage output test %s is missing from retained parent %s", testID, parentID)
				}
			}
		}
	}
	return nil
}
