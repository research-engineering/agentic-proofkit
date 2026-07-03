package requirementcoverageview

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"sort"
)

func exitCode(view map[string]any) int {
	if stringValue(view["state"]) == "failed" {
		return 1
	}
	return 0
}
func scenariosToAny(scenarios []scenario) []any {
	result := make([]any, 0, len(scenarios))
	for _, item := range scenarios {
		result = append(result, map[string]any{
			"commandIds":         admit.StringSliceToAny(item.CommandIDs),
			"environmentClasses": admit.StringSliceToAny(item.EnvironmentClasses),
			"scenarioId":         item.ScenarioID,
			"witnessId":          item.WitnessID,
			"witnessKind":        item.WitnessKind,
			"witnessPath":        item.WitnessPath,
		})
	}
	return result
}
func testEntriesToAny(entries []testevidenceinventory.Entry) []any {
	result := make([]any, 0, len(entries))
	for _, entry := range entries {
		oracleSummary := ""
		oracleKind := ""
		if entry.Oracle != nil {
			oracleSummary = entry.Oracle.AssertionSummary
			oracleKind = entry.Oracle.OracleKind
		}
		wrongImplementation := ""
		negativeCaseID := ""
		if entry.Falsifier != nil {
			wrongImplementation = entry.Falsifier.WrongImplementationClassID
			negativeCaseID = entry.Falsifier.NegativeCaseID
		}
		result = append(result, map[string]any{
			"commandRefs":                admit.StringSliceToAny(entry.CommandRefs),
			"evidenceClass":              entry.EvidenceClass,
			"negativeCaseId":             negativeCaseID,
			"nonClaims":                  admit.StringSliceToAny(entry.NonClaims),
			"oracleKind":                 oracleKind,
			"oracleSummary":              oracleSummary,
			"qualityFindings":            qualityFindingsToAny(entry.QualityFindings),
			"selector":                   entry.Selector,
			"sourcePath":                 entry.SourcePath,
			"testId":                     entry.TestID,
			"witnessRefs":                admit.StringSliceToAny(entry.WitnessRefs),
			"wrongImplementationClassId": wrongImplementation,
		})
	}
	return result
}

func qualityFindingsToAny(findings []testevidenceinventory.QualityFinding) []any {
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

func entryCommandRefs(entries []testevidenceinventory.Entry) []string {
	values := []string{}
	for _, entry := range entries {
		values = append(values, entry.CommandRefs...)
	}
	return sortedUnique(values)
}

func inventoryID(inventory *testevidenceinventory.Result) any {
	if inventory == nil {
		return nil
	}
	return inventory.Inventory.InventoryID
}
func entryIDs(entries []testevidenceinventory.Entry) []string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry.TestID)
	}
	return sortedUnique(values)
}
func surfaceIDs(values []surface) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.SurfaceID)
	}
	sort.Strings(result)
	return result
}
func ownerInvariantIDs(values []ownerInvariant) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.OwnerInvariantID)
	}
	sort.Strings(result)
	return result
}
func mapsToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
