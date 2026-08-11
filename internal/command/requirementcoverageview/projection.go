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
func scenariosToAny(scenarios []scenario, proofMode string) []any {
	result := make([]any, 0, len(scenarios))
	for _, item := range scenarios {
		if proofMode == "compact" {
			result = append(result, map[string]any{
				"bindingRecordId":            item.BindingRecordID,
				"bindingVerifyCommands":      admit.StringSliceToAny(item.BindingVerifyCommands),
				"declaredWitnessRoutes":      declaredWitnessRoutesToAny(item.DeclaredWitnessRoutes),
				"environmentClasses":         admit.StringSliceToAny(item.EnvironmentClasses),
				"requiredEnvironmentClasses": admit.StringSliceToAny(item.RequiredEnvironmentClasses),
				"requirementId":              item.RequirementID,
				"scenarioId":                 item.ScenarioID,
				"surfaceId":                  item.SurfaceID,
				"verifyCommands":             admit.StringSliceToAny(item.VerifyCommands),
			})
			continue
		}
		result = append(result, map[string]any{
			"commandIds":         admit.StringSliceToAny(item.CommandIDs),
			"environmentClasses": admit.StringSliceToAny(item.EnvironmentClasses),
			"scenarioId":         item.ScenarioID,
			"verifyCommands":     admit.StringSliceToAny(item.VerifyCommands),
			"witnessId":          item.WitnessID,
			"witnessKind":        item.WitnessKind,
			"witnessPath":        item.WitnessPath,
		})
	}
	return result
}

func declaredWitnessRoutesToAny(routes []declaredWitnessRoute) []any {
	result := make([]any, 0, len(routes))
	for _, route := range routes {
		result = append(result, map[string]any{
			"bindingRecordId":      route.BindingRecordID,
			"environmentClasses":   admit.StringSliceToAny(route.EnvironmentClasses),
			"requirementId":        route.RequirementID,
			"resolutionOrderIndex": route.ResolutionOrder,
			"role":                 route.Role,
			"scenarioId":           route.ScenarioID,
			"selector":             route.Selector,
			"surfaceId":            route.SurfaceID,
			"verifyCommands":       admit.StringSliceToAny(route.VerifyCommands),
			"witnessRouteId":       route.WitnessRouteID,
		})
	}
	return result
}
func testEntriesToAny(entries []testevidenceinventory.Entry) []any {
	result := make([]any, 0, len(entries))
	for _, entry := range entries {
		expectedPublicOutcome := ""
		oracleSummary := ""
		oracleKind := ""
		oracleID := ""
		if entry.Oracle != nil {
			expectedPublicOutcome = entry.Oracle.ExpectedPublicOutcome
			oracleSummary = entry.Oracle.AssertionSummary
			oracleKind = entry.Oracle.OracleKind
			oracleID = entry.Oracle.OracleID
		}
		dominanceGroup := ""
		falsifierID := ""
		wrongImplementation := ""
		negativeCaseID := ""
		supersedes := []string{}
		supersessionDeclarationRef := ""
		if entry.Falsifier != nil {
			dominanceGroup = entry.Falsifier.DominanceGroup
			falsifierID = entry.Falsifier.FalsifierID
			wrongImplementation = entry.Falsifier.WrongImplementationClassID
			negativeCaseID = entry.Falsifier.NegativeCaseID
			supersedes = entry.Falsifier.Supersedes
			supersessionDeclarationRef = entry.Falsifier.SupersessionDeclarationRef
		}
		result = append(result, map[string]any{
			"commandRefs":                admit.StringSliceToAny(entry.CommandRefs),
			"dominanceGroup":             dominanceGroup,
			"evidenceClass":              entry.EvidenceClass,
			"expectedPublicOutcome":      expectedPublicOutcome,
			"falsifierId":                falsifierID,
			"negativeCaseId":             negativeCaseID,
			"nonClaims":                  admit.StringSliceToAny(entry.NonClaims),
			"oracleId":                   oracleID,
			"oracleKind":                 oracleKind,
			"oracleSummary":              oracleSummary,
			"ownerId":                    entry.OwnerID,
			"ownerInvariantRefs":         admit.StringSliceToAny(entry.OwnerInvariantRefs),
			"qualityFindings":            qualityFindingsToAny(entry.QualityFindings),
			"requirementRefs":            admit.StringSliceToAny(entry.RequirementRefs),
			"selector":                   entry.Selector,
			"sourcePath":                 entry.SourcePath,
			"supersedes":                 admit.StringSliceToAny(supersedes),
			"supersessionDeclarationRef": supersessionDeclarationRef,
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

func unprojectedTestEntries(entries []testevidenceinventory.Entry, rowGroups ...[]map[string]any) []testevidenceinventory.Entry {
	projected := map[string]struct{}{}
	for _, rows := range rowGroups {
		for _, row := range rows {
			for _, testID := range stringArray(row["testIds"]) {
				projected[testID] = struct{}{}
			}
		}
	}
	result := make([]testevidenceinventory.Entry, 0)
	for _, entry := range entries {
		if _, ok := projected[entry.TestID]; !ok {
			result = append(result, entry)
		}
	}
	return result
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
