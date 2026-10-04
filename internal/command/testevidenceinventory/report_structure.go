package testevidenceinventory

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func ReportOutputShape() jsonshape.Shape {
	text := jsonshape.String()
	texts := jsonshape.Array(text, 0)
	state := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	summary := []jsonshape.Property{}
	for _, name := range []string{
		"agentActionCount", "entryCount", "failureCount", "inputPathCount", "qualityFindingFailureCount", "qualityFindingWarningCount",
		"routeOnlyNonClaimCount", "proofRouteCandidateCount", "declaredSemanticFalsifierRouteCount", "sourceCount",
		"incompleteDeclaredOracleMetadataFailureCount", "wrongBoundaryFailureCount", "warningCount",
	} {
		summary = append(summary, jsonshape.Required(name, jsonshape.IntegerMinimum(0)))
	}
	action := jsonshape.Object(
		jsonshape.Required("actionId", text), jsonshape.Required("classificationId", classificationIDShape()),
		jsonshape.Required("decisionOwner", jsonshape.StringLiteral("consumer_repository")),
		jsonshape.Required("diagnostic", text), jsonshape.Required("evidenceRefs", jsonshape.Tuple(text)),
		jsonshape.Required("instruction", text), jsonshape.Required("nonClaim", jsonshape.StringLiteral(agentActionNonClaim)),
		jsonshape.Required("severity", jsonshape.Enum(qualityFindingSeveritySet)),
	)
	diagnostics := jsonshape.Tuple(
		report.DiagnosticStructure("agentActionPlan", jsonshape.Array(action, 0)),
		report.DiagnosticStructure("failureClassifications", classificationShape("failure")),
		report.DiagnosticStructure("failures", texts),
		report.DiagnosticStructure("warningClassifications", classificationShape("warning")),
		report.DiagnosticStructure("warnings", texts),
	)
	rules := []jsonshape.Shape{}
	for _, rule := range ruleResults(nil, nil) {
		rules = append(rules, report.RuleStructure(jsonshape.StringLiteral(rule.RuleID), state,
			jsonshape.StringLiteral(rule.Message), jsonshape.Tuple()))
	}
	return report.Structure(1, ReportKind, state, jsonshape.Object(summary...), diagnostics, jsonshape.Tuple(rules...))
}

func classificationShape(severity string) jsonshape.Shape {
	return jsonshape.Array(jsonshape.Object(
		jsonshape.Required("classificationId", classificationIDShape()),
		jsonshape.Required("diagnostic", jsonshape.String()),
		jsonshape.Required("severity", jsonshape.StringLiteral(severity)),
	), 0)
}

func classificationIDShape() jsonshape.Shape {
	values := map[string]struct{}{}
	for _, id := range ClassificationIDs() {
		values[id] = struct{}{}
	}
	return jsonshape.Enum(values)
}

func DiscoveryOutputShape() jsonshape.Shape {
	text := jsonshape.String()
	summary := []jsonshape.Property{jsonshape.Required("runnerKind", jsonshape.Enum(runnerKindSet))}
	for _, name := range []string{"agentActionCount", "candidateInventoryEntryCount", "discoveredTestCount",
		"fragileSelectorWarningCount", "missingAnchorWarningCount", "missingDeclaredAssertionSignalWarningCount", "warningCount"} {
		summary = append(summary, jsonshape.Required(name, jsonshape.IntegerMinimum(0)))
	}
	action := jsonshape.Object(
		jsonshape.Required("actionId", text), jsonshape.Required("commandRef", text),
		jsonshape.Required("message", text), jsonshape.Required("testId", text), jsonshape.Required("type", text),
		jsonshape.Required("severity", jsonshape.StringLiteral("review")),
	)
	diagnostics := jsonshape.Tuple(
		report.DiagnosticStructure("agentActionPlan", jsonshape.Array(action, 1)),
		report.DiagnosticStructure("candidateInventory", discoveryCandidateShape()),
		report.DiagnosticStructure("warningClassifications", classificationShape("warning")),
		report.DiagnosticStructure("warnings", jsonshape.Array(text, 1)),
	)
	passed := jsonshape.StringLiteral("passed")
	rules := jsonshape.Tuple(
		report.RuleStructure(jsonshape.StringLiteral("test_inventory.discovery_draft.input_admitted"), passed, text, jsonshape.Tuple()),
		report.RuleStructure(jsonshape.StringLiteral("test_inventory.discovery_draft.candidate_only"), passed, text, jsonshape.Tuple()),
	)
	return report.Structure(1, discoveryDraftReportKind, passed, jsonshape.Object(summary...), diagnostics, rules)
}

func discoveryCandidateShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("authority", jsonshape.StringLiteral(discoveryCandidateInventoryAuthority)),
		jsonshape.Required("candidateKind", jsonshape.StringLiteral(discoveryCandidateInventoryKind)),
		jsonshape.Required("inventoryId", jsonshape.String()),
		jsonshape.Required("nonClaims", jsonshape.Array(jsonshape.String(), 1)),
		jsonshape.Required("entries", jsonshape.Array(inventoryEntryShape(true), 1)),
	)
}
