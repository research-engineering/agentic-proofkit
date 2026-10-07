package stackpreset

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func OutputStructure() map[string]any {
	alternatives := make([]any, 0, len(presetIDs))
	for _, id := range presetIDs {
		item := presets[id]
		summary := jsonshape.Object(
			jsonshape.Required("expectedFileCount", jsonshape.IntegerLiteral(int64(len(item.ExpectedFiles)))),
			jsonshape.Required("presetId", jsonshape.StringLiteral(id)),
			jsonshape.Required("primaryLanguages", textTuple(item.PrimaryLanguages)),
			jsonshape.Required("starterEnvironmentClassCount", jsonshape.IntegerLiteral(int64(len(item.StarterEnvironmentClasses)))),
			jsonshape.Required("starterWitnessKindCount", jsonshape.IntegerLiteral(int64(len(item.StarterWitnessKinds)))),
		)
		policy := jsonshape.Object(
			jsonshape.Required("consumerOverrideRequired", jsonshape.BooleanLiteral(true)),
			jsonshape.Required("defaultFilesAreSuggestions", jsonshape.BooleanLiteral(true)),
			jsonshape.Required("nonClaims", textTuple(pathPolicyNonClaims)),
			jsonshape.Required("policyClass", jsonshape.StringLiteral("starter_suggestion")),
		)
		commands := make([]jsonshape.Shape, len(item.SuggestedCommandArgs))
		for index := range commands {
			commands[index] = jsonshape.NonBlankString()
		}
		profile := jsonshape.Object(
			jsonshape.Required("expectedFiles", textTuple(item.ExpectedFiles)),
			jsonshape.Required("purpose", jsonshape.StringLiteral(item.Purpose)),
			jsonshape.Required("starterProofLikePaths", textTuple(item.StarterProofLikePaths)),
			jsonshape.Required("suggestedCommands", jsonshape.Tuple(commands...)),
		)
		schema := report.Structure(1, reportKind, jsonshape.StringLiteral("passed"), summary,
			jsonshape.Tuple(report.DiagnosticStructure("pathPolicy", policy), report.DiagnosticStructure("preset", profile)),
			jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"),
				jsonshape.StringLiteral(acceptedRuleMessage), jsonshape.Tuple())),
		).JSONSchema()
		properties := schema["properties"].(map[string]any)
		properties["reportId"] = jsonshape.StringLiteral(reportKind + "." + id).JSONSchema()
		properties["nonClaims"] = textTuple(presetNonClaims).JSONSchema()
		schema["description"] = "One successful preset report with exact owner-defined suggestions, counts and ordered claims. Suggested command strings depend on the admitted path, npm-offline or Python-module launcher; the native renderer owns quoting and argv correspondence. Structural validation does not prove command execution, consumer suitability, coverage or rollout readiness. Flag errors emit stderr without a JSON report."
		alternatives = append(alternatives, schema)
	}
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "oneOf": alternatives}
}

// PlanningHintShape describes the compact projection replayed by
// AdmitPlanningHint, without copying preset policy into its parent commands.
func PlanningHintShape() jsonshape.Shape {
	alternatives := make([]jsonshape.Shape, 0, len(presetIDs))
	for _, id := range presetIDs {
		item := presets[id]
		alternatives = append(alternatives, jsonshape.Object(
			jsonshape.Required("presetId", jsonshape.StringLiteral(id)),
			jsonshape.Required("primaryLanguages", textTuple(item.PrimaryLanguages)),
			jsonshape.Required("starterEnvironmentClasses", textTuple(item.StarterEnvironmentClasses)),
			jsonshape.Required("starterWitnessKinds", textTuple(item.StarterWitnessKinds)),
		))
	}
	return jsonshape.OneOf(alternatives...)
}

func textTuple(values []string) jsonshape.Shape {
	items := make([]jsonshape.Shape, len(values))
	for index, value := range values {
		items[index] = jsonshape.StringLiteral(value)
	}
	return jsonshape.Tuple(items...)
}
