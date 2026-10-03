package requirementbinding

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func selectionOutputShape() jsonshape.Shape {
	texts := jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 0)
	return jsonshape.Object(jsonshape.Required("changedPaths", texts), jsonshape.Required("ownerIds", texts), jsonshape.Required("requirementIds", texts))
}

func requirementOutputShape() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	scenario := jsonshape.Object(
		jsonshape.Required("commandIds", jsonshape.Array(id, 1)), jsonshape.Required("environmentClasses", jsonshape.Array(id, 1)),
		jsonshape.Required("scenarioId", id), jsonshape.Required("witnessId", id),
		jsonshape.Required("witnessKind", jsonshape.Enum(witnessKinds)), jsonshape.Required("witnessPath", text),
		jsonshape.Optional("witnessSelectors", jsonshape.Array(jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("selector", text)), 1)),
	)
	return jsonshape.Object(
		jsonshape.Required("claimLevel", jsonshape.Enum(claimLevels)), jsonshape.Required("proofState", jsonshape.Enum(proofStates)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 0)), jsonshape.Required("ownerId", id),
		jsonshape.Required("requirementId", id), jsonshape.Required("specPath", text), jsonshape.Required("scenarios", jsonshape.Array(scenario, 0)),
	)
}

func ReportOutputStructure() map[string]any {
	count := jsonshape.IntegerMinimum(0)
	summary := jsonshape.Object(
		jsonshape.Required("bindingCount", count), jsonshape.Required("commandCount", count),
		jsonshape.Required("omittedRequirementCount", count), jsonshape.Required("requirementCount", count), jsonshape.Required("selectedRequirementCount", count),
	)
	diagnostics := jsonshape.Tuple(report.DiagnosticStructure("selection", selectionOutputShape()))
	passed := report.Structure(1, "proofkit.requirement-proof-bindings", jsonshape.StringLiteral("passed"), summary, diagnostics,
		jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral("proofkit.requirement-proof-bindings.accepted"), jsonshape.StringLiteral("passed"),
			jsonshape.StringLiteral("requirement proof bindings are deterministic and reference-complete"), jsonshape.Tuple())))
	failed := report.Structure(1, "proofkit.requirement-proof-bindings", jsonshape.StringLiteral("failed"), summary, diagnostics,
		jsonshape.Array(report.RuleStructure(jsonshape.StringGrammar(`proofkit\.requirement-proof-bindings\.failure\.[0-9]{3,}`), jsonshape.StringLiteral("failed"),
			jsonshape.StringGrammar(`[\s\S]+`), jsonshape.Tuple()), 1))
	schema := jsonshape.DiscriminatedUnion("state", passed, failed).JSONSchema()
	for _, branch := range schema["oneOf"].([]any) {
		branch.(map[string]any)["description"] = "Admission errors emit no report. Semantic errors emit failed reports with sorted unique failures and sequential numbered rules. Selection uses native OR semantics across IDs, owners and exact paths; empty operands select all. Counts and reference completeness remain native derived relationships. Passing this structure does not prove witnesses ran, passed, or remain current."
	}
	return schema
}

func EvidenceGraphOutputStructure() map[string]any {
	count := jsonshape.IntegerMinimum(0)
	schema := jsonshape.Object(
		jsonshape.Required("bindingCount", count), jsonshape.Required("commandCount", count), jsonshape.Required("requirementCount", count),
		jsonshape.Required("bindingId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		jsonshape.Required("graphKind", jsonshape.StringLiteral("proofkit.requirement-evidence-graph")),
		jsonshape.Required("nonClaims", jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 0)),
		jsonshape.Required("requirements", jsonshape.Array(requirementOutputShape(), 0)), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
	).JSONSchema()
	schema["description"] = "Only semantically passing bindings emit public graphs. Requirements and their scenarios are normalized and deterministically ordered; unbound/deferred requirements may have empty scenarios. Absent or null input witnessSelectors are omitted, never emitted null. Native rules own identity/reference completeness, count equality, canonical privacy/path/selector constraints and proof-state compatibility. The graph is a lookup projection, not execution evidence."
	return schema
}

func ProofSliceOutputStructure() map[string]any {
	count := jsonshape.IntegerMinimum(0)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	schema := jsonshape.Object(
		jsonshape.Required("bindingId", id), jsonshape.Required("nonClaims", jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 0)),
		jsonshape.Required("omittedRequirementCount", count), jsonshape.Required("selectedRequirementCount", count),
		jsonshape.Required("selectedCommandIds", jsonshape.Array(id, 0)),
		jsonshape.Required("selectedRequirements", jsonshape.Array(requirementOutputShape(), 0)),
		jsonshape.Required("selection", selectionOutputShape()), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("sliceKind", jsonshape.StringLiteral("proofkit.requirement-proof-slice")),
	).JSONSchema()
	schema["description"] = "Only semantically passing bindings emit public slices. Selection uses OR across requirement IDs, owner IDs, exact spec paths and bound witness paths. Empty operands select all; a nonmatching owner/path can select none. Unknown explicit requirement IDs are semantic failures. SelectedCommandIds is the sorted unique union over retained scenarios. Native evaluation owns selected/omitted partition, counts, references, canonical text and paths, and optional-selector omission. This is not proof that selected commands execute or pass."
	return schema
}
