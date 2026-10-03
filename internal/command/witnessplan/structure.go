package witnessplan

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

func DirectInputStructure() map[string]any {
	schema := jsonshape.Object(
		jsonshape.Required("commands", jsonshape.Array(witnesscommand.CommandStructure(), 0)),
		jsonshape.Optional("schemaVersion", jsonshape.IntegerLiteral(1)),
	).JSONSchema()
	schema["properties"].(map[string]any)["vocabulary"] = witnesscommand.VocabularyStructure()
	schema["required"] = append(schema["required"].([]any), "vocabulary")
	schema["description"] = "Direct schemaVersion is optional but not nullable. Commands may be empty. Native admission owns canonical tokens, privacy, paths, command safety, sortedness and identity uniqueness, vocabulary membership, environment-policy conjunction and caller timeout limits. This plan does not execute commands."
	return schema
}

func ProjectedInputStructure() map[string]any {
	schema := jsonshape.Object(
		jsonshape.Required("projection", jsonshape.StringLiteral("requirement-bindings")),
		jsonshape.Required("requirementProofBinding", requirementbinding.InputShape()),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
	).JSONSchema()
	schema["properties"].(map[string]any)["vocabulary"] = witnesscommand.VocabularyStructure()
	schema["required"] = append(schema["required"].([]any), "vocabulary")
	schema["description"] = "Presence of projection selects binding projection; it never falls back to direct admission. Projection requires schemaVersion=1, a passing binding report, exactly one parallelGroup and commands expressible without shell quoting/control. Binding ownership and cross-record links, canonical token spelling, privacy, command safety and vocabulary policy remain native checks. No root nonClaims field is accepted. This plan does not execute commands."
	return schema
}

func OutputStructure() map[string]any { return witnesscommand.PlanStructure() }
