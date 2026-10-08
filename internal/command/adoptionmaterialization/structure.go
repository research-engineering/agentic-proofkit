package adoptionmaterialization

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func InputShape() (jsonshape.Shape, error) {
	plan, err := adoptionplan.OutputShape()
	if err != nil {
		return jsonshape.Shape{}, err
	}
	source, err := requirementsourcecodec.InputShape(requirementsourcemodel.DefaultLimits())
	if err != nil {
		return jsonshape.Shape{}, err
	}
	return jsonshape.Object(
		jsonshape.Required("nonClaims", jsonshape.Array(materializationTextShape(), 0)),
		jsonshape.Required("projectId", materializationIDShape()),
		jsonshape.Required("requestId", materializationIDShape()),
		jsonshape.Required("requestKind", jsonshape.StringLiteral(RequestKind)),
		jsonshape.Required("requirementProofBinding", artifactShape(requirementbinding.InputShape())),
		jsonshape.Required("requirementSources", jsonshape.BoundedArray(source, 1, MaximumRequirementSources)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(RequestSchemaVersion)),
		jsonshape.Required("sourcePlan", plan),
		jsonshape.Required("testEvidenceInventory", artifactShape(testevidenceinventory.DirectInputShape())),
	), nil
}

func InputStructure() (map[string]any, error) {
	shape, err := InputShape()
	if err != nil {
		return nil, err
	}
	schema := shape.JSONSchema()
	schema["description"] = "Materialization candidates, not passed child reports or executable plans. Native admission requires passed source/binding/direct-inventory semantics, canonical repo-relative paths, sorted unique private-safe text and complete source/requirement/test closure. Raw source framing and resources remain codec-owned. Structural success does not approve meaning, execute witnesses or authorize writes; CLI root and expected identities are separate prerequisites."
	return schema, nil
}

func PlanOutputShape() jsonshape.Shape {
	intents := make(map[string]struct{})
	for _, intent := range adoptionplan.IntentValues() {
		intents[intent] = struct{}{}
	}
	return jsonshape.Object(
		jsonshape.Required("manifest", ManifestShape()),
		jsonshape.Required("nonClaims", jsonshape.Array(materializationTextShape(), len(boundaryNonClaims))),
		jsonshape.Required("planKind", jsonshape.StringLiteral(PlanKind)),
		jsonshape.Required("projectId", materializationIDShape()),
		jsonshape.Required("requestId", materializationIDShape()),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("sourceIntent", jsonshape.Enum(intents)),
		jsonshape.Required("sourcePlanId", materializationDigestShape()),
		jsonshape.Required("state", jsonshape.StringLiteral("ready")),
		jsonshape.Required("transaction", repositorytransaction.PlanShape()),
	)
}

func PlanOutputStructure() map[string]any {
	schema := PlanOutputShape().JSONSchema()
	schema["description"] = "Descriptive ready plan with child-owned routing manifest and public transaction fields. Native admission owns canonical digest replay, built-in nonclaim membership, sorted/private-safe values, output bytes and manifest/transaction path/content closure. A public transaction has no executable payload or native construction identity; apply recomputes from the candidate. Structural success is not execution, durability or approval evidence."
	return schema
}

func ReceiptOutputShape(operation string) (jsonshape.Shape, error) {
	desired := jsonshape.Null()
	switch operation {
	case OperationApply:
		desired = materializationDigestShape()
	case OperationRecover:
	default:
		return jsonshape.Shape{}, fmt.Errorf("unsupported materialization receipt operation")
	}
	return jsonshape.Object(
		jsonshape.Required("expectedDesiredStateId", desired),
		jsonshape.Required("expectedTransactionId", materializationDigestShape()),
		jsonshape.Required("failureClass", jsonshape.Nullable(materializationTextShape())),
		jsonshape.Required("nonClaims", jsonshape.Array(materializationTextShape(), len(boundaryNonClaims))),
		jsonshape.Required("operation", jsonshape.StringLiteral(operation)),
		jsonshape.Required("receiptId", materializationDigestShape()),
		jsonshape.Required("receiptKind", jsonshape.StringLiteral(ReceiptKind)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", jsonshape.Enum(receiptStateSet)),
		jsonshape.Required("transactionResult", jsonshape.Nullable(repositorytransaction.ResultShape())),
	), nil
}

func ReceiptOutputStructure(operation string) (map[string]any, error) {
	shape, err := ReceiptOutputShape(operation)
	if err != nil {
		return nil, err
	}
	schema := shape.JSONSchema()
	schema["description"] = "Operation-specific receipts, including blocked and nonterminal outcomes. Native admission owns identity/canonical replay, built-in claim membership, output bytes and state/failure/recovery/result relations. Required expected identity is not an observed transaction guarantee; missing results are admitted only by the native blocked relation. Structural success does not authenticate filesystem execution, durability or approval."
	return schema, nil
}

func artifactShape(record jsonshape.Shape) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("path", jsonshape.NonBlankString()),
		jsonshape.Required("record", record),
	)
}

func materializationIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func materializationDigestShape() jsonshape.Shape {
	return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
}

func materializationTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^` + space + `](?:[\s\S]*[^` + space + `])?`
	})
}
