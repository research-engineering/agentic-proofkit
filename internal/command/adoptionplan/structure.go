package adoptionplan

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func OutputShape() (jsonshape.Shape, error) {
	guidance, err := nativeevidenceguidance.ReferenceShape()
	if err != nil {
		return jsonshape.Shape{}, err
	}
	inventory := repositoryinventory.OutputShape()
	hint := jsonshape.Nullable(stackpreset.PlanningHintShape())
	presetIDs := make(map[string]struct{})
	for _, id := range stackpreset.IDs() {
		presetIDs[id] = struct{}{}
	}
	selectedPreset := jsonshape.Nullable(jsonshape.Enum(presetIDs))
	digest := jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
	claims := make([]jsonshape.Shape, len(boundaryNonClaims))
	for i, claim := range boundaryNonClaims {
		claims[i] = jsonshape.StringLiteral(claim)
	}
	alternatives := make([]jsonshape.Shape, 0, len(intentValues))
	for _, intent := range intentValues {
		trust, tasks, err := intentPlan(intent)
		if err != nil {
			return jsonshape.Shape{}, err
		}
		taskShapes := make([]jsonshape.Shape, len(tasks))
		for i, task := range tasks {
			taskShapes[i] = jsonshape.Object(
				jsonshape.Required("commandId", nullableTextLiteral(task.CommandID)),
				jsonshape.Required("instruction", jsonshape.StringLiteral(task.Instruction)),
				jsonshape.Required("order", jsonshape.IntegerLiteral(int64(task.Order))),
				jsonshape.Required("outputKind", jsonshape.StringLiteral(task.OutputKind)),
				jsonshape.Required("owner", jsonshape.StringLiteral(task.Owner)),
				jsonshape.Required("taskId", jsonshape.StringLiteral(task.TaskID)),
			)
		}
		alternatives = append(alternatives, jsonshape.Object(
			jsonshape.Required("authority", jsonshape.StringLiteral("derived_non_authoritative_plan")),
			jsonshape.Required("authoringPacket", jsonshape.Object(
				jsonshape.Required("authority", jsonshape.StringLiteral("candidate_only")),
				jsonshape.Required("inventoryRef", digest),
				jsonshape.Required("nativeEvidenceGuidance", guidance),
				jsonshape.Required("packetKind", jsonshape.StringLiteral(PacketKind)),
				jsonshape.Required("proposedBindingCount", jsonshape.IntegerLiteral(0)),
				jsonshape.Required("proposedRequirementCount", jsonshape.IntegerLiteral(0)),
				jsonshape.Required("tasks", jsonshape.Tuple(taskShapes...)),
			)),
			jsonshape.Required("intent", jsonshape.StringLiteral(intent)),
			jsonshape.Required("nonClaims", jsonshape.Tuple(claims...)),
			jsonshape.Required("planId", digest),
			jsonshape.Required("planKind", jsonshape.StringLiteral(PlanKind)),
			jsonshape.Required("repositoryInventory", inventory),
			jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(SchemaVersion)),
			jsonshape.Required("sourceTrust", jsonshape.Object(
				jsonshape.Required("capabilityMapTrustMode", nullableTextLiteral(trust.CapabilityMapTrustMode)),
				jsonshape.Required("declarationClass", jsonshape.StringLiteral(trust.Class)),
			)),
			jsonshape.Required("stackHint", hint),
			jsonshape.Required("state", jsonshape.StringLiteral(PlanState)),
			jsonshape.Required("summary", jsonshape.Object(
				jsonshape.Required("codeBaselineDeclared", jsonshape.BooleanLiteral(intent == IntentCodeBaseline)),
				jsonshape.Required("generatedBindingCount", jsonshape.IntegerLiteral(0)),
				jsonshape.Required("generatedRequirementCount", jsonshape.IntegerLiteral(0)),
				jsonshape.Required("observedCatalogFileCount", jsonshape.IntegerMinimum(0)),
				jsonshape.Required("omittedRecognizedCount", jsonshape.IntegerMinimum(0)),
				jsonshape.Required("selectedStackPreset", selectedPreset),
				jsonshape.Required("taskCount", jsonshape.IntegerLiteral(int64(len(tasks)))),
				jsonshape.Required("unrecognizedRootEntryCount", jsonshape.IntegerMinimum(0)),
			)),
		))
	}
	return jsonshape.DiscriminatedUnion("intent", alternatives...), nil
}

func OutputStructure() (map[string]any, error) {
	shape, err := OutputShape()
	if err != nil {
		return nil, err
	}
	return shape.JSONSchema(), nil
}

func nullableTextLiteral(value *string) jsonshape.Shape {
	if value == nil {
		return jsonshape.Null()
	}
	return jsonshape.StringLiteral(*value)
}
