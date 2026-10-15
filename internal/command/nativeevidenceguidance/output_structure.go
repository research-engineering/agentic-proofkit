package nativeevidenceguidance

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// OutputShape projects the one JSON value Build can emit. Every member is
// position-bound to the command-owned table, so the projection derives every
// literal instead of keeping a second copy of the slot vocabulary.
func OutputShape() (jsonshape.Shape, error) {
	guidance, err := Build()
	if err != nil {
		return jsonshape.Shape{}, err
	}
	slots := make([]jsonshape.Shape, len(guidance.Slots))
	for index, slot := range guidance.Slots {
		slots[index] = jsonshape.Object(
			jsonshape.Required("applicabilityClass", jsonshape.StringLiteral(slot.ApplicabilityClass)),
			jsonshape.Required("completionCriterion", jsonshape.StringLiteral(slot.CompletionCriterion)),
			jsonshape.Required("order", jsonshape.IntegerLiteral(int64(slot.Order))),
			jsonshape.Required("question", jsonshape.StringLiteral(slot.Question)),
			jsonshape.Required("requiredConsumerDecision", jsonshape.StringLiteral(slot.RequiredConsumerDecision)),
			jsonshape.Required("slotId", jsonshape.StringLiteral(slot.SlotID)),
		)
	}
	claims := make([]jsonshape.Shape, len(guidance.NonClaims))
	for index, claim := range guidance.NonClaims {
		claims[index] = jsonshape.StringLiteral(claim)
	}
	return jsonshape.Object(
		jsonshape.Required("guidanceId", jsonshape.StringLiteral(guidance.GuidanceID)),
		jsonshape.Required("nonClaims", jsonshape.Tuple(claims...)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(int64(guidance.SchemaVersion))),
		jsonshape.Required("slots", jsonshape.Tuple(slots...)),
	), nil
}

// OutputStructure describes JSON mode only. The text format is a bounded
// derived presentation and is deliberately outside this structural claim.
func OutputStructure() (map[string]any, error) {
	shape, err := OutputShape()
	if err != nil {
		return nil, err
	}
	schema := shape.JSONSchema()
	schema["description"] = fmt.Sprintf("The default JSON mode emits exactly one fixed repository-neutral template: the ordered %d-slot table, its identity and its non-claim, each bound literally to the command-owned table. --format text emits a bounded non-JSON presentation that this schema does not describe. Flag errors emit stderr without JSON. Structural validity does not generate, execute, approve or prove adequacy of any consuming repository's witness, oracle, receipt, policy or cleanup implementation.", SlotCount)
	return schema, nil
}
