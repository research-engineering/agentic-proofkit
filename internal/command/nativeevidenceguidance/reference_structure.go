package nativeevidenceguidance

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// ReferenceShape describes the compact owner-replayed link, not the full
// guidance or evidence that a consuming repository fulfilled its slots.
func ReferenceShape() (jsonshape.Shape, error) {
	reference, err := GuidanceReference()
	if err != nil {
		return jsonshape.Shape{}, err
	}
	return jsonshape.Object(
		jsonshape.Required("commandId", jsonshape.StringLiteral(reference.CommandID)),
		jsonshape.Required("contentSha256", jsonshape.StringLiteral(reference.ContentSHA256)),
		jsonshape.Required("guidanceId", jsonshape.StringLiteral(reference.GuidanceID)),
		jsonshape.Required("slotCount", jsonshape.IntegerLiteral(int64(reference.SlotCount))),
	), nil
}
