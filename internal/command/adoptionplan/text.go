package adoptionplan

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
)

// TextProjection derives bounded human coordinates from the same typed plan as
// JSON output. Presentation adapters may style labels but not semantic values.
func TextProjection(plan Plan) ([]TextLine, error) {
	if _, err := AdmitOutput(plan.JSONValue()); err != nil {
		return nil, err
	}
	stack := "none"
	if plan.StackHint != nil {
		stack = plan.StackHint.PresetID
	}
	lines := []TextLine{
		{Label: "Adoption plan"},
		{Label: "Mode", Value: plan.Intent},
		{Label: "State", Value: PlanState},
		{Label: "Inventory", Value: fmt.Sprintf("%d recognized, %d omitted, %d opaque", len(plan.Inventory.Entries), len(plan.Inventory.Omissions.OmittedRecognized), plan.Inventory.Omissions.UnrecognizedCount)},
		{Label: "Stack hint", Value: stack},
		{Label: "Authority", Value: "candidate-only; consuming repository owner"},
	}
	for _, task := range plan.Packet.Tasks {
		lines = append(lines, TextLine{Label: fmt.Sprintf("Next %d", task.Order), Value: task.Instruction})
	}
	lines = append(lines, TextLine{Label: "Evidence template", Value: plan.Packet.GuidanceReference.CommandID})
	for _, nonClaim := range boundaryNonClaims {
		lines = append(lines, TextLine{Label: "Non-claim", Value: nonClaim})
	}
	for _, nonClaim := range repositoryinventory.NonClaims() {
		lines = append(lines, TextLine{Label: "Inventory non-claim", Value: nonClaim})
	}
	if len(lines) > MaximumTextLines {
		return nil, fmt.Errorf("adoption plan text exceeds line limit")
	}
	return append([]TextLine{}, lines...), nil
}

func RenderText(lines []TextLine) (string, error) {
	return renderTextWithinLimits(lines, MaximumTextBytes, MaximumTextLines)
}

func renderTextWithinLimits(lines []TextLine, maximumBytes, maximumLines int) (string, error) {
	if len(lines) > maximumLines {
		return "", fmt.Errorf("adoption plan text exceeds line limit")
	}
	plain := make([]string, len(lines))
	for index, line := range lines {
		if line.Label == "" || strings.ContainsAny(line.Label, "\r\n") || strings.ContainsAny(line.Value, "\r\n") {
			return "", fmt.Errorf("adoption plan text coordinate is invalid")
		}
		plain[index] = line.Label
		if line.Value != "" {
			plain[index] += ": " + line.Value
		}
	}
	text := strings.Join(plain, "\n") + "\n"
	if len(text) > maximumBytes {
		return "", fmt.Errorf("adoption plan text exceeds byte limit")
	}
	return text, nil
}
