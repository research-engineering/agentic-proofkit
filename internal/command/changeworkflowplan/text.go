package changeworkflowplan

import (
	"strconv"
	"strings"
)

func textProjection(value projection) []TextLine {
	lines := []TextLine{
		{Label: "Change workflow plan"},
		{Label: "Output", Value: value.Decision.OutputKind},
		{Label: "Completed stages", Value: joinStrings(value.Input.CompletedStageIDs)},
	}
	if value.Decision.OutputKind == "next_action" {
		prompt := value.Prompt
		lines = append(lines,
			TextLine{Label: "Active stage", Value: value.Decision.ActiveStageID},
			TextLine{Label: "Action", Value: value.Decision.Action},
			TextLine{Label: "Checkpoint", Value: value.Decision.CheckpointState},
			TextLine{Label: "Owner or escalation", Value: prompt["ownerOrEscalationTarget"].(string)},
			TextLine{Label: "Stop condition", Value: prompt["stopCondition"].(string)},
			TextLine{Label: "Expected next checkpoint", Value: prompt["expectedNextCheckpoint"].(string)},
		)
		if delta := value.Decision.SuccessorStateDelta; delta != nil {
			lines = append(lines, TextLine{Label: "Successor completed stages", Value: joinStrings(delta.CompletedStageIDs)})
			if delta.Checkpoint == nil {
				lines = append(lines, TextLine{Label: "Successor checkpoint", Value: "none"})
			} else {
				lines = append(lines,
					TextLine{Label: "Successor checkpoint", Value: delta.Checkpoint.State},
					TextLine{Label: "Successor subject ref", Value: delta.Checkpoint.SubjectRefID},
					TextLine{Label: "Successor subject digest", Value: delta.Checkpoint.SubjectDigest},
				)
			}
		}
	} else {
		lines = append(lines,
			TextLine{Label: "Checkpoint", Value: "none"},
			TextLine{Label: "Owner or escalation", Value: "consumer_repository"},
			TextLine{Label: "Stop condition", Value: terminalStop},
			TextLine{Label: "Expected next checkpoint", Value: "none"},
		)
	}
	lines = append(lines,
		TextLine{Label: "Omitted context", Value: integerText(len(value.Closure.Omitted))},
		TextLine{Label: "Non-claim", Value: boundaryNonClaims[1]},
	)
	return lines
}

// RenderText emits the canonical plain bytes from a structured projection.
func RenderText(lines []TextLine) (string, error) {
	return renderText(cloneTextLines(lines))
}

func renderText(lines []TextLine) (string, error) {
	if len(lines) > maxTextLines {
		return "", reject("proofkit.workflow.text_line_limit", "text output exceeds the line limit")
	}
	plain := make([]string, len(lines))
	for index, line := range lines {
		if line.Value == "" {
			plain[index] = line.Label
			continue
		}
		plain[index] = line.Label + ": " + line.Value
	}
	textValue := strings.Join(plain, "\n") + "\n"
	if len(textValue) > maxTextBytes {
		return "", reject("proofkit.workflow.text_output_limit", "text output exceeds the byte limit")
	}
	return textValue, nil
}

func joinStrings(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func integerText(value int) string {
	return strconv.Itoa(value)
}

func cloneTextLines(lines []TextLine) []TextLine {
	return append([]TextLine{}, lines...)
}
