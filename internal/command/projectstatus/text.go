package projectstatus

import (
	"fmt"
	"strings"
)

type TextLine struct {
	Label string
	Value string
}

func StatusText(status Status) ([]TextLine, error) {
	admitted, err := AdmitStatusOutput(status.JSONValue())
	if err != nil {
		return nil, err
	}
	status = admitted
	lines := []TextLine{
		{Label: "Project status"},
		{Label: "State", Value: string(status.ProjectState)},
		{Label: "snapshot", Value: status.SnapshotID},
		{Label: "Next", Value: status.NextAction.ActionClass},
	}
	if len(status.IssueCodes) > 0 {
		lines = append(lines, TextLine{Label: "Issues", Value: strings.Join(status.IssueCodes, ", ")})
	}
	return lines, nil
}

func NextText(next Next) ([]TextLine, error) {
	admitted, err := AdmitNextOutput(next.JSONValue())
	if err != nil {
		return nil, err
	}
	next = admitted
	lines := []TextLine{
		{Label: "Project next action"},
		{Label: "State", Value: string(next.ProjectState)},
		{Label: "Action", Value: next.Action.ActionClass},
		{Label: "Executable", Value: "false"},
	}
	if len(next.Action.CommandRoute) > 0 {
		lines = append(lines, TextLine{Label: "Route", Value: strings.Join(next.Action.CommandRoute, " ")})
	}
	if next.Action.ContextRef != "" {
		lines = append(lines, TextLine{Label: "Context", Value: next.Action.ContextRef})
	}
	if next.Action.RequiredDecision != "" {
		lines = append(lines, TextLine{Label: "Decision", Value: next.Action.RequiredDecision})
	}
	if len(next.IssueCodes) > 0 {
		lines = append(lines, TextLine{Label: "Issues", Value: strings.Join(next.IssueCodes, ", ")})
	}
	return lines, nil
}

func RenderText(lines []TextLine) (string, error) {
	if len(lines) == 0 || len(lines) > MaximumTextLines {
		return "", fmt.Errorf("project status text exceeds its line limit")
	}
	plain := make([]string, len(lines))
	for index, line := range lines {
		if line.Label == "" || strings.ContainsAny(line.Label, "\r\n") || strings.ContainsAny(line.Value, "\r\n") {
			return "", fmt.Errorf("project status text coordinate is invalid")
		}
		plain[index] = line.Label
		if line.Value != "" {
			plain[index] += ": " + line.Value
		}
	}
	text := strings.Join(plain, "\n") + "\n"
	if len(text) > MaximumTextBytes {
		return "", fmt.Errorf("project status text exceeds its byte limit")
	}
	return text, nil
}
