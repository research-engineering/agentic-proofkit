package changeworkflowplan

import (
	"encoding/json"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// Project admits raw input once and derives every supported presentation from
// the resulting immutable values.
func Project(raw any) (Result, error) {
	internal, err := project(raw)
	if err != nil {
		return Result{}, err
	}
	lines := textProjection(internal)
	textValue, err := renderText(lines)
	if err != nil {
		return Result{}, err
	}
	envelope, err := agentEnvelope(internal)
	if err != nil {
		return Result{}, err
	}
	return Result{AgentEnvelope: envelope, Plan: internal.Plan, Text: textValue, TextLines: cloneTextLines(lines)}, nil
}

func project(raw any) (projection, error) {
	input, err := admitInput(raw)
	if err != nil {
		return projection{}, err
	}
	decision, err := decide(input)
	if err != nil {
		return projection{}, err
	}
	closure, err := leastClosure(input)
	if err != nil {
		return projection{}, err
	}
	prompt := map[string]any(nil)
	if decision.OutputKind == "next_action" {
		prompt, err = buildPrompt(input, decision, closure)
		if err != nil {
			return projection{}, err
		}
	}
	internal := projection{Decision: decision, Input: input, Closure: closure, Prompt: prompt}
	internal.Plan = planValue(internal)
	if err := enforceJSONCap(internal.Plan); err != nil {
		return projection{}, err
	}
	return internal, nil
}

// Build returns the canonical JSON projection for one explicit snapshot.
func Build(raw any) (map[string]any, error) {
	result, err := project(raw)
	if err != nil {
		return nil, err
	}
	return result.Plan, nil
}

// BuildText returns the bounded plain-text projection for one explicit snapshot.
func BuildText(raw any) (string, error) {
	result, err := project(raw)
	if err != nil {
		return "", err
	}
	return renderText(textProjection(result))
}

// BuildTextProjection returns a fresh command-owned label/value projection.
// Labels may be styled by an app; values must be emitted unchanged.
func BuildTextProjection(raw any) ([]TextLine, error) {
	result, err := project(raw)
	if err != nil {
		return nil, err
	}
	return cloneTextLines(textProjection(result)), nil
}

// BuildAgentEnvelope returns the bounded generic agent-envelope projection.
func BuildAgentEnvelope(raw any) (map[string]any, error) {
	result, err := project(raw)
	if err != nil {
		return nil, err
	}
	return agentEnvelope(result)
}

func planValue(value projection) map[string]any {
	plan := map[string]any{
		"authority":             "derived_non_authoritative_plan",
		"completedStageIds":     stringsValue(value.Input.CompletedStageIDs),
		"nonClaims":             stringsValue(boundaryNonClaims),
		"omittedContextCount":   len(value.Closure.Omitted),
		"omittedContextRefIds":  stringsValue(contextRefIDs(value.Closure.Omitted)),
		"outputKind":            value.Decision.OutputKind,
		"reportId":              reportKind,
		"reportKind":            reportKind,
		"retainedContextRefIds": stringsValue(contextRefIDs(value.Closure.Retained)),
		"retainedContextRefs":   contextRefsValue(value.Closure.Retained),
		"schemaVersion":         json.Number("1"),
	}
	if value.Decision.OutputKind == "workflow_complete" {
		return plan
	}
	plan["action"] = value.Decision.Action
	plan["activeStageId"] = value.Decision.ActiveStageID
	plan["checkpointState"] = value.Decision.CheckpointState
	plan["prompt"] = value.Prompt
	if value.Decision.SuccessorStateDelta != nil {
		plan["successorStateDelta"] = successorValue(*value.Decision.SuccessorStateDelta)
	}
	return plan
}

func successorValue(delta successorStateDelta) map[string]any {
	result := map[string]any{
		"completedStageIds": stringsValue(delta.CompletedStageIDs),
		"checkpoint":        nil,
	}
	if delta.Checkpoint != nil {
		result["checkpoint"] = map[string]any{"state": delta.Checkpoint.State}
	}
	return result
}

func enforceJSONCap(value map[string]any) error {
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > maxJSONBytes {
		return reject("proofkit.workflow.json_output_limit", "JSON output exceeds the byte limit")
	}
	return nil
}
