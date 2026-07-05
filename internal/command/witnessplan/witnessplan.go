package witnessplan

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

type input struct {
	Commands   []any
	Vocabulary any
}

func Build(raw any) (map[string]any, error) {
	if projected, ok, err := buildProjectedInput(raw); ok || err != nil {
		if err != nil {
			return nil, err
		}
		raw = projected
	}
	input, err := admitInput(raw)
	if err != nil {
		return nil, err
	}
	vocabulary, err := witnesscommand.AdmitVocabulary(input.Vocabulary)
	if err != nil {
		return nil, err
	}
	commands := make([]witnesscommand.Command, 0, len(input.Commands))
	for _, rawCommand := range input.Commands {
		command, err := witnesscommand.AdmitWithVocabulary(rawCommand, vocabulary)
		if err != nil {
			return nil, err
		}
		commands = append(commands, command)
	}
	plan, err := witnesscommand.PlanCommands(commands)
	if err != nil {
		return nil, err
	}
	return plan.JSONValue(), nil
}

func buildProjectedInput(raw any) (map[string]any, bool, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, false, nil
	}
	projectionRaw, hasProjection := record["projection"]
	if !hasProjection {
		return nil, false, nil
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "projection", "requirementProofBinding", "schemaVersion", "vocabulary"}, "witness-plan projection input"); err != nil {
		return nil, true, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return nil, true, fmt.Errorf("witness-plan projection input schemaVersion must be 1")
	}
	projection, err := admit.Enum(projectionRaw, map[string]struct{}{"requirement-bindings": {}}, "witness-plan projection")
	if err != nil {
		return nil, true, err
	}
	if projection != "requirement-bindings" {
		return nil, true, fmt.Errorf("witness-plan projection is unsupported")
	}
	projected, err := requirementbinding.BuildWitnessPlanInput(record["requirementProofBinding"], record["vocabulary"])
	if err != nil {
		return nil, true, err
	}
	return projected, true, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("witness-plan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commands", "vocabulary"}, "witness-plan input"); err != nil {
		return input{}, err
	}
	if _, ok := record["vocabulary"].(map[string]any); !ok {
		return input{}, fmt.Errorf("witness-plan input must include object vocabulary")
	}
	commands, ok := record["commands"].([]any)
	if !ok {
		return input{}, fmt.Errorf("witness-plan input must include commands array")
	}
	return input{Commands: commands, Vocabulary: record["vocabulary"]}, nil
}
