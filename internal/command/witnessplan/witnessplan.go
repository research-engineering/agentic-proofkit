package witnessplan

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

type input struct {
	Commands   []any
	Vocabulary any
}

func Build(raw any) (map[string]any, error) {
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
