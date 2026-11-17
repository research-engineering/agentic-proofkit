package gradualadoption

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

var preparedOperations = []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"}

// PreparedCommand is a child-owned operation/input pair bound to the current
// invocation renderer. It is not a wire record or an execution capability.
type PreparedCommand struct {
	command  string
	inputRef string
	renderer cliexec.Renderer
}

func (command PreparedCommand) Command() string  { return command.command }
func (command PreparedCommand) InputRef() string { return command.inputRef }

func (command PreparedCommand) Argv() []string {
	if command.command == "" {
		return nil
	}
	return command.renderer.Argv(command.command, "--input", command.inputRef)
}

func (command PreparedCommand) DisplayCommand() string {
	return cliexec.DisplayArgv(command.Argv())
}

func (result BootstrapResult) PreparedCommands() []PreparedCommand {
	return slices.Clone(result.preparedCommands)
}

func admitPreparedCommands(raw map[string]any, renderer cliexec.Renderer, failures *[]string) []PreparedCommand {
	value, present := raw["proofkitCommands"]
	if !present {
		return nil
	}
	commands, ok := value.(map[string]any)
	if !ok {
		*failures = append(*failures, "agentGuidance proofkitCommands must be an object")
		return nil
	}
	if err := admit.KnownKeys(commands, preparedOperations, "agentGuidance proofkitCommands"); err != nil {
		addErr(failures, err)
		return nil
	}
	prepared := make([]PreparedCommand, 0, len(preparedOperations))
	for _, operation := range preparedOperations {
		value, present := commands[operation]
		if !present {
			continue
		}
		path, ok := value.(string)
		if !ok {
			*failures = append(*failures, fmt.Sprintf("agentGuidance proofkitCommands %s must name a materialized input path", operation))
			continue
		}
		command, err := admitPreparedCommand(operation, path, renderer, "agentGuidance proofkitCommands "+operation)
		addErr(failures, err)
		if err == nil {
			prepared = append(prepared, command)
		}
	}
	return prepared
}

func admitPreparedCommand(operation, path string, renderer cliexec.Renderer, context string) (PreparedCommand, error) {
	path, err := admit.MaterializedInputPath(path, context)
	if err != nil {
		return PreparedCommand{}, err
	}
	if unicodepolicy.ContainsUnsafeScalar(path) {
		return PreparedCommand{}, fmt.Errorf("%s must contain only safe Unicode scalars", context)
	}
	command := PreparedCommand{command: operation, inputRef: path, renderer: renderer}
	display := command.DisplayCommand()
	if unicodepolicy.ContainsUnsafeScalar(display) || admit.ContainsSecretLikePathValue(display) {
		return PreparedCommand{}, fmt.Errorf("%s must render safe prepared command text", context)
	}
	return command, nil
}

func preparedCommandSource(commands []PreparedCommand) map[string]any {
	source := make(map[string]any, len(commands))
	for _, command := range commands {
		source[command.command] = command.inputRef
	}
	return source
}

func preparedCommandDisplays(caller []string, commands []PreparedCommand) []string {
	combined := append([]string{}, caller...)
	for _, command := range commands {
		display := command.DisplayCommand()
		if !contains(combined, display) {
			combined = append(combined, display)
		}
	}
	return combined
}

func bootstrapPreparedCommands(paths map[string]any, renderer cliexec.Renderer, failures *[]string) []PreparedCommand {
	commands := make([]PreparedCommand, 0, len(preparedOperations))
	for index, key := range []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath"} {
		// Path admission already collected errors and replaced invalid values.
		if path := stringFromMap(paths, key); path != "" {
			command, err := admitPreparedCommand(preparedOperations[index], path, renderer, "bootstrap "+key)
			addErr(failures, err)
			if err == nil {
				commands = append(commands, command)
			}
		}
	}
	return commands
}
