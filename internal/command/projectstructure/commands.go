package projectstructure

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

type preparedCommand struct {
	argv     []string
	inputRef string
}

func projectCommands(paths projectPathSet, bootstrap gradualadoption.BootstrapResult, renderer cliexec.Renderer) []preparedCommand {
	commands := []preparedCommand{}
	for _, item := range []struct{ operation, path string }{
		{"scaffold-profile-plan", paths.repoProfileScaffoldInputPath},
		{"gradual-adoption-bootstrap", paths.bootstrapInputPath},
		{"adoption-workflow-plan", paths.workflowInputPath},
	} {
		commands = append(commands, preparedCommand{renderer.Argv(item.operation, "--input", item.path), item.path})
	}
	for _, child := range bootstrap.PreparedCommands() {
		commands = append(commands, preparedCommand{child.Argv(), child.InputRef()})
	}
	return commands
}

func commandDisplays(commands []preparedCommand) []any {
	values := make([]any, 0, len(commands))
	for _, command := range commands {
		values = append(values, cliexec.DisplayArgv(command.argv))
	}
	return values
}

func commandRefs(commands []preparedCommand, contexts []map[string]any) ([]map[string]any, []agentenvelope.OperandBinding) {
	refs := make([]map[string]any, 0, len(commands))
	bindings := []agentenvelope.OperandBinding{}
	for index, command := range commands {
		id := fmt.Sprintf("proofkit.project-structure.command.%03d", index+1)
		refs = append(refs, map[string]any{
			"argv": admit.StringSliceToAny(command.argv), "command": cliexec.DisplayArgv(command.argv), "commandId": id,
			"nonClaim": "Project-structure commands are planned invocations, not execution or pass evidence.",
			"owner":    "consumer_repository", "purpose": "Caller-owned follow-up command emitted by project-structure scaffold planning.",
		})
		// The manifest owner enforces unique exact materialized paths.
		contextID := ""
		for _, context := range contexts {
			if context["ref"] == command.inputRef {
				contextID = context["refId"].(string)
				break
			}
		}
		// A lost target still carries a binding, so it cannot become untyped argv.
		bindings = append(bindings, agentenvelope.OperandBinding{CommandID: id, ArgvIndex: len(command.argv) - 1, ContextRefID: contextID})
	}
	return refs, bindings
}
