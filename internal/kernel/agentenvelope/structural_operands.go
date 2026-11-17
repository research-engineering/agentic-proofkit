package agentenvelope

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

// OperandBinding is internal metadata, not a wire field. The command owner
// identifies the exact argv position; equal-valued text never grants a role.
type OperandBinding struct {
	CommandID    string
	ArgvIndex    int
	ContextRefID string
	ContextField string // Empty selects the standard ref member.
}

// Only role-specific admission creates this value. Serialization unwraps it
// once; arbitrary caller text still follows scalar redaction.
type admittedStructuralOperand string

func admitStructuralOperands(prepared *preparedLocalReferences, rejected localReferenceTargets, bindings []OperandBinding, fields []ContextReferenceField, renderer cliexec.Renderer, displayField string, callerCommandIDs []string) {
	fallbacks, orphanCommands := prepareCallerDisplayFallbacks(prepared.commands, callerCommandIDs, displayField)
	prepared.callerDisplayFallbacks = fallbacks
	contexts, paths, omitted := admitContextOperands(prepared.contextRefs, fields, rejected.contexts)
	prepared.contextRefs = contexts
	prepared.operandContexts = map[string][]string{}
	byCommand := map[string][]OperandBinding{}
	for _, binding := range bindings {
		byCommand[binding.CommandID] = append(byCommand[binding.CommandID], binding)
	}
	commands := make([]map[string]any, 0, len(prepared.commands))
	for _, command := range prepared.commands {
		id := command["commandId"].(string)
		value, exists := command["argv"]
		if !exists && len(byCommand[id]) == 0 {
			commands = append(commands, command)
			continue
		}
		commandBindings := byCommand[id]
		argv, ok := admitStructuralArgv(value, commandBindings, paths, renderer)
		delete(byCommand, id)
		if !ok || !projectCommandDisplay(command, argv, displayField) {
			if fallback, exists := fallbacks[id]; exists {
				commands = append(commands, fallback.apply(command))
			} else {
				rejected.commands[id] = struct{}{}
			}
			omitted++
			continue
		}
		command["argv"] = argv
		// Seal only successfully admitted dependencies, never caller-owned metadata.
		for _, binding := range commandBindings {
			prepared.operandContexts[id] = append(prepared.operandContexts[id], binding.ContextRefID)
		}
		commands = append(commands, command)
	}
	prepared.commands = commands
	for id := range byCommand {
		orphanCommands[id] = struct{}{}
	}
	for id := range orphanCommands {
		if _, covered := rejected.commands[id]; !covered {
			omitted++
		}
	}
	if omitted > 0 {
		prepared.omitted = append(prepared.omitted, omissionRecord("unsafeStructuralOperand", "commandOrContextOperands", omitted))
	}
}

func projectCommandDisplay(command map[string]any, argv []any, field string) bool {
	switch field {
	case "":
		return true
	case "command", "display":
	default:
		return false
	}
	if _, present := command[field]; !present {
		return true
	}
	values := make([]string, len(argv))
	for index, value := range argv {
		switch text := value.(type) {
		case string:
			values[index] = text
		case admittedStructuralOperand:
			values[index] = string(text)
		default:
			return false
		}
	}
	display, err := cliexec.SafeDisplayArgv(values, "agent envelope command")
	if err != nil {
		return false
	}
	command[field] = admittedStructuralOperand(display)
	return true
}

func admitStructuralArgv(raw any, bindings []OperandBinding, paths map[contextOperandKey]admittedStructuralOperand, renderer cliexec.Renderer) ([]any, bool) {
	var items []any
	switch values := raw.(type) {
	case []any:
		items = values
	case []string:
		items = make([]any, len(values))
		for index, value := range values {
			items[index] = value
		}
	default:
		return nil, false
	}
	bound := map[int]admittedStructuralOperand{}
	if renderer.Profile() == cliexec.ProfilePythonModule {
		prefix := renderer.Argv()
		matches := len(items) >= len(prefix)
		for index, expected := range prefix {
			if index >= len(items) || items[index] != expected {
				matches = false
				break
			}
		}
		if matches {
			if !unicodepolicy.ValidScalarString(prefix[0]) || unicodepolicy.ContainsUnsafeScalar(prefix[0]) {
				return nil, false
			}
			bound[0] = admittedStructuralOperand(prefix[0])
		}
	}
	for _, binding := range bindings {
		index := binding.ArgvIndex
		if index < 0 || index >= len(items) {
			return nil, false
		}
		if _, duplicate := bound[index]; duplicate {
			return nil, false
		}
		field := binding.ContextField
		if field == "" {
			field = "ref"
		}
		text, ok := items[index].(string)
		path, admitted := paths[contextOperandKey{binding.ContextRefID, field}]
		if !ok || !admitted || string(path) != text {
			return nil, false
		}
		bound[index] = path
	}
	result := make([]any, len(items))
	for index, value := range items {
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		if operand, admitted := bound[index]; admitted {
			result[index] = operand
		} else if admit.RedactStructuralText(text) == text {
			result[index] = text
		} else {
			return nil, false
		}
	}
	return result, true
}

func commandsWithRetainedOperandContexts(commands []map[string]any, contexts []map[string]any, dependencies map[string][]string, fallbacks map[string]callerDisplayFallback) ([]map[string]any, int) {
	retained := idSet(contexts, "refId")
	missing := map[string]struct{}{}
	for commandID, refs := range dependencies {
		for _, ref := range refs {
			if _, exists := retained[ref]; !exists {
				missing[commandID] = struct{}{}
			}
		}
	}
	result := make([]map[string]any, 0, len(commands))
	omitted := 0
	for _, command := range commands {
		if _, typed := command["argv"]; !typed {
			result = append(result, command)
			continue
		}
		if _, absent := missing[command["commandId"].(string)]; absent {
			omitted++
			if fallback, exists := fallbacks[command["commandId"].(string)]; exists {
				result = append(result, fallback.apply(command))
			}
			continue
		}
		result = append(result, command)
	}
	return result, omitted
}
