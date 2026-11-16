package agentenvelope

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

const (
	ContextPathOperand    = "context_path"
	PythonLauncherOperand = "python_launcher"
)

// OperandBinding is internal metadata, not a wire field. The command owner
// identifies the exact argv position; matching text alone never grants a role.
type OperandBinding struct {
	CommandID    string
	ArgvIndex    int
	ContextRefID string
	Role         string
}

// Only role-specific admission creates this type. Serialization unwraps the
// admitted value once; arbitrary caller text still follows scalar redaction.
type admittedStructuralOperand string

func admitStructuralOperands(prepared *preparedLocalReferences, rejected map[string]struct{}, bindings []OperandBinding) {
	paths := map[string]admittedStructuralOperand{}
	contexts := make([]map[string]any, 0, len(prepared.contextRefs))
	omitted := 0
	for _, context := range prepared.contextRefs {
		value, exists := context["ref"]
		if !exists {
			contexts = append(contexts, context)
			continue
		}
		text, isText := value.(string)
		canonical, pathErr := admit.SafeRepoRelativePath(text, "agent envelope path operand")
		isPath := context["kind"] == "path"
		if !isText || !unicodepolicy.ValidScalarString(text) || unicodepolicy.ContainsUnsafeScalar(text) ||
			(admit.RedactStructuralText(text) != text && (!isPath || pathErr != nil)) {
			rejected[context["refId"].(string)] = struct{}{}
			omitted++
			continue
		}
		operand := admittedStructuralOperand(text)
		if isPath {
			if pathErr == nil {
				operand = admittedStructuralOperand(canonical)
			}
			paths[context["refId"].(string)] = operand
		}
		context["ref"] = operand
		contexts = append(contexts, context)
	}
	prepared.contextRefs = contexts
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
		argv, ok := admitStructuralArgv(value, byCommand[id], paths)
		delete(byCommand, id)
		if !ok {
			rejected[id] = struct{}{}
			omitted++
			continue
		}
		command["argv"] = argv
		commands = append(commands, command)
	}
	prepared.commands = commands
	for _, unmatched := range byCommand {
		omitted += len(unmatched)
	}
	if omitted > 0 {
		prepared.omitted = append(prepared.omitted, omissionRecord("unsafeStructuralOperand", "commandOrContextOperands", omitted))
	}
}

func admitStructuralArgv(raw any, bindings []OperandBinding, paths map[string]admittedStructuralOperand) ([]any, bool) {
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
	for _, binding := range bindings {
		index := binding.ArgvIndex
		if index < 0 || index >= len(items) {
			return nil, false
		}
		if _, duplicate := bound[index]; duplicate {
			return nil, false
		}
		text, ok := items[index].(string)
		if !ok {
			return nil, false
		}
		switch binding.Role {
		case ContextPathOperand:
			path, admitted := paths[binding.ContextRefID]
			if !admitted || string(path) != text {
				return nil, false
			}
			bound[index] = path
		case PythonLauncherOperand:
			if index != 0 || binding.ContextRefID != "" || !unicodepolicy.ValidScalarString(text) || unicodepolicy.ContainsUnsafeScalar(text) {
				return nil, false
			}
			if _, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, text); err != nil {
				return nil, false
			}
			bound[index] = admittedStructuralOperand(text)
		default:
			return nil, false
		}
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
