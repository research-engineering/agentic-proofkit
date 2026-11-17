package agentenvelope

import "github.com/research-engineering/agentic-proofkit/internal/kernel/admit"

// Caller provenance is declared by the command owner before display merging.
// Capture the scalar form before argv can give its display a structural role.
type callerDisplayFallback struct {
	field string
	text  string
}

func (fallback callerDisplayFallback) apply(command map[string]any) map[string]any {
	result := copyMap(command)
	delete(result, "argv")
	result[fallback.field] = fallback.text
	return result
}

func prepareCallerDisplayFallbacks(commands []map[string]any, ids []string, field string) (map[string]callerDisplayFallback, map[string]struct{}) {
	pending := map[string]struct{}{}
	for _, id := range ids {
		pending[id] = struct{}{}
	}
	fallbacks := map[string]callerDisplayFallback{}
	for _, command := range commands {
		id := command["commandId"].(string)
		if _, declared := pending[id]; !declared {
			continue
		}
		delete(pending, id)
		if field != "command" && field != "display" {
			continue
		}
		text, ok := command[field].(string)
		if !ok {
			continue
		}
		fallbacks[id] = callerDisplayFallback{field: field, text: admit.RedactDiagnosticValue(text)}
	}
	return fallbacks, pending
}
