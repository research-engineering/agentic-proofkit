package agentenvelope

// Caller provenance is declared by the command owner before display merging.
// Capture the scalar form before argv can give its display a structural role.
func prepareCallerDisplayFallbacks(commands []map[string]any, ids []string, field string) (map[string]map[string]any, map[string]struct{}) {
	pending := map[string]struct{}{}
	for _, id := range ids {
		pending[id] = struct{}{}
	}
	fallbacks := map[string]map[string]any{}
	for _, command := range commands {
		id := command["commandId"].(string)
		if _, declared := pending[id]; !declared {
			continue
		}
		delete(pending, id)
		if field != "command" && field != "display" {
			continue
		}
		if _, text := command[field].(string); !text {
			continue
		}
		fallback := make(map[string]any, len(command))
		for key, value := range command {
			if key != "argv" {
				fallback[key] = value
			}
		}
		fallbacks[id] = sanitizeMap(fallback)
	}
	return fallbacks, pending
}
