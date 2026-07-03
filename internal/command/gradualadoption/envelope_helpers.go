package gradualadoption

func envelopeActionRationale(phase string) string {
	if phase == "route" {
		return "Agents must load only caller-owned routes before changing repository proof surfaces."
	}
	if phase == "bind" {
		return "Requirement and witness bindings must stay synchronized under caller-owned authority."
	}
	if phase == "verify" {
		return "Native witnesses are planned here but must be executed outside proofkit."
	}
	if phase == "modernize-boundary" {
		return "Candidate boundaries remain advisory until the consuming repository owner admits stable requirements and proof bindings."
	}
	return "Promotion is caller-owned and requires resolved routes, bindings, witnesses, and blockers."
}

func envelopeMapValues(values []map[string]any, key string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value[key].(string))
	}
	return result
}
