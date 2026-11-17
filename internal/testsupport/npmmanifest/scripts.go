// Package npmmanifest selects npm script values for repository test oracles.
package npmmanifest

import (
	"encoding/json"
	"fmt"
)

// Scripts selects the exact lowercase property and its final complete value.
// Command bodies and lifecycle policy remain with the individual gate owners.
func Scripts(raw []byte) (map[string]string, error) {
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("package manifest must be a JSON object")
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(manifest["scripts"], &values); err != nil || values == nil {
		return nil, fmt.Errorf("package manifest must contain the exact scripts object")
	}
	scripts := make(map[string]string, len(values))
	for name, rawValue := range values {
		var value any
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return nil, fmt.Errorf("package scripts must contain only string commands")
		}
		command, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("package scripts must contain only string commands")
		}
		scripts[name] = command
	}
	return scripts, nil
}
