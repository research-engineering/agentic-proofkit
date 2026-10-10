package projectstructure

import (
	"strings"
	"testing"
)

func TestProjectScaffoldRefusesUnsafeBootstrapPayload(t *testing.T) {
	marker := "api_" + "key=synthetic-scaffold-fixture"
	for _, build := range []func(any) (map[string]any, int, error){Build, BuildEnvelope} {
		input := validProjectStructureInput()
		input["bootstrap"].(map[string]any)["budget"].(map[string]any)["unadmittedExtra"] = marker
		output, exit, err := build(input)
		if output != nil || exit != 1 || err == nil {
			t.Fatal("scaffold bypassed bootstrap refusal")
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatal("scaffold error disclosed caller text")
		}
	}
}
