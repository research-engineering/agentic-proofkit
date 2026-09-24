package requirementimpactinput

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
)

func TestBaselinePresenceIsIndependentOfRequirementCardinality(t *testing.T) {
	for _, sourceState := range []string{"null", "empty", "nonempty"} {
		for _, contractState := range []string{"null", "empty", "nonempty"} {
			t.Run(sourceState+"/"+contractState, func(t *testing.T) {
				input := validComposeInput(t)
				switch sourceState {
				case "null":
					input["baseRequirementSources"] = nil
				case "empty":
					input["baseRequirementSources"] = []any{requirementSource([]any{})}
				}
				switch contractState {
				case "null":
					input["baseCompactProofContract"] = nil
				case "empty":
					contract := input["baseCompactProofContract"].(map[string]any)
					contract["bindings"] = []any{}
					contract["surfaces"] = []any{}
				}
				output, exit, err := Build(input)
				if (sourceState == "null") != (contractState == "null") {
					if err == nil || !strings.Contains(err.Error(), "must both be present or both be null") {
						t.Fatalf("mismatched baseline presence: exit=%d error=%v", exit, err)
					}
					return
				}
				if err != nil || exit != 0 {
					t.Fatalf("present baseline rejected by cardinality: exit=%d error=%v", exit, err)
				}
				if _, _, err := impact.Build(output); err != nil {
					t.Fatalf("composed input violates downstream admission: %v", err)
				}
			})
		}
	}
}
