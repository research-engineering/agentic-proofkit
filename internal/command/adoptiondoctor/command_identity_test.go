package adoptiondoctor

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func TestDoctorCommandCatalogReservesSourceIdentityBeforeBounds(t *testing.T) {
	for _, count := range []int{1, agentenvelope.MaxCommandRefs + 1} {
		for _, collision := range []bool{false, true} {
			doctorID := "unrelated.source"
			if collision {
				doctorID = fmt.Sprintf("r.command.%03d", count)
			}
			input := doctorSourceCollisionInput("r", doctorID, true)
			commands := []any{}
			for index := 0; index < count; index++ {
				commands = append(commands, fmt.Sprintf("go test ./case%03d", index))
			}
			input["ownerRoutes"].([]any)[0].(map[string]any)["commands"] = commands
			envelope, code := wireDoctorEnvelope(t, input)
			if code != 0 || envelope["sourceReport"].(map[string]any)["reportId"] != doctorID {
				t.Fatal("source identity or advisory report state changed")
			}
			retained := map[any]bool{}
			for _, raw := range envelope["commands"].([]any) {
				command := raw.(map[string]any)
				if command["commandId"] == doctorID {
					t.Fatal("external source identity was allocated as a local command")
				}
				retained[command["commandId"]] = true
			}
			if count == 1 && !retained[map[bool]string{true: "r.command.001.local", false: "r.command.001"}[collision]] {
				t.Fatal("ordinary or collision-resolved command identity drifted")
			}
			for _, raw := range envelope["routeQuestions"].([]any) {
				if !reflect.DeepEqual(raw.(map[string]any)["evidenceRefs"], []any{doctorID}) {
					t.Fatal("command bounds pruned or rebound the source report reference")
				}
			}
			for _, raw := range envelope["actionPlan"].([]any) {
				action := raw.(map[string]any)
				for _, id := range action["commandIds"].([]any) {
					if !retained[id] || id == doctorID {
						t.Fatal("action command declaration and reference allocations diverged")
					}
				}
			}
		}
	}
}
