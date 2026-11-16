package adoptiondoctor

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestDoctorEnvelopePreservesWireContextPaths(t *testing.T) {
	for _, path := range []struct{ name, prefix string }{
		{"task_names", "docs/task-"},
		{"risk_names", "docs/risk-"},
		{"long_paths", strings.Repeat("segment/", 70) + "task-"},
	} {
		t.Run(path.name, func(t *testing.T) {
			input := completeInput()
			route := input["ownerRoutes"].([]any)[0].(map[string]any)
			want := map[string]string{}
			for index, field := range []string{"specPaths", "proofBindingPaths", "nativeWitnessRefs"} {
				value := path.prefix + field + ".json"
				route[field] = []any{value}
				want[fmt.Sprintf("%s.context.%03d", route["routeId"], index+1)] = value
			}
			candidate := baseInput()["modernization"].(map[string]any)["candidateBoundaries"].([]any)[0].(map[string]any)
			candidate["admissionState"] = "owner_admitted"
			candidate["proofBindingRefs"] = route["proofBindingPaths"]
			candidate["nativeWitnessRefs"] = route["nativeWitnessRefs"]
			candidatePath := path.prefix + "candidate.ts"
			candidate["affectedPaths"] = []any{candidatePath}
			input["modernization"] = map[string]any{"candidateBoundaries": []any{candidate}}
			want[candidate["boundaryId"].(string)+".context.001"] = candidatePath
			authorityPath := path.prefix + "authority.md"
			input["staleAuthority"] = staleAuthorityInput("current", authorityPath, "")
			surface := input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)
			surface["matchedVocabularyIds"] = []any{}
			want[surface["surfaceId"].(string)+".context"] = authorityPath
			if path.name == "long_paths" {
				for _, value := range want {
					if len(value) <= 512 {
						t.Fatal("context path does not cross the scalar truncation boundary")
					}
				}
			}
			envelope, code, err := BuildEnvelope(decodeInput(t, input))
			if err != nil || code != 0 {
				t.Fatalf("complete doctor envelope: exit=%d err=%v", code, err)
			}
			encoded, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			if wire["sourceReport"].(map[string]any)["state"] != "passed" {
				t.Fatal("complete fixture did not reach a passed doctor envelope")
			}
			contexts := wire["contextRefs"].([]any)
			if len(contexts) != len(want) || len(wire["omitted"].([]any)) != 0 || len(wire["commands"].([]any)) != 1 {
				t.Fatalf("complete doctor context/command inventory changed: refs=%d want=%d omitted=%v", len(contexts), len(want), wire["omitted"])
			}
			seenKinds := map[string]bool{}
			for _, raw := range contexts {
				ref := raw.(map[string]any)
				id, ok := ref["refId"].(string)
				value, exists := want[id]
				if !ok || !exists || ref["path"] != value {
					t.Fatalf("context path was altered, duplicated, or invented: %#v", ref)
				}
				delete(want, id)
				seenKinds[ref["kind"].(string)] = true
			}
			if len(want) != 0 || !seenKinds["owner_route"] || !seenKinds["candidate_boundary"] || !seenKinds["stale_authority_surface"] {
				t.Fatal("doctor did not preserve every context-producing family")
			}
		})
	}
}
