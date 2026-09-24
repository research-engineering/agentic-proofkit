package proofbindingtestinventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectionRequiresWholeGroupedSourceAdmission(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"old input identity", func(input map[string]any) { input["schemaVersion"] = json.Number("2") }, "schemaVersion must be 3"},
		{"flat partial source", func(input map[string]any) {
			input["requirementSource"] = map[string]any{"requirements": []any{map[string]any{"requirementId": "REQ-PROOFKIT-COMPACT-001", "ownerId": "proofkit.spec"}}}
		}, "requirementSource"},
		{"failed source policy", func(input map[string]any) {
			projectionSourceMember(input)["fields"].(map[string]any)["proofBindingRefs"] = []any{}
		}, "failed admission"},
		{"duplicate identity", func(input map[string]any) {
			group := input["requirementSource"].(map[string]any)["groups"].([]any)[0].(map[string]any)
			group["members"] = append(group["members"].([]any), projectionSourceMember(input))
		}, "requirementSource"},
		{"invalid unrelated sibling", func(input map[string]any) {
			group := input["requirementSource"].(map[string]any)["groups"].([]any)[0].(map[string]any)
			group["members"] = append(group["members"].([]any), map[string]any{
				"requirementId": "REQ-UNRELATED-001", "statementCompletion": "Unrelated input is still admitted.", "fields": map[string]any{},
			})
		}, "requirementSource"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validInput()
			item.edit(input)
			out, exit, err := Build(input)
			if err == nil || exit != 1 || out != nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() = %v, %d, %v; want no projection and %q", out, exit, err, item.want)
			}
		})
	}
}

func TestProjectionOwnerComesFromResolvedProfile(t *testing.T) {
	input := validInput()
	source := input["requirementSource"].(map[string]any)
	source["profiles"] = []any{map[string]any{"profileId": "RPROF-TEST", "fields": map[string]any{"ownerId": "changed.owner"}}}
	group := source["groups"].([]any)[0].(map[string]any)
	group["profileId"] = "RPROF-TEST"
	member := projectionSourceMember(input)
	delete(member["fields"].(map[string]any), "ownerId")
	group["members"] = append(group["members"].([]any), map[string]any{
		"requirementId": "REQ-UNROUTED-001", "statementCompletion": "Another member shares its metadata owner.", "fields": member["fields"],
	})
	output, exit, err := Build(input)
	if err != nil || exit != 0 {
		t.Fatalf("Build() = %v, %d", err, exit)
	}
	entry := output.(map[string]any)["inventory"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	if entry["ownerId"] != "changed.owner" || entry["evidenceClass"] != "proof_route_candidate" {
		t.Fatalf("resolved owner or evidence class lost: %#v", entry)
	}
}

func projectionSourceMember(input map[string]any) map[string]any {
	return input["requirementSource"].(map[string]any)["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
}
