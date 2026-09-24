package requirementcontext

import (
	"encoding/json"
	"testing"
)

func TestSliceOutputStructureCoversBothOriginsAndAllProfiles(t *testing.T) {
	for origin, value := range snapshotStructureCases(t) {
		snapshot, err := AdmitSnapshot(value)
		if err != nil {
			t.Fatal(err)
		}
		id := snapshot.RequirementSources[0].Requirements()[0].RequirementID
		for profile := range sliceProfiles {
			t.Run(origin+"/"+profile, func(t *testing.T) {
				output, err := SliceSnapshot(snapshot, map[string]any{"profile": profile, "requirementIds": []any{id}}, "slice.output.structure")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := sliceOutputShape.Admit(predecessorRecord(t, projectTestJSON(t, output)), "slice"); err != nil {
					t.Fatal(err)
				}
				fragment := output["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
				if fragment["authority"] != "lookup_fragment_only" || fragment["selectedRequirementCount"] != 1 {
					t.Fatal("lookup fragment identity/count drift")
				}
				fragment["requirements"].([]any)[0].(map[string]any)["extra"] = true
				if err := sliceOutputShape.CheckGenerated(output, "slice"); err == nil {
					t.Fatal("unknown atomic field accepted")
				}
			})
		}
	}
}

func TestSliceOutputStructurePreservesEmptyKnownSelectorIntersection(t *testing.T) {
	output, err := Slice(map[string]any{
		"context": sliceTopologyFixture(t), "schemaVersion": json.Number("2"), "sliceId": "slice.empty",
		"query": map[string]any{"ownerIds": []any{"consumer.owner-b"}, "profile": "specification", "requirementIds": []any{"REQ-CONSUMER-A"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if output["state"] != "no_match" {
		t.Fatal("empty intersection must remain no_match")
	}
	if err := sliceOutputShape.CheckGenerated(output, "slice"); err != nil {
		t.Fatal(err)
	}
	output["projections"].(map[string]any)["specTree"].(map[string]any)["schemaVersion"] = json.Number("1")
	if err := sliceOutputShape.CheckGenerated(output, "slice"); err == nil {
		t.Fatal("retired tree fragment identity admitted")
	}
}

func TestSliceOutputStructurePreservesBoundedOmissionReasons(t *testing.T) {
	value := snapshotStructureCases(t)["catalog"]
	output, err := Slice(map[string]any{
		"schemaVersion": json.Number("2"), "sliceId": "slice.bounded", "context": value,
		"query": map[string]any{"profile": "routing", "maxNodes": json.Number("1"), "maxRequirements": json.Number("1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	omissions := output["omissions"].([]any)
	if len(omissions) == 0 {
		t.Fatal("bounded fixture did not exercise omissions")
	}
	if err := sliceOutputShape.CheckGenerated(output, "slice"); err != nil {
		t.Fatal(err)
	}
	omissions[0].(map[string]any)["reason"] = "silently_truncated"
	if err := sliceOutputShape.CheckGenerated(output, "slice"); err == nil {
		t.Fatal("unknown omission reason admitted")
	}
}
