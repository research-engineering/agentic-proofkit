package requirementbrowser

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The workspace shows the source owner's deferral record and the deferred
// count; it must not invent deferral for other claim levels.
func TestWorkspaceExposesOwnerDeclaredDeferral(t *testing.T) {
	fixture := workspaceFixture(t)
	context := fixture["context"].(map[string]any)
	fields := workspaceSourceMember(context)["fields"].(map[string]any)
	fields["claimLevel"] = "deferred"
	fields["deferral"] = map[string]any{
		"ownerId": "consumer.owner", "riskAcceptedBy": "consumer.product", "reviewCondition": "Before the express release.",
		"expiryRef": "roadmap.2026-q4", "mergePolicy": "advisory_until_implemented", "evidenceRefs": []any{"roadmap.express"},
	}
	resignWorkspaceSnapshot(t, context)
	handle, capability := startWorkspaceTestServer(t, fixture, false)
	manifest := getWorkspaceJSON(t, handle.URL+"api/v1/manifest", capability)
	if manifest["requirementCount"] != json.Number("1") || manifest["deferredRequirementCount"] != json.Number("1") {
		t.Fatalf("manifest counts = %v/%v, want 1/1", manifest["requirementCount"], manifest["deferredRequirementCount"])
	}
	response := postWorkspaceJSON(t, handle.URL+"api/v1/requirements", capability, map[string]any{"requestId": "lookup.deferral", "snapshotId": handle.SnapshotID, "query": map[string]any{}})
	row := response["projection"].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	want := map[string]any{
		"evidenceRefs": []any{"roadmap.express"}, "expiryRef": "roadmap.2026-q4", "mergePolicy": "advisory_until_implemented",
		"ownerId": "consumer.owner", "reviewCondition": "Before the express release.", "riskAcceptedBy": "consumer.product",
	}
	if row["claimLevel"] != "deferred" || !reflect.DeepEqual(row["deferral"], want) {
		t.Fatalf("deferred row = %#v, want deferral %#v", row, want)
	}

	blocking, blockingCapability := startWorkspaceTestServer(t, workspaceFixture(t), false)
	manifest = getWorkspaceJSON(t, blocking.URL+"api/v1/manifest", blockingCapability)
	response = postWorkspaceJSON(t, blocking.URL+"api/v1/requirements", blockingCapability, map[string]any{"requestId": "lookup.blocking", "snapshotId": blocking.SnapshotID, "query": map[string]any{}})
	row = response["projection"].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	if value, present := row["deferral"]; !present || value != nil || manifest["deferredRequirementCount"] != json.Number("0") {
		t.Fatalf("blocking row deferral = %#v (present %v), deferred count %v", value, present, manifest["deferredRequirementCount"])
	}
}
