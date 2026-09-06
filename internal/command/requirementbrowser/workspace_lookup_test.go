package requirementbrowser

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestWorkspaceLookupFiltersTheWholeCohortBeforePaging(t *testing.T) {
	handle, capability := startWorkspaceTestServer(t, workspaceLookupFixture(t), false)
	for _, item := range []struct {
		name     string
		query    map[string]any
		ids      []string
		matching int
	}{
		{"nested role isolation", map[string]any{"nodeId": "spec.grandchild"}, []string{"REQ-C"}, 1},
		{"known empty intersection", map[string]any{"nodeId": "spec.grandchild", "ownerId": "owner.b"}, []string{}, 0},
		{"full cohort search", map[string]any{"searchText": "keeps source identity"}, []string{"REQ-B-129"}, 1},
		{"unicode literal", map[string]any{"searchText": " \U0001f9ed E\u0301 "}, []string{"REQ-B-129"}, 1},
		{"no implicit unicode normalization", map[string]any{"searchText": "\u00e9"}, []string{}, 0},
		{"id simple case", map[string]any{"searchText": "req-b-128"}, []string{"REQ-B-128"}, 1},
		{"no cross field concatenation", map[string]any{"searchText": "REQ-B-129 owner.b"}, []string{}, 0},
		{"lifecycle without replacement expansion", map[string]any{"lifecycleState": "superseded", "ownerId": "owner.b"}, []string{"REQ-B-000"}, 1},
		{"intersection before offset", map[string]any{"nodeId": "spec.child", "ownerId": "owner.b", "lifecycleState": "active", "offset": json.Number("127"), "maxRecords": json.Number("64")}, []string{"REQ-B-129"}, 128},
		{"descendants but not ancestors", map[string]any{"nodeId": "spec.child", "offset": json.Number("130")}, []string{"REQ-C"}, 131},
	} {
		t.Run(item.name, func(t *testing.T) {
			response := postWorkspaceJSON(t, handle.URL+"api/v1/requirements", capability, map[string]any{"requestId": "lookup.test", "snapshotId": handle.SnapshotID, "query": item.query})
			projection := response["projection"].(map[string]any)
			assertWorkspaceRowIDs(t, projection["requirements"], "requirementId", item.ids)
			for key, want := range map[string]int{"availableRequirementCount": 132, "matchingRequirementCount": item.matching, "selectedRequirementCount": len(item.ids), "filteredOutRequirementCount": 132 - item.matching, "pageOmittedRequirementCount": item.matching - len(item.ids), "omittedRequirementCount": 132 - len(item.ids)} {
				if projection[key] != json.Number(fmt.Sprint(want)) {
					t.Fatalf("%s = %v, want %d", key, projection[key], want)
				}
			}
			if response["requestId"] != "lookup.test" || response["snapshotId"] != handle.SnapshotID || response["state"] != "partial_with_omissions" {
				t.Fatal("lookup lost request identity or existing omission semantics")
			}
		})
	}
}

func TestWorkspaceLookupPreservesOriginalAnchorAndDistinctHandoffClosure(t *testing.T) {
	workspace, _, err := buildWorkspace(workspaceLookupFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	handle, capability := startWorkspaceTestServer(t, workspaceLookupFixture(t), false)
	response := postWorkspaceJSON(t, handle.URL+"api/v1/requirements", capability, map[string]any{"requestId": "lookup.anchor", "snapshotId": handle.SnapshotID, "query": map[string]any{"lifecycleState": "superseded"}})
	rows := response["projection"].(map[string]any)["requirements"].([]any)
	assertWorkspaceRowIDs(t, rows, "requirementId", []string{"REQ-B-000"})
	anchor := rows[0].(map[string]any)["anchor"].(map[string]any)
	if anchor["jsonPointer"] != "/projections/requirementSources/1/requirements/0/invariant" || anchor["sourceDigest"] != digest.SHA256TextRef("source-b") {
		t.Fatal("lookup rebased the original source anchor")
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/handoff", strings.NewReader(`{"annotations":[{"anchorId":"requirement:REQ-B-000:invariant","exactQuote":"Capability","startCodePoint":0,"endCodePoint":10,"question":"Is replacement required?"}]}`))
	packet, err := buildHandoffPacket(request, workspace)
	if err != nil {
		t.Fatal(err)
	}
	contextValue := packet["context"].(map[string]any)
	projections := contextValue["projections"].(map[string]any)
	sources := projections["requirementSources"].([]any)
	if len(sources) != 1 || sources[0].(map[string]any)["sourceId"] != "consumer.b" {
		t.Fatal("handoff source closure is not the selected source")
	}
	assertWorkspaceRowIDs(t, sources[0].(map[string]any)["requirements"], "requirementId", []string{"REQ-B-000", "REQ-B-001"})
	tree := projections["specTree"].(map[string]any)
	if len(tree["overlays"].([]any)) != 2 {
		t.Fatal("handoff lost the two distinct path-reference overlays")
	}
	for _, raw := range tree["nodes"].([]any) {
		node := raw.(map[string]any)
		if node["nodeId"] != "spec.root" {
			continue
		}
		assertWorkspaceRowIDs(t, node["sourceRefs"], "sourceRefId", []string{"root.path-a", "root.path-b"})
	}
}

func TestWorkspaceNavigationPagesAdmittedChildrenOnly(t *testing.T) {
	handle, capability := startWorkspaceTestServer(t, workspaceLookupFixture(t), false)
	for _, item := range []struct {
		query map[string]any
		ids   []string
	}{
		{map[string]any{}, []string{"spec.root"}},
		{map[string]any{"parentNodeId": "spec.root"}, []string{"spec.child"}},
		{map[string]any{"parentNodeId": "spec.child"}, []string{"spec.grandchild"}},
		{map[string]any{"parentNodeId": "spec.grandchild"}, []string{}},
		{map[string]any{"parentNodeId": "spec.root", "offset": json.Number("1")}, []string{}},
	} {
		response := postWorkspaceJSON(t, handle.URL+"api/v1/navigation", capability, map[string]any{"requestId": "navigation.test", "snapshotId": handle.SnapshotID, "query": item.query})
		projection := response["projection"].(map[string]any)
		assertWorkspaceRowIDs(t, projection["nodes"], "nodeId", item.ids)
		if projection["authority"] != "lookup_fragment_only" || response["snapshotId"] != handle.SnapshotID || response["requestId"] != "navigation.test" {
			t.Fatal("navigation promoted authority or lost session identity")
		}
		if parent, ok := item.query["parentNodeId"]; ok {
			if projection["parent"].(map[string]any)["nodeId"] != parent {
				t.Fatal("navigation page lost its parent context")
			}
		} else if projection["parent"] != nil {
			t.Fatal("root navigation invented a parent")
		}
	}
}

func assertWorkspaceRowIDs(t *testing.T, raw any, key string, expected []string) {
	t.Helper()
	rows, ok := raw.([]any)
	if !ok {
		t.Fatalf("expected row array, got %T", raw)
	}
	actual := make([]string, 0, len(rows))
	for _, raw := range rows {
		actual = append(actual, raw.(map[string]any)[key].(string))
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s order = %v, want %v", key, actual, expected)
	}
}
