package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestWorkspaceLookupQueryAdmitsExactTextBoundsBeforeIndexUse(t *testing.T) {
	for _, text := range []string{"", " \t\n", strings.Repeat("x", 256), strings.Repeat("\U0001f9ed", 256)} {
		if _, err := admitWorkspaceLookupQuery(map[string]any{"searchText": text}, workspaceLookupIndex{}); err != nil {
			t.Fatalf("valid boundary text rejected: %v", err)
		}
	}
	for _, raw := range []any{nil, true, json.Number("1"), strings.Repeat("x", 257), strings.Repeat("\U0001f9ed", 257), string([]byte{0xff})} {
		if _, err := admitWorkspaceLookupQuery(map[string]any{"searchText": raw}, workspaceLookupIndex{}); err == nil {
			t.Fatal("invalid text type, encoding or bound was admitted")
		}
	}
}

func TestWorkspaceLookupAdmissionRejectsWithoutDisclosureOrSessionMutation(t *testing.T) {
	handle, capability := startWorkspaceTestServer(t, workspaceLookupFixture(t), false)
	sentinel := "api_key=" + strings.Repeat("a", 40)
	for _, item := range []struct {
		path  string
		query map[string]any
	}{
		{"requirements", map[string]any{"searchText": sentinel}},
		{"requirements", map[string]any{sentinel: true}},
		{"requirements", map[string]any{"nodeId": "spec.unknown"}},
		{"requirements", map[string]any{"nodeId": nil}},
		{"requirements", map[string]any{"ownerId": "owner.unknown"}},
		{"requirements", map[string]any{"ownerId": nil}},
		{"requirements", map[string]any{"lifecycleState": "invented"}},
		{"requirements", map[string]any{"lifecycleState": nil}},
		{"navigation", map[string]any{"parentNodeId": "spec.unknown"}},
		{"navigation", map[string]any{"parentNodeId": nil}},
		{"navigation", map[string]any{"maxRecords": json.Number("129")}},
		{"navigation", map[string]any{"maxRecords": nil}},
		{"navigation", map[string]any{"offset": json.Number("-1")}},
	} {
		body := stableWorkspaceBytes(t, map[string]any{"requestId": "query.rejected", "snapshotId": handle.SnapshotID, "query": item.query})
		request, err := http.NewRequest(http.MethodPost, handle.URL+"api/v1/"+item.path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", strings.TrimSuffix(handle.URL, "/"))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Proofkit-Browser-Capability", capability)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		output, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusBadRequest || string(output) != "request rejected\n" || bytes.Contains(output, []byte(sentinel)) {
			t.Fatal("rejected query escaped its fixed nondisclosing error contract")
		}
	}
	valid := postWorkspaceJSON(t, handle.URL+"api/v1/requirements", capability, map[string]any{"requestId": "query.valid", "snapshotId": handle.SnapshotID, "query": map[string]any{"searchText": "REQ-C"}})
	assertWorkspaceRowIDs(t, valid["projection"].(map[string]any)["requirements"], "requirementId", []string{"REQ-C"})
	manifest := getWorkspaceJSON(t, handle.URL+"api/v1/manifest", capability)
	facets := manifest["lookupFacets"].(map[string]any)
	if got := facets["ownerIds"].([]any); len(got) != 3 || got[0] != "owner.a" || got[1] != "owner.b" || got[2] != "owner.c" {
		t.Fatal("owner facets were derived from the current page rather than the full cohort")
	}
	if got := facets["lifecycleStates"].([]any); len(got) != 2 || got[0] != "active" || got[1] != "superseded" {
		t.Fatal("lifecycle facets differ from source-owned states in the admitted cohort")
	}
}
