package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestWorkspaceNavigationHTTPAccountsForFullAndRemainderWindows(t *testing.T) {
	fixture := workspaceLookupFixture(t)
	contextValue := fixture["context"].(map[string]any)
	tree := contextValue["projections"].(map[string]any)["specTree"].(map[string]any)
	for index := 129; index >= 0; index-- {
		id := fmt.Sprintf("spec.sibling-%03d", index)
		tree["nodes"] = append(tree["nodes"].([]any), map[string]any{
			"nodeId": id, "label": "Independent sibling", "nodeKind": "module_spec",
			"displayOrder": json.Number(fmt.Sprint(index + 100)), "callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{"sourceRefId": id + ".requirements", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "consumer.a"}},
		})
		tree["edges"] = append(tree["edges"].([]any), map[string]any{"parentNodeId": "spec.root", "childNodeId": id})
	}
	resignWorkspaceSnapshot(t, contextValue)
	handle, capability := startWorkspaceTestServer(t, fixture, false)
	first := []string{"spec.child"}
	for index := 0; index < 127; index++ {
		first = append(first, fmt.Sprintf("spec.sibling-%03d", index))
	}
	for _, item := range []struct {
		name      string
		query     map[string]any
		ids       []string
		available int
		selected  int
		omitted   int
		state     string
	}{
		{"root", map[string]any{}, []string{"spec.root"}, 1, 1, 0, "complete"},
		{"full window", map[string]any{"parentNodeId": "spec.root", "maxRecords": json.Number("128")}, first, 131, 128, 3, "partial_with_omissions"},
		{"remainder", map[string]any{"parentNodeId": "spec.root", "maxRecords": json.Number("128"), "offset": json.Number("128")}, []string{"spec.sibling-127", "spec.sibling-128", "spec.sibling-129"}, 131, 3, 128, "partial_with_omissions"},
		{"offset at end", map[string]any{"parentNodeId": "spec.root", "offset": json.Number("131")}, []string{}, 131, 0, 131, "partial_with_omissions"},
		{"leaf", map[string]any{"parentNodeId": "spec.sibling-000"}, []string{}, 0, 0, 0, "complete"},
	} {
		t.Run(item.name, func(t *testing.T) {
			response := postWorkspaceJSON(t, handle.URL+"api/v1/navigation", capability, map[string]any{"requestId": "navigation.capacity", "snapshotId": handle.SnapshotID, "query": item.query})
			projection := response["projection"].(map[string]any)
			assertWorkspaceRowIDs(t, projection["nodes"], "nodeId", item.ids)
			for field, expected := range map[string]int{"availableNodeCount": item.available, "selectedNodeCount": item.selected, "omittedNodeCount": item.omitted} {
				if projection[field] != json.Number(fmt.Sprint(expected)) {
					t.Fatalf("navigation %s = %v, want %d", field, projection[field], expected)
				}
			}
			if response["state"] != item.state || response["requestId"] != "navigation.capacity" || response["snapshotId"] != handle.SnapshotID {
				t.Fatal("navigation response lost exact completion state or request identity")
			}
		})
	}
}

func TestWorkspaceLookupHTTPEnforcesExpandedWireBudget(t *testing.T) {
	const wireLimit = 16 << 20
	const boundaryBytes = 1 << 20
	boundary := strings.Repeat("x", boundaryBytes)
	fixture := workspaceLookupFixture(t)
	contextValue := fixture["context"].(map[string]any)
	source := contextValue["projections"].(map[string]any)["requirementSources"].([]any)[1].(map[string]any)
	source["nonClaims"] = []any{boundary}
	resignWorkspaceSnapshot(t, contextValue)
	if len(stableWorkspaceBytes(t, contextValue)) >= 8<<20 {
		t.Fatal("wire expansion fixture must fit the independently admitted snapshot input cap")
	}
	handle, capability := startWorkspaceTestServer(t, fixture, false)
	// Fifteen 1 MiB source notices fit, but sixteen plus metadata cannot fit.
	// The second request uses the actual first-page cardinality, not its limit.
	offset := 0
	for page := 0; page < 2; page++ {
		query := map[string]any{"nodeId": "spec.child", "maxRecords": json.Number("128"), "offset": json.Number(fmt.Sprint(offset))}
		request, err := http.NewRequest(http.MethodPost, handle.URL+"api/v1/requirements", bytes.NewReader(stableWorkspaceBytes(t, map[string]any{"requestId": "lookup.capacity", "snapshotId": handle.SnapshotID, "query": query})))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", strings.TrimSuffix(handle.URL, "/"))
		request.Header.Set("X-Proofkit-Browser-Capability", capability)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, wireLimit+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read expanded HTTP response: %v; close: %v", readErr, closeErr)
		}
		if response.StatusCode != http.StatusOK || len(body) > wireLimit || len(body) <= 15*boundaryBytes {
			t.Fatalf("expanded HTTP response status=%d bytes=%d, want 200 with 15 MiB < bytes <= 16 MiB", response.StatusCode, len(body))
		}
		decoded, err := admission.DecodeJSON(bytes.NewReader(body), wireLimit)
		if err != nil {
			t.Fatal(err)
		}
		record := decoded.(map[string]any)
		projection := record["projection"].(map[string]any)
		rows := projection["requirements"].([]any)
		ids := make([]string, 15)
		for index := range ids {
			ids[index] = fmt.Sprintf("REQ-B-%03d", offset+index)
		}
		assertWorkspaceRowIDs(t, rows, "requirementId", ids)
		for index, raw := range rows {
			row := raw.(map[string]any)
			anchor := row["anchor"].(map[string]any)
			if anchor["jsonPointer"] != fmt.Sprintf("/projections/requirementSources/1/requirements/%d/invariant", offset+index) || anchor["sourceDigest"] != digest.SHA256TextRef("source-b") {
				t.Fatal("byte-limited HTTP page rebased an original source anchor")
			}
			claims := row["sourceNonClaims"].([]any)
			if len(claims) != 1 || claims[0] != boundary {
				t.Fatal("byte-limited HTTP page truncated its admitted source notice")
			}
		}
		for field, expected := range map[string]int{"availableRequirementCount": 132, "matchingRequirementCount": 131, "selectedRequirementCount": 15, "filteredOutRequirementCount": 1, "pageOmittedRequirementCount": 116, "omittedRequirementCount": 117} {
			if projection[field] != json.Number(fmt.Sprint(expected)) {
				t.Fatalf("byte-limited HTTP %s = %v, want %d", field, projection[field], expected)
			}
		}
		if record["state"] != "partial_with_omissions" || record["requestId"] != "lookup.capacity" || record["snapshotId"] != handle.SnapshotID {
			t.Fatal("byte-limited HTTP page lost completion state or request identity")
		}
		offset += len(rows)
	}
}
