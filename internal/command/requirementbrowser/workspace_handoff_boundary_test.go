package requirementbrowser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOneShotHandoffTrustBoundaryRejectsWithoutTerminalCommit(t *testing.T) {
	for _, item := range []struct {
		name        string
		origin      string
		capability  string
		contentType string
	}{
		{name: "missing origin", contentType: "application/json"},
		{name: "foreign origin", origin: "https://attacker.invalid", contentType: "application/json"},
		{name: "missing capability", origin: "expected", contentType: "application/json"},
		{name: "wrong capability", origin: "expected", capability: strings.Repeat("A", 43), contentType: "application/json"},
		{name: "wrong content type", origin: "expected", capability: "expected", contentType: "text/plain"},
	} {
		t.Run(item.name, func(t *testing.T) {
			handle, capability := startWorkspaceTestServer(t, workspaceFixture(t), true)
			origin := item.origin
			if origin == "expected" {
				origin = strings.TrimSuffix(handle.URL, "/")
			}
			providedCapability := item.capability
			if providedCapability == "expected" {
				providedCapability = capability
			}
			request := workspaceHandoffRequest(t, handle.URL, origin, item.contentType, providedCapability)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("rejected handoff status=%d, want forbidden", response.StatusCode)
			}
			valid := postWorkspaceHandoff(t, handle.URL, capability)
			_ = valid.Body.Close()
			if valid.StatusCode != http.StatusOK {
				t.Fatalf("valid handoff after rejection status=%d, want success", valid.StatusCode)
			}
			select {
			case <-handle.Handoff:
			case <-time.After(time.Second):
				t.Fatal("valid handoff did not own the terminal state")
			}
		})
	}
}

func TestOneShotConcurrentHandoffsHaveExactlyOneWinner(t *testing.T) {
	handle, capability := startWorkspaceTestServer(t, workspaceFixture(t), true)
	start := make(chan struct{})
	statuses := make(chan int, 2)
	errors := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			request := workspaceHandoffRequest(t, handle.URL, strings.TrimSuffix(handle.URL, "/"), "application/json", capability)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				errors <- err
				return
			}
			_ = response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	close(start)
	workers.Wait()
	close(statuses)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent handoff statuses=%v, want one success and one conflict", counts)
	}
	select {
	case <-handle.Handoff:
	case <-time.After(time.Second):
		t.Fatal("concurrent handoff winner was not published")
	}
}

func TestTerminalArbiterLinearizesHandoffAgainstTimeout(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		arbiter := newTerminalArbiter()
		start := make(chan struct{})
		results := make(chan bool, 2)
		for _, state := range []string{"submitted", "expired"} {
			state := state
			go func() {
				<-start
				results <- arbiter.TryCommit(map[string]any{"state": state})
			}()
		}
		close(start)
		if first, second := <-results, <-results; first == second {
			t.Fatalf("iteration %d produced %v/%v, want exactly one terminal winner", iteration, first, second)
		}
		if packet := <-arbiter.packets; packet["state"] != "submitted" && packet["state"] != "expired" {
			t.Fatalf("iteration %d published invalid terminal state: %#v", iteration, packet)
		}
	}
}

func TestHandoffSupportsTheAdmittedTreeDepthDomain(t *testing.T) {
	for _, nodeCount := range []int{256, 257, 512} {
		t.Run(fmt.Sprint(nodeCount), func(t *testing.T) {
			workspace, _, err := buildWorkspace(deepWorkspaceFixture(t, nodeCount))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/handoff", strings.NewReader(workspaceHandoffBody))
			packet, err := buildHandoffPacket(request, workspace)
			if err != nil {
				t.Fatalf("handoff rejected admitted tree depth %d: %v", nodeCount, err)
			}
			tree := packet["context"].(map[string]any)["projections"].(map[string]any)["specTree"].(map[string]any)
			if got := len(tree["nodes"].([]any)); got != nodeCount {
				t.Fatalf("handoff tree nodes=%d, want %d", got, nodeCount)
			}
		})
	}
}

func TestHandoffRetainsAncestorClosureAcrossDeepBranches(t *testing.T) {
	workspace, _, err := buildWorkspace(branchedWorkspaceFixture(t, 300))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"annotations":[{"anchorId":"requirement:REQ-CONSUMER-001:invariant","exactQuote":"preserves","startCodePoint":11,"endCodePoint":20,"question":"Does this remain true?"},{"anchorId":"requirement:REQ-CONSUMER-002:invariant","exactQuote":"preserves","startCodePoint":11,"endCodePoint":20,"question":"Does this remain true?"}]}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/handoff", strings.NewReader(body))
	packet, err := buildHandoffPacket(request, workspace)
	if err != nil {
		t.Fatalf("handoff rejected multi-branch ancestor closure: %v", err)
	}
	tree := packet["context"].(map[string]any)["projections"].(map[string]any)["specTree"].(map[string]any)
	if got := len(tree["nodes"].([]any)); got != 601 {
		t.Fatalf("handoff tree nodes=%d, want complete 601-node branch closure", got)
	}
}

func startWorkspaceTestServer(t *testing.T, fixture map[string]any, oneShot bool) (ServerHandle, string) {
	t.Helper()
	mode := "browse"
	if oneShot {
		mode = "one-shot-question"
	}
	handle, err := StartServer(fixture, Options{Host: "127.0.0.1", Port: 0, PortSet: true, SessionMode: mode, View: "workspace"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handle.Close(ctx)
	})
	response, err := http.Get(handle.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	match := capabilityPattern.FindSubmatch(body)
	if len(match) != 2 {
		t.Fatal("workspace capability missing")
	}
	return handle, string(match[1])
}

func postWorkspaceHandoff(t *testing.T, url, capability string) *http.Response {
	t.Helper()
	request := workspaceHandoffRequest(t, url, strings.TrimSuffix(url, "/"), "application/json", capability)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

const workspaceHandoffBody = `{"annotations":[{"anchorId":"requirement:REQ-CONSUMER-001:invariant","exactQuote":"preserves","startCodePoint":11,"endCodePoint":20,"question":"Does this remain true?"}]}`

func workspaceHandoffRequest(t *testing.T, url, origin, contentType, capability string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url+"api/v1/handoff", strings.NewReader(workspaceHandoffBody))
	if err != nil {
		t.Fatal(err)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if capability != "" {
		request.Header.Set("X-Proofkit-Browser-Capability", capability)
	}
	return request
}

func deepWorkspaceFixture(t *testing.T, nodeCount int) map[string]any {
	t.Helper()
	fixture := workspaceFixture(t)
	contextValue := fixture["context"].(map[string]any)
	tree := contextValue["projections"].(map[string]any)["specTree"].(map[string]any)
	nodes := make([]any, nodeCount)
	edges := make([]any, 0, nodeCount-1)
	for index := 0; index < nodeCount; index++ {
		nodeID := fmt.Sprintf("spec.%04d", index)
		role := "overview"
		sourceID := fmt.Sprintf("consumer.overview.%04d", index)
		if index == nodeCount-1 {
			role = "requirements"
			sourceID = "consumer.requirements"
		}
		kind := "module_spec"
		if index == 0 {
			kind = "meta_spec"
		}
		nodes[index] = map[string]any{
			"callerAnnotations": []any{}, "displayOrder": json.Number(fmt.Sprint(index + 1)), "label": nodeID,
			"nodeId": nodeID, "nodeKind": kind, "sourceRefs": []any{map[string]any{
				"sourceId": sourceID, "sourceRefId": nodeID + ".source", "sourceRefKind": "source_id", "sourceRole": role,
			}},
		}
		if index > 0 {
			edges = append(edges, map[string]any{"childNodeId": nodeID, "parentNodeId": fmt.Sprintf("spec.%04d", index-1)})
		}
	}
	tree["rootNodeId"] = "spec.0000"
	tree["nodes"] = nodes
	tree["edges"] = edges
	contextValue["sources"].([]any)[0].(map[string]any)["nodeId"] = fmt.Sprintf("spec.%04d", nodeCount-1)
	resignWorkspaceSnapshot(t, contextValue)
	return fixture
}

func branchedWorkspaceFixture(t *testing.T, branchDepth int) map[string]any {
	t.Helper()
	fixture := workspaceFixture(t)
	contextValue := fixture["context"].(map[string]any)
	projections := contextValue["projections"].(map[string]any)
	firstSource := projections["requirementSources"].([]any)[0].(map[string]any)
	secondSource := map[string]any{
		"schemaVersion":    json.Number("1"),
		"sourceId":         "consumer.requirements.second",
		"specPackagePath":  "docs/specs/consumer-second",
		"overviewPath":     "docs/specs/consumer-second/overview.md",
		"requirementsPath": "docs/specs/consumer-second/requirements.v1.json",
		"nonClaims":        []any{"Consumer source does not approve merge."},
		"requirements": []any{map[string]any{
			"requirementId":    "REQ-CONSUMER-002",
			"ownerId":          "consumer.owner",
			"claimLevel":       "blocking",
			"riskClass":        "high",
			"invariant":        "The system preserves semantic identity.",
			"proofBindingRefs": []any{"proofkit/requirement-bindings.json"},
			"nonClaimRefs":     []any{"NC-CONSUMER-002"},
			"nonClaims":        []any{"This requirement does not approve merge."},
			"lifecycle":        map[string]any{"state": "active", "replacementRequirementIds": []any{}, "evidenceRefs": []any{}},
			"updatePolicy":     map[string]any{"reviewOwnerId": "consumer.owner", "requiresImpactDeclaration": true, "requiresProofBindingReview": true},
		}},
	}
	projections["requirementSources"] = []any{firstSource, secondSource}

	tree := projections["specTree"].(map[string]any)
	nodes := []any{map[string]any{
		"callerAnnotations": []any{}, "displayOrder": json.Number("1"), "label": "Root", "nodeId": "spec.root", "nodeKind": "meta_spec",
		"sourceRefs": []any{map[string]any{"sourceId": "consumer.overview", "sourceRefId": "spec.root.overview", "sourceRefKind": "source_id", "sourceRole": "overview"}},
	}}
	edges := []any{}
	leafIDs := make([]string, 2)
	for branch := 0; branch < 2; branch++ {
		parentID := "spec.root"
		for depth := 1; depth <= branchDepth; depth++ {
			nodeID := fmt.Sprintf("spec.branch-%d.%03d", branch+1, depth)
			displayOrder := branch*branchDepth + depth + 1
			role := "overview"
			sourceID := fmt.Sprintf("consumer.overview.branch-%d.%03d", branch+1, depth)
			if depth == branchDepth {
				role = "requirements"
				if branch == 0 {
					sourceID = "consumer.requirements"
				} else {
					sourceID = "consumer.requirements.second"
				}
				leafIDs[branch] = nodeID
			}
			nodes = append(nodes, map[string]any{
				"callerAnnotations": []any{}, "displayOrder": json.Number(fmt.Sprint(displayOrder)), "label": nodeID, "nodeId": nodeID, "nodeKind": "module_spec",
				"sourceRefs": []any{map[string]any{"sourceId": sourceID, "sourceRefId": nodeID + ".source", "sourceRefKind": "source_id", "sourceRole": role}},
			})
			edges = append(edges, map[string]any{"childNodeId": nodeID, "parentNodeId": parentID})
			parentID = nodeID
		}
	}
	tree["nodes"] = nodes
	tree["edges"] = edges

	rawSources := contextValue["sources"].([]any)
	firstMetadata := rawSources[0].(map[string]any)
	firstMetadata["nodeId"] = leafIDs[0]
	secondMetadata := map[string]any{
		"currentDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"kind":          "requirement_source",
		"nodeId":        leafIDs[1],
		"path":          "docs/specs/consumer-second/requirements.v1.json",
		"sourceRef":     "consumer.requirements.second",
		"sourceRole":    "requirements",
	}
	contextValue["sources"] = []any{firstMetadata, secondMetadata, rawSources[1]}
	resignWorkspaceSnapshot(t, contextValue)
	return fixture
}
