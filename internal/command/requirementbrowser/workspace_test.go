package requirementbrowser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var capabilityPattern = regexp.MustCompile(`name="proofkit-browser-capability" content="([A-Za-z0-9_-]{43})"`)

func TestWorkspaceServerEnforcesCapabilityAndBuildsSourceBoundHandoff(t *testing.T) {
	handle, err := StartServer(workspaceFixture(t), Options{Host: "127.0.0.1", Port: 0, PortSet: true, View: "workspace"})
	if err != nil {
		t.Fatalf("StartServer() error = %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handle.Close(ctx)
	}()
	indexResponse, err := http.Get(handle.URL)
	if err != nil {
		t.Fatalf("GET workspace: %v", err)
	}
	indexBody, _ := io.ReadAll(indexResponse.Body)
	_ = indexResponse.Body.Close()
	if indexResponse.StatusCode != http.StatusOK || !strings.Contains(indexResponse.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("workspace security response status=%d headers=%v", indexResponse.StatusCode, indexResponse.Header)
	}
	match := capabilityPattern.FindSubmatch(indexBody)
	if len(match) != 2 {
		t.Fatalf("workspace capability missing from shell")
	}
	capability := string(match[1])
	unauthorized, _ := http.Get(handle.URL + "api/v1/manifest")
	if unauthorized.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized session status=%d", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()
	sessionRequest, _ := http.NewRequest(http.MethodGet, handle.URL+"api/v1/manifest", nil)
	sessionRequest.Header.Set("X-Proofkit-Browser-Capability", capability)
	sessionResponse, err := http.DefaultClient.Do(sessionRequest)
	if err != nil {
		t.Fatal(err)
	}
	if sessionResponse.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d", sessionResponse.StatusCode)
	}
	manifestBody, _ := io.ReadAll(sessionResponse.Body)
	_ = sessionResponse.Body.Close()
	manifestValue, err := admission.DecodeJSON(bytes.NewReader(manifestBody), int64(len(manifestBody)))
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestValue.(map[string]any)
	if manifest["expectedDigestCoverage"] != "none" || manifest["snapshotId"] != handle.SnapshotID {
		t.Fatalf("workspace manifest lost digest-coverage identity: %#v", manifest)
	}
	handoff := `{"annotations":[{"anchorId":"requirement:REQ-CONSUMER-001:invariant","exactQuote":"preserves","startCodePoint":11,"endCodePoint":20,"question":"Does this remain true?"}]}`
	handoffRequest, _ := http.NewRequest(http.MethodPost, handle.URL+"api/v1/handoff", strings.NewReader(handoff))
	handoffRequest.Header.Set("Origin", strings.TrimSuffix(handle.URL, "/"))
	handoffRequest.Header.Set("Content-Type", "application/json")
	handoffRequest.Header.Set("X-Proofkit-Browser-Capability", capability)
	handoffResponse, err := http.DefaultClient.Do(handoffRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(handoffResponse.Body)
	_ = handoffResponse.Body.Close()
	if handoffResponse.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"handoffKind": "proofkit.requirement-browser-question"`)) {
		t.Fatalf("handoff status=%d body=%s", handoffResponse.StatusCode, body)
	}
	packet, err := admission.DecodeJSON(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	packetRecord := packet.(map[string]any)
	annotation := packetRecord["annotations"].([]any)[0].(map[string]any)
	anchor := annotation["anchor"].(map[string]any)
	if anchor["jsonPointer"] != "/projections/requirementSources/0/requirements/0/invariant" || anchor["sourceDigest"] != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || packetRecord["snapshotRefs"].([]any)[0].(map[string]any)["snapshotId"] != handle.SnapshotID {
		t.Fatalf("handoff lost source identity: %#v", packetRecord)
	}
	spaceQuote := `{"annotations":[{"anchorId":"requirement:REQ-CONSUMER-001:invariant","exactQuote":" system","startCodePoint":3,"endCodePoint":10,"question":"Does whitespace remain source-bound?"}]}`
	spaceRequest, _ := http.NewRequest(http.MethodPost, handle.URL+"api/v1/handoff", strings.NewReader(spaceQuote))
	spaceRequest.Header.Set("Origin", strings.TrimSuffix(handle.URL, "/"))
	spaceRequest.Header.Set("Content-Type", "application/json")
	spaceRequest.Header.Set("X-Proofkit-Browser-Capability", capability)
	spaceResponse, err := http.DefaultClient.Do(spaceRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer spaceResponse.Body.Close()
	if spaceResponse.StatusCode != http.StatusOK {
		t.Fatalf("source-exact whitespace quote status=%d", spaceResponse.StatusCode)
	}
}

func TestV2DigestCoverageProjections(t *testing.T) {
	fixture := workspaceFixture(t)
	current := fixture["context"].(map[string]any)
	base := cloneWorkspaceRecord(t, current)
	base["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)["invariant"] = "The system preserved the previous semantic identity."
	resignWorkspaceSnapshot(t, base)
	fixture["diffInput"] = map[string]any{"baseContext": base, "currentContext": current, "diffId": "consumer.workspace.digest-coverage", "schemaVersion": json.Number("2")}
	fixture["graphInput"] = map[string]any{"context": current, "graphId": "consumer.workspace.digest-coverage", "schemaVersion": json.Number("2")}

	handle, capability := startWorkspaceTestServer(t, fixture, false)
	manifest := getWorkspaceJSON(t, handle.URL+"api/v1/manifest", capability)
	if manifest["schemaVersion"] != json.Number("2") || manifest["expectedDigestCoverage"] != "none" || manifest["baselineVerification"] != nil {
		t.Fatalf("workspace manifest is not a clean v2 projection: %#v", manifest)
	}
	for _, path := range []string{"requirements", "diff", "graph"} {
		response := postWorkspaceJSON(t, handle.URL+"api/v1/"+path, capability, map[string]any{
			"query": map[string]any{}, "requestId": "consumer.workspace." + path, "snapshotId": handle.SnapshotID,
		})
		if response["schemaVersion"] != json.Number("2") {
			t.Fatalf("%s response schemaVersion = %v, want 2", path, response["schemaVersion"])
		}
		if path == "diff" {
			projection := response["projection"].(map[string]any)
			if projection["baseExpectedDigestCoverage"] != "none" || projection["currentExpectedDigestCoverage"] != "none" || projection["baseBaselineVerification"] != nil || projection["currentBaselineVerification"] != nil {
				t.Fatalf("diff API projection is not clean v2: %#v", projection)
			}
		}
	}

	v2Minimal := workspaceFixture(t)
	v1Minimal := cloneWorkspaceRecord(t, v2Minimal)
	v1Minimal["schemaVersion"] = json.Number("1")
	v1Context := v1Minimal["context"].(map[string]any)
	delete(v1Context, "expectedDigestCoverage")
	v1Context["baselineVerification"] = "unverified"
	v1Context["nonClaims"] = []any{
		"Requirement context is a derived projection and is not requirement, proof, coverage, merge, release, rollout, or readiness authority.",
		"Requirement context does not execute native witnesses or prove source freshness after composition.",
	}
	v1Context["schemaVersion"] = json.Number("1")
	v1Session, _, err := buildWorkspace(v1Minimal)
	if err != nil {
		t.Fatalf("buildWorkspace(v1) error = %v", err)
	}
	v2Session, _, err := buildWorkspace(v2Minimal)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stableWorkspaceBytes(t, v1Session.Manifest), stableWorkspaceBytes(t, v2Session.Manifest); !bytes.Equal(got, want) {
		t.Fatalf("v1 workspace normalized to a different v2 manifest\n got: %s\nwant: %s", got, want)
	}
	v1Minimal["context"] = current
	if _, _, err := buildWorkspace(v1Minimal); err == nil {
		t.Fatal("buildWorkspace accepted a v1 envelope with a v2 context")
	}
}

func getWorkspaceJSON(t *testing.T, url, capability string) map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Proofkit-Browser-Capability", capability)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return decodeWorkspaceResponse(t, response)
}

func postWorkspaceJSON(t *testing.T, url, capability string, value any) map[string]any {
	t.Helper()
	body := stableWorkspaceBytes(t, value)
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", strings.Split(url, "/api/")[0])
	request.Header.Set("X-Proofkit-Browser-Capability", capability)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return decodeWorkspaceResponse(t, response)
}

func decodeWorkspaceResponse(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("workspace response status=%d body=%s", response.StatusCode, body)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func cloneWorkspaceRecord(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	decoded, err := admission.DecodeJSON(bytes.NewReader(stableWorkspaceBytes(t, value)), 24<<20)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func stableWorkspaceBytes(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestWorkspaceAssetsHaveExactSecureHTTPContract(t *testing.T) {
	handle, err := StartServer(workspaceFixture(t), Options{Host: "127.0.0.1", Port: 0, PortSet: true, View: "workspace"})
	if err != nil {
		t.Fatalf("StartServer() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close(t.Context()) })
	client := http.Client{Timeout: 5 * time.Second}
	for _, item := range []struct {
		method      string
		path        string
		wantAllow   string
		wantBody    []byte
		wantType    string
		wantStatus  int
		wantSuccess bool
	}{
		{method: http.MethodGet, path: "assets/workspace.js", wantBody: workspaceJavaScript, wantType: "text/javascript; charset=utf-8", wantStatus: http.StatusOK, wantSuccess: true},
		{method: http.MethodHead, path: "assets/workspace.js", wantBody: []byte{}, wantType: "text/javascript; charset=utf-8", wantStatus: http.StatusOK, wantSuccess: true},
		{method: http.MethodPost, path: "assets/workspace.js", wantAllow: "GET, HEAD", wantBody: []byte("method not allowed\n"), wantStatus: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "assets/workspace.js/", wantBody: []byte("not found\n"), wantStatus: http.StatusNotFound},
		{method: http.MethodGet, path: "assets/selection-authority.js", wantBody: selectionAuthorityJavaScript, wantType: "text/javascript; charset=utf-8", wantStatus: http.StatusOK, wantSuccess: true},
		{method: http.MethodHead, path: "assets/selection-authority.js", wantBody: []byte{}, wantType: "text/javascript; charset=utf-8", wantStatus: http.StatusOK, wantSuccess: true},
		{method: http.MethodPost, path: "assets/selection-authority.js", wantAllow: "GET, HEAD", wantBody: []byte("method not allowed\n"), wantStatus: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "assets/selection-authority.js/", wantBody: []byte("not found\n"), wantStatus: http.StatusNotFound},
		{method: http.MethodGet, path: "assets/workspace.css", wantBody: workspaceCSS, wantType: "text/css; charset=utf-8", wantStatus: http.StatusOK, wantSuccess: true},
		{method: http.MethodHead, path: "assets/workspace.css", wantBody: []byte{}, wantType: "text/css; charset=utf-8", wantStatus: http.StatusOK, wantSuccess: true},
		{method: http.MethodPost, path: "assets/workspace.css", wantAllow: "GET, HEAD", wantBody: []byte("method not allowed\n"), wantStatus: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "assets/workspace.css/", wantBody: []byte("not found\n"), wantStatus: http.StatusNotFound},
	} {
		t.Run(item.method+" "+item.path, func(t *testing.T) {
			request, err := http.NewRequest(item.method, handle.URL+item.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != item.wantStatus || !bytes.Equal(body, item.wantBody) || response.Header.Get("allow") != item.wantAllow {
				t.Fatalf("asset response status=%d allow=%q body=%q", response.StatusCode, response.Header.Get("allow"), body)
			}
			if item.wantSuccess {
				assertWorkspaceAssetSecurityHeaders(t, response.Header, item.wantType)
			}
		})
	}
}

func assertWorkspaceAssetSecurityHeaders(t *testing.T, header http.Header, contentType string) {
	t.Helper()
	want := map[string]string{
		"cache-control":                "no-store",
		"content-security-policy":      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
		"content-type":                 contentType,
		"cross-origin-opener-policy":   "same-origin",
		"cross-origin-resource-policy": "same-origin",
		"permissions-policy":           "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
		"referrer-policy":              "no-referrer",
		"x-content-type-options":       "nosniff",
	}
	for name, value := range want {
		if header.Get(name) != value {
			t.Fatalf("header %s = %q, want %q", name, header.Get(name), value)
		}
	}
}

func TestWorkspaceDefaultUsesFreshEphemeralOrigin(t *testing.T) {
	first, err := StartServer(workspaceFixture(t), Options{Host: "127.0.0.1", View: "workspace"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := StartServer(workspaceFixture(t), Options{Host: "127.0.0.1", View: "workspace"})
	if err != nil {
		_ = first.Close(t.Context())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close(t.Context())
		_ = second.Close(t.Context())
	})
	if first.Port == 0 || second.Port == 0 || first.Port == second.Port {
		t.Fatalf("default browser origins are not fresh: first=%s second=%s", first.URL, second.URL)
	}
}

func TestWorkspaceRejectsGraphInputForAnotherContext(t *testing.T) {
	fixture := workspaceFixture(t)
	encoded, err := stablejson.Marshal(fixture["context"])
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	otherContext := decoded.(map[string]any)
	otherContext["catalogId"] = "consumer.other-context"
	resignWorkspaceSnapshot(t, otherContext)
	fixture["graphInput"] = map[string]any{"context": otherContext, "graphId": "consumer.workspace.graph", "schemaVersion": json.Number("2")}
	if _, _, err := buildWorkspace(fixture); err == nil {
		t.Fatal("buildWorkspace accepted graph input for a different context")
	}
}

func TestWorkspaceAdmitsMultiFieldSemanticDiffFromProducer(t *testing.T) {
	fixture := workspaceFixture(t)
	current := fixture["context"].(map[string]any)
	encoded, err := stablejson.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	base := decoded.(map[string]any)
	requirement := base["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	requirement["invariant"] = "The system preserved the previous semantic identity."
	requirement["riskClass"] = "medium"
	resignWorkspaceSnapshot(t, base)
	fixture["diffInput"] = map[string]any{"baseContext": base, "currentContext": current, "diffId": "consumer.workspace.diff", "schemaVersion": json.Number("2")}

	workspace, _, err := buildWorkspace(fixture)
	if err != nil {
		t.Fatalf("workspace rejected producer-owned multi-field diff: %v", err)
	}
	if len(workspace.Diff["changes"].([]any)) != 2 {
		t.Fatalf("workspace diff = %#v, want two changes", workspace.Diff)
	}
}

func TestOneShotTerminalStateIsLinearizedAfterWinnerIsDrained(t *testing.T) {
	handle, capability := startWorkspaceTestServer(t, workspaceFixture(t), true)
	first := postWorkspaceHandoff(t, handle.URL, capability)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first handoff status=%d", first.StatusCode)
	}
	_ = first.Body.Close()
	<-handle.Handoff
	second := postWorkspaceHandoff(t, handle.URL, capability)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second handoff status=%d, want conflict", second.StatusCode)
	}
	_ = second.Body.Close()
}

func TestWorkspaceHandoffRetainsLifecycleReplacementClosure(t *testing.T) {
	fixture := workspaceFixture(t)
	contextValue := fixture["context"].(map[string]any)
	source := contextValue["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
	requirements := source["requirements"].([]any)
	first := requirements[0].(map[string]any)
	first["claimLevel"] = "advisory"
	first["lifecycle"] = map[string]any{"state": "superseded", "replacementRequirementIds": []any{"REQ-CONSUMER-002"}, "evidenceRefs": []any{"consumer.lifecycle.migration"}}
	second := map[string]any{"requirementId": "REQ-CONSUMER-002", "ownerId": "consumer.owner", "claimLevel": "blocking", "riskClass": "high", "invariant": "The replacement preserves semantic identity.", "proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "nonClaimRefs": []any{"NC-CONSUMER-002"}, "nonClaims": []any{"This replacement requirement does not approve merge."}, "lifecycle": map[string]any{"state": "active", "replacementRequirementIds": []any{}, "evidenceRefs": []any{}}, "updatePolicy": map[string]any{"reviewOwnerId": "consumer.owner", "requiresImpactDeclaration": true, "requiresProofBindingReview": true}}
	source["requirements"] = append(requirements, second)
	resignWorkspaceSnapshot(t, contextValue)
	handle, capability := startWorkspaceTestServer(t, fixture, false)
	response := postWorkspaceHandoff(t, handle.URL, capability)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("handoff status=%d body=%s", response.StatusCode, body)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	contextSlice := decoded.(map[string]any)["context"].(map[string]any)
	selected := contextSlice["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)
	if len(selected) != 2 {
		t.Fatalf("handoff lifecycle closure=%#v, want selected requirement plus replacement", selected)
	}
}

func TestWorkspaceCapabilityReplacementIsConfinedToBootstrapMeta(t *testing.T) {
	fixture := workspaceFixture(t)
	fixture["workspaceId"] = workspaceCapabilityPlaceholder
	handle, capability := startWorkspaceTestServer(t, fixture, false)
	response, err := http.Get(handle.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	text := string(body)
	if strings.Count(text, capability) != 1 || !strings.Contains(text, "<h1>"+workspaceCapabilityPlaceholder+"</h1>") {
		t.Fatalf("capability replacement escaped bootstrap boundary: %s", text)
	}
}

func TestOneShotOutputVariantsUseExactRootShapes(t *testing.T) {
	var terminalStdout bytes.Buffer
	err := Serve(t.Context(), workspaceFixture(t), Options{Host: "127.0.0.1", Port: 0, PortSet: true, SessionMode: "one-shot-question", SessionTimeout: 10 * time.Millisecond, View: "workspace"}, &terminalStdout)
	if !errors.Is(err, ErrOneShotTerminal) {
		t.Fatalf("Serve() error = %v, want terminal state", err)
	}
	if strings.Count(terminalStdout.String(), "\n") != 1 || strings.Contains(terminalStdout.String(), "\n  ") {
		t.Fatalf("unexpected one-shot terminal packet layout: %q", terminalStdout.String())
	}
	terminalValue, err := admission.DecodeJSON(bytes.NewReader(terminalStdout.Bytes()), int64(terminalStdout.Len()))
	if err != nil {
		t.Fatal(err)
	}
	terminal := terminalValue.(map[string]any)
	assertExactRootKeys(t, terminal, "handoffKind", "nonClaims", "schemaVersion", "snapshotRefs", "state")
	if terminal["state"] != "expired" {
		t.Fatalf("terminal state=%v, want expired", terminal["state"])
	}

	handle, capability := startWorkspaceTestServer(t, workspaceFixture(t), true)
	var submittedStdout bytes.Buffer
	result := make(chan error, 1)
	go func() {
		result <- serveHandle(t.Context(), handle, Options{SessionMode: "one-shot-question"}, &submittedStdout)
	}()
	response := postWorkspaceHandoff(t, handle.URL, capability)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("handoff status=%d body=%s", response.StatusCode, body)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serveHandle() submitted error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveHandle did not emit submitted packet")
	}
	submittedValue, err := admission.DecodeJSON(bytes.NewReader(submittedStdout.Bytes()), int64(submittedStdout.Len()))
	if err != nil {
		t.Fatal(err)
	}
	submitted := submittedValue.(map[string]any)
	assertExactRootKeys(t, submitted, "annotations", "context", "handoffKind", "instructionAuthority", "nonClaims", "schemaVersion", "snapshotRefs", "sourceTextAuthority", "state")
	if submitted["state"] != "submitted" {
		t.Fatalf("submitted state=%v, want submitted", submitted["state"])
	}
}

func assertExactRootKeys(t *testing.T, record map[string]any, keys ...string) {
	t.Helper()
	if len(record) != len(keys) {
		t.Fatalf("root keys=%v, want exactly %v", record, keys)
	}
	for _, key := range keys {
		if _, ok := record[key]; !ok {
			t.Fatalf("root is missing %s: %#v", key, record)
		}
	}
}

func TestGraphWindowRetainsCrossPageRelationsWithEndpointClosure(t *testing.T) {
	nodes := make([]any, 257)
	for index := range nodes {
		nodes[index] = map[string]any{"nodeId": fmt.Sprintf("node.%03d", index)}
	}
	edge := map[string]any{"edgeId": "edge.cross-page", "fromNodeId": "node.255", "toNodeId": "node.256"}
	fragment, state := graphWindow(map[string]any{"edges": []any{edge}, "graphId": "consumer.graph", "nodes": nodes}, projectionQuery{MaxEdges: 10, MaxRecords: 256})
	if state != "complete" || fragment["selectedEdgeCount"] != 1 || fragment["primaryNodeCount"] != 256 || fragment["boundaryNodeCount"] != 1 {
		t.Fatalf("cross-page graph fragment lost relation closure: %#v", fragment)
	}
	selected := fragment["nodes"].([]any)
	if selected[len(selected)-1].(map[string]any)["nodeId"] != "node.256" {
		t.Fatalf("cross-page endpoint missing: %#v", selected[len(selected)-1])
	}
	if fragment["availableNodeCount"] != fragment["selectedNodeCount"].(int)+fragment["omittedNodeCount"].(int) || fragment["omittedNodeCount"] != 0 || fragment["omittedPrimaryNodeCount"] != 1 {
		t.Fatalf("graph node accounting is not set-consistent: %#v", fragment)
	}
}

func TestRequirementWindowMakesEveryBoundedPageReachable(t *testing.T) {
	requirements := make([]any, 257)
	for index := range requirements {
		requirements[index] = map[string]any{"requirementId": fmt.Sprintf("REQ-%03d", index)}
	}
	first, firstState := requirementWindow(requirements, projectionQuery{MaxRecords: 256})
	second, secondState := requirementWindow(requirements, projectionQuery{MaxRecords: 256, Offset: 256})
	if firstState != "partial_with_omissions" || first["selectedRequirementCount"] != 256 || secondState != "partial_with_omissions" || second["selectedRequirementCount"] != 1 {
		t.Fatalf("requirement pagination is not omission-honest: first=%#v second=%#v", first, second)
	}
	last := second["requirements"].([]any)[0].(map[string]any)["requirementId"]
	if last != "REQ-256" {
		t.Fatalf("last requirement is unreachable: %v", last)
	}
}

func workspaceFixture(t *testing.T) map[string]any {
	return workspaceFixtureWithInvariant(t, "The system preserves semantic identity. "+strings.Repeat("x", maxHandoffAnnotations+1))
}

func workspaceFixtureWithInvariant(t *testing.T, invariant string) map[string]any {
	t.Helper()
	projections := map[string]any{
		"requirementSources": []any{map[string]any{
			"schemaVersion":    json.Number("1"),
			"sourceId":         "consumer.requirements",
			"specPackagePath":  "docs/specs/consumer",
			"overviewPath":     "docs/specs/consumer/overview.md",
			"requirementsPath": "docs/specs/consumer/requirements.v1.json",
			"nonClaims":        []any{"Consumer source does not approve merge."},
			"requirements": []any{map[string]any{
				"requirementId":    "REQ-CONSUMER-001",
				"ownerId":          "consumer.owner",
				"claimLevel":       "blocking",
				"riskClass":        "high",
				"invariant":        invariant,
				"proofBindingRefs": []any{"proofkit/requirement-bindings.json"},
				"nonClaimRefs":     []any{"NC-CONSUMER-001"},
				"nonClaims":        []any{"This requirement does not approve merge."},
				"lifecycle":        map[string]any{"state": "active", "replacementRequirementIds": []any{}, "evidenceRefs": []any{}},
				"updatePolicy":     map[string]any{"reviewOwnerId": "consumer.owner", "requiresImpactDeclaration": true, "requiresProofBindingReview": true},
			}},
		}},
		"specTree": map[string]any{"schemaVersion": json.Number("2"), "treeId": "consumer.spec-tree", "rootNodeId": "spec.root", "callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{}, "nodes": []any{map[string]any{"nodeId": "spec.root", "nodeKind": "meta_spec", "label": "Root", "displayOrder": json.Number("1"), "callerAnnotations": []any{}, "sourceRefs": []any{map[string]any{"sourceRefId": "spec.root.requirements", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "consumer.requirements"}}}}},
	}
	sources := []requirementcontext.Source{{CurrentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: "requirement_source", NodeID: "spec.root", Path: "docs/specs/consumer/requirements.v1.json", SourceRef: "consumer.requirements", SourceRole: "requirements"}, {CurrentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Kind: "spec_tree", Path: "proofkit/spec-tree.json", SourceRef: "spec_tree:consumer.spec-tree"}}
	identity := map[string]any{"catalogId": "consumer.context", "projections": projections, "sources": []any{map[string]any{"currentDigest": sources[0].CurrentDigest, "expectedDigest": "", "kind": sources[0].Kind, "nodeId": sources[0].NodeID, "path": sources[0].Path, "sourceRef": sources[0].SourceRef, "sourceRole": sources[0].SourceRole}, map[string]any{"currentDigest": sources[1].CurrentDigest, "expectedDigest": "", "kind": sources[1].Kind, "path": sources[1].Path, "sourceRef": sources[1].SourceRef}}}
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	contextValue := requirementcontext.SnapshotValue(requirementcontext.Snapshot{CatalogID: "consumer.context", ExpectedDigestCoverage: "none", Projections: projections, SnapshotID: digest.SHA256TextRef(string(encoded)), Sources: sources})
	return map[string]any{"schemaVersion": json.Number("2"), "workspaceId": "consumer.workspace", "context": contextValue}
}

func resignWorkspaceSnapshot(t *testing.T, contextValue map[string]any) {
	t.Helper()
	projections := contextValue["projections"].(map[string]any)
	canonicalSources := make([]any, 0, len(projections["requirementSources"].([]any)))
	for _, raw := range projections["requirementSources"].([]any) {
		result, err := requirementsourceadmission.Evaluate(raw)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("canonicalize requirement source: exit=%d err=%v failures=%v", result.ExitCode, err, result.Failures)
		}
		canonicalSources = append(canonicalSources, requirementsourceadmission.SourceValue(result.Source))
	}
	projections["requirementSources"] = canonicalSources
	treeResult, err := requirementspectree.Evaluate(projections["specTree"])
	if err != nil || treeResult.ExitCode != 0 {
		t.Fatalf("canonicalize specification tree: exit=%d err=%v report=%#v", treeResult.ExitCode, err, treeResult.Report)
	}
	projections["specTree"] = requirementspectree.TreeValue(treeResult.Tree)
	rawSources := contextValue["sources"].([]any)
	identitySources := make([]any, 0, len(rawSources))
	for _, raw := range rawSources {
		source := raw.(map[string]any)
		identity := map[string]any{"currentDigest": source["currentDigest"], "expectedDigest": "", "kind": source["kind"], "path": source["path"], "sourceRef": source["sourceRef"]}
		for _, key := range []string{"expectedDigest", "nodeId", "sourceRole"} {
			if source[key] != nil {
				identity[key] = source[key]
			}
		}
		identitySources = append(identitySources, identity)
	}
	encoded, err := stablejson.Marshal(map[string]any{"catalogId": contextValue["catalogId"], "projections": projections, "sources": identitySources})
	if err != nil {
		t.Fatal(err)
	}
	contextValue["snapshotId"] = digest.SHA256TextRef(string(encoded))
}
