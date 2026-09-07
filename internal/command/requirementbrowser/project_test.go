package requirementbrowser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/projectfixture"
)

// Bound a stuck test after both cleanup phases, not the product's response latency.
const projectShutdownWatchdog = 2*serverShutdownTimeout + time.Second

func TestProjectBrowserCapturesAndHandsOffExactSourceFacts(t *testing.T) {
	for _, selected := range []int{1, 2} {
		t.Run(fmt.Sprint(selected), func(t *testing.T) {
			fixture := projectfixture.New(t)
			if err := os.WriteFile(filepath.Join(fixture.Root, "initial-unlisted.json"), []byte("invalid ambient input"), 0o600); err != nil {
				t.Fatal(err)
			}
			plan, exit, err := BuildProjectPlan(t.Context(), fixture.Root, Options{})
			if err != nil || exit != 0 || len(plan) != 12 || plan["view"] != "workspace" || plan["url"] != nil || plan["portSelection"] != "ephemeral" || plan["renderedAuthority"] != "presentation_adapter" || plan["planKind"] != "proofkit.requirement-browser-server-plan" {
				t.Fatalf("project plan lost its bounded presentation contract: %v", err)
			}
			prepared, _, err := prepareProject(t.Context(), fixture.Root, Options{})
			if err != nil {
				t.Fatal(err)
			}
			handle, err := StartProjectServer(t.Context(), fixture.Root, Options{SessionMode: "one-shot-question"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = handle.Close(context.Background()) })
			var stdout bytes.Buffer
			finished := make(chan error, 1)
			go func() {
				finished <- serveHandle(t.Context(), handle, Options{SessionMode: "one-shot-question"}, &stdout)
			}()
			response, err := (&http.Client{Timeout: 5 * time.Second}).Get(handle.URL)
			if err != nil {
				t.Fatal(err)
			}
			html, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			match := capabilityPattern.FindSubmatch(html)
			if err != nil || response.StatusCode != http.StatusOK || len(match) != 2 || plan["htmlByteLength"] != len(html) || !strings.Contains(response.Header.Get("Content-Security-Policy"), "default-src 'none'") {
				t.Fatal("project browser did not reuse the secured workspace document")
			}
			capability := string(match[1])
			for path := range fixture.Files {
				if err := os.Remove(filepath.Join(fixture.Root, filepath.FromSlash(path))); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(fixture.Root, "unlisted.json"), []byte("invalid ambient input"), 0o600); err != nil {
				t.Fatal(err)
			}
			manifest := projectHTTP(t, handle, capability, "manifest", nil, http.StatusOK)
			if manifest["workspaceId"] != "shared.identity" || manifest["snapshotId"] != handle.SnapshotID || manifest["coverageAvailable"] != false || manifest["diffAvailable"] != false || manifest["graphAvailable"] != true || manifest["expectedDigestCoverage"] != "partial" || manifest["requirementCount"] != json.Number("3") {
				t.Fatal("project manifest invented coverage, baseline or a different snapshot")
			}
			query := map[string]any{"requestId": "project.lookup", "snapshotId": handle.SnapshotID, "query": map[string]any{}}
			rows := projectHTTP(t, handle, capability, "requirements", query, http.StatusOK)["projection"].(map[string]any)["requirements"].([]any)
			assertWorkspaceRowIDs(t, rows, "requirementId", []string{"REQ-WIRE-001", "REQ-WIRE-002", "REQ-WIRE-003"})
			for _, endpoint := range []string{"coverage", "diff"} {
				projectHTTP(t, handle, capability, endpoint, query, http.StatusNotFound)
			}
			graph := projectHTTP(t, handle, capability, "graph", query, http.StatusOK)["projection"].(map[string]any)
			if len(graph["nodes"].([]any)) != 7 || len(graph["edges"].([]any)) != 6 {
				t.Fatal("project graph did not preserve all three declarations and binding relations")
			}
			annotations := []any{}
			for index, item := range []struct {
				id, path, pointer, quote string
				end                      int
			}{
				{"REQ-WIRE-001", "docs/specs/a/requirements.v1.json", "/projections/requirementSources/1/requirements/0/invariant", "\U0001f9ed", 12},
				{"REQ-WIRE-002", "docs/specs/z/requirements.v1.json", "/projections/requirementSources/0/requirements/0/invariant", "E\u0301", 13},
			}[:selected] {
				anchor := rows[index].(map[string]any)["anchor"].(map[string]any)
				wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(fixture.Files[item.path]))
				if anchor["jsonPointer"] != item.pointer || anchor["sourceDigest"] != wantDigest || anchor["requirementId"] != item.id {
					t.Fatal("lookup source order changed its original anchor identity")
				}
				original, err := jsonpointer.Select(requirementcontext.SnapshotValue(prepared.workspace.Snapshot), item.pointer)
				if err != nil || original != rows[index].(map[string]any)["invariant"] {
					t.Fatalf("original context pointer no longer resolves to lookup text: %v", err)
				}
				annotations = append(annotations, map[string]any{"anchorId": anchor["anchorId"], "startCodePoint": json.Number("11"), "endCodePoint": json.Number(fmt.Sprint(item.end)), "exactQuote": item.quote, "question": "Does this remain source-bound?"})
			}
			packet := projectHTTP(t, handle, capability, "handoff", map[string]any{"annotations": annotations}, http.StatusOK)
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(projectShutdownWatchdog):
				t.Fatal("project one-shot did not complete after handoff")
			}
			terminal, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), int64(stdout.Len()))
			if err != nil || !reflect.DeepEqual(terminal, packet) || packet["state"] != "submitted" || packet["snapshotRefs"].([]any)[0].(map[string]any)["snapshotId"] != handle.SnapshotID {
				t.Fatalf("terminal packet differs from the captured HTTP handoff: %v", err)
			}
			fragments := packet["context"].(map[string]any)["projections"].(map[string]any)["requirementSources"].([]any)
			if len(fragments) != selected {
				t.Fatal("terminal context included an omitted source")
			}
			for _, raw := range fragments {
				fragment := raw.(map[string]any)
				id, limitation, count, omitted := "REQ-WIRE-001", "Source a does not prove execution.", "1", "0"
				if fragment["sourceId"] == "shared.identity" {
					id, limitation, count, omitted = "REQ-WIRE-002", "Source z does not prove execution.", "2", "1"
				}
				if !reflect.DeepEqual(fragment["nonClaims"], []any{limitation}) || fragment["totalRequirementCount"] != json.Number(count) || fragment["omittedRequirementCount"] != json.Number(omitted) {
					t.Fatal("terminal source-level restrictions or omissions were lost")
				}
				requirements := fragment["requirements"].([]any)
				if len(requirements) != 1 || requirements[0].(map[string]any)["requirementId"] != id || !reflect.DeepEqual(requirements[0].(map[string]any)["nonClaims"], []any{"This fixture does not establish execution evidence."}) {
					t.Fatal("terminal selected requirement or its independent restrictions were lost")
				}
			}
			connection, err := net.DialTimeout("tcp", net.JoinHostPort(handle.Host, fmt.Sprint(handle.Port)), time.Second)
			if err == nil {
				_ = connection.Close()
				t.Fatal("successful terminal output left the listener open")
			}
		})
	}
}

func TestProjectWorkspacePreparationValidatesBeforeRendering(t *testing.T) {
	fixture := projectfixture.New(t)
	project, err := adoptionmaterialization.AdmitProject(fixture.Project)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := requirementcontext.FromProject(project, fmt.Sprintf("sha256:%x", sha256.Sum256(fixture.Files[adoptionmaterialization.ProjectManifestPath])))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := requirementgraph.Build(map[string]any{"schemaVersion": json.Number("2"), "graphId": "project.graph", "context": requirementcontext.SnapshotValue(snapshot)})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	document := func(id string) string { calls++; return workspaceHTML(id) }
	if _, _, err := prepareWorkspace("shared.identity", snapshot, nil, graph, document); err != nil || calls != 1 {
		t.Fatalf("owner-valid project did not reach exactly one render: %v calls=%d", err, calls)
	}
	calls = 0
	graph["snapshotId"] = "different.snapshot"
	if _, _, err := prepareWorkspace("shared.identity", snapshot, nil, graph, document); err == nil || calls != 0 {
		t.Fatal("invalid graph reached rendering")
	}
	graph["snapshotId"] = snapshot.SnapshotID
	graph["nodes"], graph["edges"] = []any{}, []any{}
	graph["nodeCount"], graph["edgeCount"] = json.Number("0"), json.Number("0")
	if _, err := requirementgraph.AdmitOutput(graph, snapshot.SnapshotID); err != nil {
		t.Fatalf("closure falsifier failed before workspace guard: %v", err)
	}
	if _, _, err := prepareWorkspace("shared.identity", snapshot, nil, graph, document); err == nil || !strings.Contains(err.Error(), "does not close") || calls != 0 {
		t.Fatal("individually admitted but incomplete graph reached rendering")
	}
}

func TestProjectHandoffPreservesLongRequirementIdentities(t *testing.T) {
	for _, length := range []int{234, 235, 244, 245, 256} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			id := "REQ-" + strings.Repeat("A", length-4)
			fixture := projectfixture.WithRequirementIDs(t, [3]string{id, "REQ-WIRE-002", "REQ-WIRE-003"})
			handle, err := StartProjectServer(t.Context(), fixture.Root, Options{SessionMode: "one-shot-question"})
			if err != nil {
				t.Fatalf("admitted requirement did not reach the workspace: %v", err)
			}
			t.Cleanup(func() { _ = handle.Close(context.Background()) })
			response, err := (&http.Client{Timeout: 5 * time.Second}).Get(handle.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			match := capabilityPattern.FindSubmatch(body)
			if err != nil || response.StatusCode != http.StatusOK || len(match) != 2 {
				t.Fatal("workspace capability is unavailable")
			}
			capability := string(match[1])
			query := map[string]any{"requestId": "long.lookup", "snapshotId": handle.SnapshotID, "query": map[string]any{}}
			rows := projectHTTP(t, handle, capability, "requirements", query, http.StatusOK)["projection"].(map[string]any)["requirements"].([]any)
			anchor := rows[0].(map[string]any)["anchor"].(map[string]any)
			anchorID := "requirement:" + id + ":invariant"
			wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(fixture.Files["docs/specs/a/requirements.v1.json"]))
			if anchor["anchorId"] != anchorID || anchor["requirementId"] != id || anchor["sourceDigest"] != wantDigest || anchor["jsonPointer"] != "/projections/requirementSources/1/requirements/0/invariant" {
				t.Fatal("workspace changed the original long requirement coordinate")
			}
			for _, invalid := range []any{json.Number("7"), "requirement:unknown:invariant", anchorID + "x", "requirement:" + strings.Repeat("A", 257) + ":invariant"} {
				annotation := map[string]any{"anchorId": invalid, "startCodePoint": json.Number("11"), "endCodePoint": json.Number("12"), "exactQuote": "\U0001f9ed", "question": "Is this source-bound?"}
				projectHTTP(t, handle, capability, "handoff", map[string]any{"annotations": []any{annotation}}, http.StatusBadRequest)
			}
			var stdout bytes.Buffer
			finished := make(chan error, 1)
			go func() {
				finished <- serveHandle(t.Context(), handle, Options{SessionMode: "one-shot-question"}, &stdout)
			}()
			annotation := map[string]any{"anchorId": anchorID, "startCodePoint": json.Number("11"), "endCodePoint": json.Number("12"), "exactQuote": "\U0001f9ed", "question": "Is this source-bound?"}
			packet := projectHTTP(t, handle, capability, "handoff", map[string]any{"annotations": []any{annotation}}, http.StatusOK)
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(projectShutdownWatchdog):
				t.Fatal("long-ID handoff did not terminate")
			}
			terminal, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), int64(stdout.Len()))
			if err != nil || !reflect.DeepEqual(terminal, packet) || !reflect.DeepEqual(packet["annotations"].([]any)[0].(map[string]any)["anchor"], anchor) {
				t.Fatal("terminal handoff lost the browser-issued coordinate")
			}
			fragments := packet["context"].(map[string]any)["projections"].(map[string]any)["requirementSources"].([]any)
			if len(fragments) != 1 || !reflect.DeepEqual(fragments[0].(map[string]any)["nonClaims"], []any{"Source a does not prove execution."}) || fragments[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)["requirementId"] != id {
				t.Fatal("long-ID handoff lost source restrictions or requirement identity")
			}
			connection, err := net.DialTimeout("tcp", net.JoinHostPort(handle.Host, fmt.Sprint(handle.Port)), time.Second)
			if err == nil {
				_ = connection.Close()
				t.Fatal("long-ID handoff left the listener open")
			}
		})
	}
}

func TestProjectBrowserRejectsIncompleteProjectBeforeListening(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	options := Options{Port: occupied.Addr().(*net.TCPAddr).Port, PortSet: true}
	root := t.TempDir()
	handle, err := StartProjectServer(t.Context(), root, options)
	var operation *net.OpError
	if err == nil || errors.As(err, &operation) || !strings.Contains(err.Error(), "next with the same --repo-root") || handle.URL != "" || handle.Done() != nil {
		t.Fatalf("incomplete project reached the occupied listener: %v", err)
	}
	fixture := projectfixture.New(t)
	_, err = StartProjectServer(t.Context(), fixture.Root, options)
	if !errors.As(err, &operation) || operation.Op != "listen" {
		t.Fatalf("positive preparation sibling did not reach the actual listener: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixture.Root, "proofkit", "tests.json"), []byte("not JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = StartProjectServer(t.Context(), fixture.Root, options)
	if err == nil || errors.As(err, &operation) || !strings.Contains(err.Error(), "complete admitted project") {
		t.Fatalf("invalid routed artifact reached listening or escaped static classification: %v", err)
	}
}

func TestProjectBrowserRejectsOptionsBeforeRepositoryRead(t *testing.T) {
	for _, item := range []struct {
		options    Options
		diagnostic string
	}{
		{Options{Host: "localhost"}, "loopback literal"},
		{Options{Port: -1, PortSet: true}, "integer from 0 to 65535"},
		{Options{View: "proof"}, "does not accept"},
		{Options{ProofViewScope: "local"}, "does not accept"},
		{Options{EmptyLocalEnvironmentPolicy: true}, "does not accept"},
		{Options{LocalEnvironmentClasses: []string{"local-go"}}, "does not accept"},
	} {
		plan, code, err := BuildProjectPlan(t.Context(), filepath.Join(t.TempDir(), "missing"), item.options)
		if err == nil || !strings.Contains(err.Error(), item.diagnostic) || plan != nil || code != 1 {
			t.Fatalf("invalid options reached repository inspection: %v", err)
		}
		calls := 0
		inspect := func(ctx context.Context, root string) (projectstatus.Inspection, error) {
			calls++
			return projectstatus.InspectProject(ctx, root)
		}
		if _, _, err := prepareProjectWithInspector(t.Context(), t.TempDir(), item.options, inspect); err == nil || calls != 0 {
			t.Fatalf("invalid options crossed the inspection boundary: calls=%d error=%v", calls, err)
		}
	}
	fixture := projectfixture.New(t)
	calls := 0
	inspect := func(ctx context.Context, root string) (projectstatus.Inspection, error) {
		calls++
		return projectstatus.InspectProject(ctx, root)
	}
	rendered, _, err := prepareProjectWithInspector(t.Context(), fixture.Root, Options{}, inspect)
	if err != nil || calls != 1 || rendered.workspace == nil {
		t.Fatalf("valid sibling did not execute exactly one inspection: calls=%d error=%v", calls, err)
	}
}

func projectHTTP(t *testing.T, handle ServerHandle, capability, endpoint string, value any, expectedStatus int) map[string]any {
	t.Helper()
	method := http.MethodPost
	var body io.Reader
	if value == nil {
		method = http.MethodGet
	} else {
		body = bytes.NewReader(stableWorkspaceBytes(t, value))
	}
	request, err := http.NewRequest(method, handle.URL+"api/v1/"+endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", strings.TrimSuffix(handle.URL, "/"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Proofkit-Browser-Capability", capability)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		t.Fatalf("project endpoint %s status=%d, expected %d", endpoint, response.StatusCode, expectedStatus)
	}
	if expectedStatus != http.StatusOK {
		return nil
	}
	return decodeWorkspaceResponse(t, response)
}
