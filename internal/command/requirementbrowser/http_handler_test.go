package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestWriteAPIErrorUsesTypedClassification(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "ordinary validation", err: errors.New("unsupported field unauthorized and stale"), status: http.StatusBadRequest},
		{name: "unauthorized", err: errUnauthorizedAPIRequest, status: http.StatusForbidden},
		{name: "stale", err: errStaleAPIRequest, status: http.StatusConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeAPIError(response, http.MethodPost, test.err)
			if response.Code != test.status {
				t.Fatalf("status=%d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestWorkspaceRequestAdmissionIsBounded(t *testing.T) {
	requests := make(chan struct{}, 1)
	first := httptest.NewRecorder()
	if !admitWorkspaceRequest(first, requests) {
		t.Fatal("first request must be admitted")
	}
	second := httptest.NewRecorder()
	if admitWorkspaceRequest(second, requests) {
		t.Fatal("request beyond the concurrency bound must be rejected")
	}
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want %d", second.Code, http.StatusTooManyRequests)
	}
	releaseWorkspaceRequest(requests)
	third := httptest.NewRecorder()
	if !admitWorkspaceRequest(third, requests) {
		t.Fatal("released capacity must admit the next request")
	}
	releaseWorkspaceRequest(requests)
}

func TestWorkspaceCancelHasIndependentBoundedCapacity(t *testing.T) {
	const authority = "127.0.0.1:43127"
	const body = `{"requestId":"test.cancel","snapshotId":"snapshot.test"}`
	capability, err := browserCapability()
	if err != nil {
		t.Fatal(err)
	}
	terminal := newTerminalArbiter()
	rendered := renderedView{workspace: &workspaceSession{SnapshotID: "snapshot.test"}}
	handler := browserHandler("workspace", rendered, authority, capability, true, terminal)
	post := func(path string, payload io.Reader) int {
		request := httptest.NewRequest(http.MethodPost, "http://"+authority+path, payload)
		request.Header.Set("Origin", "http://"+authority)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Proofkit-Browser-Capability", capability)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	const graph, cancel = "/api/v1/graph", "/api/v1/cancel"
	var fillProjectionSlots func(int)
	fillProjectionSlots = func(remaining int) {
		if remaining > 0 {
			reader := &workspaceReadHook{Reader: strings.NewReader(body), before: func() { fillProjectionSlots(remaining - 1) }}
			if status := post(graph, reader); status != http.StatusNotFound {
				t.Fatalf("admitted projection did not reach the unavailable graph: %d", status)
			}
			return
		}
		if status := post(graph, strings.NewReader(body)); status != http.StatusTooManyRequests {
			t.Fatalf("projection slots were not exhausted: %d", status)
		}
		first := &workspaceReadHook{Reader: strings.NewReader(body), before: func() {
			secondRead := false
			second := &workspaceReadHook{Reader: strings.NewReader(body), before: func() { secondRead = true }}
			if status := post(cancel, second); status != http.StatusTooManyRequests || secondRead {
				t.Fatalf("overlapping cancel was not refused before reading: status=%d read=%v", status, secondRead)
			}
		}}
		if status := post(cancel, first); status != http.StatusOK {
			t.Fatalf("cancellation could not use its independent slot: %d", status)
		}
	}
	fillProjectionSlots(4)
	if status := post(cancel, strings.NewReader(body)); status != http.StatusGone {
		t.Fatalf("released cancel slot did not reach the terminal arbiter: %d", status)
	}
}

type workspaceReadHook struct {
	io.Reader
	before func()
}

func (reader *workspaceReadHook) Read(data []byte) (int, error) {
	if before := reader.before; before != nil {
		reader.before = nil
		before()
	}
	return reader.Reader.Read(data)
}

func TestProjectionQueryKeepsEveryAdmittedRequirementPageReachable(t *testing.T) {
	const finalOffset = 20_224
	index := workspaceLookupIndex{Rows: make([]workspaceRequirement, finalOffset+1)}
	for position := range index.Rows {
		index.Rows[position].Requirement.RequirementID = fmt.Sprintf("REQ-%05d", position)
	}
	query, err := admitWorkspaceLookupQuery(map[string]any{
		"maxRecords": json.Number("256"),
		"offset":     json.Number("20224"),
	}, index)
	if err != nil {
		t.Fatalf("admit final reachable page: %v", err)
	}
	body, err := workspaceLookupPage(index, query).encode("page.test", "snapshot.test", maxWorkspaceLookupResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	response := value.(map[string]any)
	projection := response["projection"].(map[string]any)
	if response["state"] != "partial_with_omissions" || projection["selectedRequirementCount"] != json.Number("1") {
		t.Fatalf("final page lost exact selection: %#v", projection)
	}
	selected := projection["requirements"].([]any)
	if got := selected[0].(map[string]any)["requirementId"]; got != "REQ-20224" {
		t.Fatalf("final requirement=%v, want REQ-20224", got)
	}
}
