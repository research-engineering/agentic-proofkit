package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
