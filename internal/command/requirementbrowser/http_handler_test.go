package requirementbrowser

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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
	requirements := make([]any, finalOffset+1)
	for index := range requirements {
		requirements[index] = map[string]any{"requirementId": fmt.Sprintf("REQ-%05d", index)}
	}
	query, err := admitProjectionQuery(map[string]any{
		"maxRecords": json.Number("256"),
		"offset":     json.Number("20224"),
	})
	if err != nil {
		t.Fatalf("admit final reachable page: %v", err)
	}
	projection, state := requirementWindow(requirements, query)
	if state != "partial_with_omissions" || projection["selectedRequirementCount"] != 1 {
		t.Fatalf("final page state=%s projection=%#v", state, projection)
	}
	selected := projection["requirements"].([]any)
	if got := selected[0].(map[string]any)["requirementId"]; got != "REQ-20224" {
		t.Fatalf("final requirement=%v, want REQ-20224", got)
	}
}
