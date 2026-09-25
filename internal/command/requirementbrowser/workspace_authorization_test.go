package requirementbrowser

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const authorizationOrigin = "http://127.0.0.1:43127"

type workspacePOSTCase struct {
	path string
	body string
}

func workspacePOSTCases(t *testing.T) (renderedView, []workspacePOSTCase) {
	t.Helper()
	rendered, err := render(coverageWorkspaceFixture(t, "compact", false), Options{View: "workspace"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := rendered.workspace.SnapshotID
	query := fmt.Sprintf(`{"requestId":"authorization.test","snapshotId":%q,"query":{}}`, snapshot)
	return rendered, []workspacePOSTCase{
		{"/api/v1/query", fmt.Sprintf(`{"requestId":"authorization.test","snapshotId":%q,"query":{"profile":"routing"}}`, snapshot)},
		{"/api/v1/requirements", query},
		{"/api/v1/navigation", query},
		{"/api/v1/coverage", query},
		{"/api/v1/diff", query},
		{"/api/v1/graph", query},
		{"/api/v1/cancel", fmt.Sprintf(`{"requestId":"authorization.test","snapshotId":%q}`, snapshot)},
		{"/api/v1/handoff", string(encodedHandoffBody(t, []any{
			handoffAnnotationRecord("requirement:REQ-BROWSER-COVERAGE-001:invariant", 0, 8, "Coverage", "Which evidence is declared?"),
		}))},
	}
}

type observedRequestBody struct {
	io.Reader
	reads int
}

func (body *observedRequestBody) Read(value []byte) (int, error) {
	body.reads++
	return body.Reader.Read(value)
}

func (*observedRequestBody) Close() error { return nil }

func authorizedWorkspacePOST(route workspacePOSTCase, capability string) (*http.Request, *observedRequestBody) {
	request := httptest.NewRequest(http.MethodPost, authorizationOrigin+route.path, nil)
	body := &observedRequestBody{Reader: strings.NewReader(route.body)}
	request.Body = body
	request.ContentLength = int64(len(route.body))
	request.Header.Set("Origin", authorizationOrigin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Proofkit-Browser-Capability", capability)
	return request, body
}

func assertNoTerminalPacket(t *testing.T, terminal *terminalArbiter) {
	t.Helper()
	select {
	case <-terminal.packets:
		t.Fatal("request unexpectedly published a terminal packet")
	default:
	}
}

func assertAuthorizedWorkspacePOST(t *testing.T, handler http.Handler, route workspacePOSTCase, capability string, terminal *terminalArbiter) {
	t.Helper()
	request, body := authorizedWorkspacePOST(route, capability)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || body.reads == 0 {
		t.Fatalf("valid %s: status=%d reads=%d body=%s", route.path, response.Code, body.reads, response.Body.String())
	}
	packet := decodeWorkspaceResponse(t, response.Result())
	if route.path == "/api/v1/cancel" || route.path == "/api/v1/handoff" {
		state := "cancelled"
		if route.path == "/api/v1/handoff" {
			state = "submitted"
		}
		if packet["state"] != state {
			t.Fatalf("valid terminal state=%v, want %s", packet["state"], state)
		}
		select {
		case winner := <-terminal.packets:
			if winner["state"] != state {
				t.Fatalf("terminal winner=%v, want %s", winner["state"], state)
			}
		default:
			t.Fatal("valid terminal request did not commit")
		}
	} else {
		state := "complete"
		if route.path == "/api/v1/query" {
			state = "selected"
		}
		if packet["requestId"] != "authorization.test" || packet["state"] != state {
			t.Fatalf("valid %s identity=%v state=%v, want authorization.test/%s", route.path, packet["requestId"], packet["state"], state)
		}
	}
	assertNoTerminalPacket(t, terminal)
}

func TestWorkspacePOSTAuthorizationMatrix(t *testing.T) {
	rendered, routes := workspacePOSTCases(t)
	capability := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", browserCapabilityBytes)))
	for _, route := range routes {
		t.Run(route.path, func(t *testing.T) {
			t.Run("valid", func(t *testing.T) {
				terminal := newTerminalArbiter()
				handler := browserHandler("workspace", rendered, strings.TrimPrefix(authorizationOrigin, "http://"), capability, true, terminal)
				assertAuthorizedWorkspacePOST(t, handler, route, capability, terminal)
			})
			// Each denial changes exactly one header; valid bodies kill removed guards.
			for _, header := range []struct{ name, wrong string }{
				{"Origin", "https://foreign.invalid"},
				{"Content-Type", "text/plain"},
				{"X-Proofkit-Browser-Capability", base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", browserCapabilityBytes)))},
			} {
				for _, value := range []string{"", header.wrong} {
					label := "wrong"
					if value == "" {
						label = "missing"
					}
					for _, bodyKind := range []string{"valid", "malformed", "oversized-length"} {
						t.Run(header.name+"/"+label+"/"+bodyKind, func(t *testing.T) {
							terminal := newTerminalArbiter()
							handler := browserHandler("workspace", rendered, strings.TrimPrefix(authorizationOrigin, "http://"), capability, true, terminal)
							input := route
							if bodyKind == "malformed" {
								input.body = "{"
							}
							request, body := authorizedWorkspacePOST(input, capability)
							if bodyKind == "oversized-length" {
								request.ContentLength = maxHandoffRequestBytes + 1
							}
							if value == "" {
								request.Header.Del(header.name)
							} else {
								request.Header.Set(header.name, value)
							}
							response := httptest.NewRecorder()
							handler.ServeHTTP(response, request)
							if response.Code != http.StatusForbidden || body.reads != 0 {
								t.Fatalf("denial must precede body admission: status=%d reads=%d", response.Code, body.reads)
							}
							assertNoTerminalPacket(t, terminal)
							assertAuthorizedWorkspacePOST(t, handler, route, capability, terminal)
						})
					}
				}
			}
		})
	}
}

func TestWorkspacePOSTBodyAdmissionBeforeTerminal(t *testing.T) {
	rendered, routes := workspacePOSTCases(t)
	capability := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", browserCapabilityBytes)))
	for _, route := range routes {
		for _, kind := range []string{"oversized-length", "malformed", "unknown-key", "stale"} {
			if kind == "stale" && route.path == "/api/v1/handoff" {
				continue // Handoff resolves immutable source anchors, not a snapshotId field.
			}
			t.Run(route.path+"/"+kind, func(t *testing.T) {
				terminal := newTerminalArbiter()
				handler := browserHandler("workspace", rendered, strings.TrimPrefix(authorizationOrigin, "http://"), capability, true, terminal)
				input := route
				want := http.StatusBadRequest
				switch kind {
				case "malformed":
					input.body = "{"
				case "unknown-key":
					input.body = `{"unknown":true,` + input.body[1:]
				case "stale":
					input.body = strings.ReplaceAll(input.body, rendered.workspace.SnapshotID, "stale.snapshot")
					want = http.StatusConflict
				}
				request, body := authorizedWorkspacePOST(input, capability)
				if kind == "oversized-length" {
					request.ContentLength = maxHandoffRequestBytes + 1
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != want || (body.reads == 0) != (kind == "oversized-length") {
					t.Fatalf("body admission: status=%d want=%d reads=%d", response.Code, want, body.reads)
				}
				assertNoTerminalPacket(t, terminal)
				assertAuthorizedWorkspacePOST(t, handler, route, capability, terminal)
			})
		}
	}
}

func TestWorkspaceTerminalPOSTPairsReturnGoneWithoutDuplicate(t *testing.T) {
	rendered, routes := workspacePOSTCases(t)
	capability := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", browserCapabilityBytes)))
	for _, first := range routes[6:] {
		for _, second := range routes[6:] {
			t.Run(first.path+"/"+second.path, func(t *testing.T) {
				terminal := newTerminalArbiter()
				handler := browserHandler("workspace", rendered, strings.TrimPrefix(authorizationOrigin, "http://"), capability, true, terminal)
				assertAuthorizedWorkspacePOST(t, handler, first, capability, terminal)
				request, _ := authorizedWorkspacePOST(second, capability)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusGone {
					t.Fatalf("consumed terminal status=%d, want 410", response.Code)
				}
				assertNoTerminalPacket(t, terminal)
			})
		}
	}
}
