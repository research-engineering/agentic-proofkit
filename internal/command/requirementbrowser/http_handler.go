package requirementbrowser

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	maxHandoffRequestBytes  = 1 << 20
	maxHandoffAnnotations   = 64
	maxHandoffQuoteBytes    = 64 << 10
	maxHandoffQuestionBytes = 4 << 10
	maxHandoffContextBytes  = 1 << 20
	maxHandoffPacketBytes   = 2 << 20
)

func browserHandler(view string, rendered renderedView, expectedAuthority, capability string, oneShot bool, terminal *terminalArbiter) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != expectedAuthority {
			forbidden(response, request.Method)
			return
		}
		expectedOrigin := "http://" + expectedAuthority
		if origin := request.Header.Get("origin"); origin != "" && origin != expectedOrigin {
			forbidden(response, request.Method)
			return
		}
		method := request.Method
		switch request.URL.Path {
		case "/", "/index.html":
			serveIndex(response, method, rendered)
		case "/healthz":
			serveHealth(response, method, view, rendered)
		case "/assets/workspace.js":
			serveWorkspaceAsset(response, method, workspaceJavaScript, "text/javascript; charset=utf-8")
		case "/assets/selection-authority.js":
			serveWorkspaceAsset(response, method, selectionAuthorityJavaScript, "text/javascript; charset=utf-8")
		case "/assets/workspace.css":
			serveWorkspaceAsset(response, method, workspaceCSS, "text/css; charset=utf-8")
		case "/api/v1/manifest":
			if method != http.MethodGet && method != http.MethodHead {
				methodNotAllowed(response, method, "GET, HEAD")
				return
			}
			if rendered.workspace == nil || !validCapability(request, capability) {
				forbidden(response, method)
				return
			}
			serveWorkspaceJSON(response, method, rendered.workspace.Manifest)
		case "/api/v1/query":
			if method != http.MethodPost {
				methodNotAllowed(response, method, "POST")
				return
			}
			serveWorkspaceQuery(response, request, expectedOrigin, capability, rendered.workspace)
		case "/api/v1/requirements":
			if method != http.MethodPost {
				methodNotAllowed(response, method, "POST")
				return
			}
			serveWorkspaceRequirements(response, request, expectedOrigin, capability, rendered.workspace)
		case "/api/v1/diff", "/api/v1/graph":
			if method != http.MethodPost {
				methodNotAllowed(response, method, "POST")
				return
			}
			serveWorkspaceProjection(response, request, expectedOrigin, capability, rendered.workspace)
		case "/api/v1/cancel":
			if method != http.MethodPost {
				methodNotAllowed(response, method, "POST")
				return
			}
			serveCancel(response, request, expectedOrigin, capability, rendered.workspace, oneShot, terminal)
		case "/api/v1/handoff":
			if method != http.MethodPost {
				methodNotAllowed(response, method, "POST")
				return
			}
			serveHandoff(response, request, expectedOrigin, capability, rendered.workspace, oneShot, terminal)
		default:
			response.WriteHeader(http.StatusNotFound)
			writeBody(response, method, []byte("not found\n"))
		}
	})
}

func serveWorkspaceRequirements(response http.ResponseWriter, request *http.Request, expectedOrigin, capability string, session *workspaceSession) {
	record, err := admitAPIRequest(request, expectedOrigin, capability, session, []string{"query", "requestId", "snapshotId"})
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	requestID, err := admit.RuleID(record["requestId"], "requirement browser requirements requestId")
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	query, err := admitProjectionQuery(record["query"])
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	projection, state := requirementWindow(session.Requirements, query)
	serveWorkspaceJSON(response, request.Method, map[string]any{"projection": projection, "requestId": requestID, "schemaVersion": json.Number("1"), "snapshotId": session.SnapshotID, "state": state})
}

func requirementWindow(requirements []any, query projectionQuery) (map[string]any, string) {
	start := min(query.Offset, len(requirements))
	end := min(start+query.MaxRecords, len(requirements))
	selected := append([]any{}, requirements[start:end]...)
	state := "complete"
	if start > 0 || end < len(requirements) {
		state = "partial_with_omissions"
	}
	return map[string]any{"authority": "lookup_fragment_only", "availableRequirementCount": len(requirements), "omittedRequirementCount": len(requirements) - len(selected), "projectionKind": "proofkit.requirement-browser-requirement-fragment", "requirements": selected, "selectedRequirementCount": len(selected)}, state
}

func serveWorkspaceQuery(response http.ResponseWriter, request *http.Request, expectedOrigin, capability string, session *workspaceSession) {
	record, err := admitAPIRequest(request, expectedOrigin, capability, session, []string{"query", "requestId", "snapshotId"})
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	requestID, err := admit.RuleID(record["requestId"], "requirement browser query requestId")
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	query, ok := record["query"].(map[string]any)
	if !ok {
		writeAPIError(response, request.Method, fmt.Errorf("requirement browser query must be an object"))
		return
	}
	queryBytes, err := stablejson.Marshal(query)
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	queryID := digest.SHA256TextRef(string(queryBytes))
	slice, err := requirementcontext.Slice(map[string]any{
		"context":       session.ContextValue,
		"query":         query,
		"schemaVersion": json.Number("1"),
		"sliceId":       "browser.query:" + requestID,
	})
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	serveWorkspaceJSON(response, request.Method, map[string]any{
		"queryId":       queryID,
		"requestId":     requestID,
		"schemaVersion": json.Number("1"),
		"slice":         slice,
		"snapshotId":    session.SnapshotID,
		"state":         slice["state"],
	})
}

func serveWorkspaceProjection(response http.ResponseWriter, request *http.Request, expectedOrigin, capability string, session *workspaceSession) {
	record, err := admitAPIRequest(request, expectedOrigin, capability, session, []string{"query", "requestId", "snapshotId"})
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	requestID, err := admit.RuleID(record["requestId"], "requirement browser projection requestId")
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	var projection map[string]any
	if request.URL.Path == "/api/v1/diff" {
		projection = session.Diff
	} else {
		projection = session.Graph
	}
	if projection == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	query, err := admitProjectionQuery(record["query"])
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	state := "complete"
	if request.URL.Path == "/api/v1/diff" {
		projection, state = diffWindow(projection, query)
	} else {
		projection, state = graphWindow(projection, query)
	}
	serveWorkspaceJSON(response, request.Method, map[string]any{"projection": projection, "requestId": requestID, "schemaVersion": json.Number("1"), "snapshotId": session.SnapshotID, "state": state})
}

type projectionQuery struct {
	EdgeOffset int
	MaxEdges   int
	MaxRecords int
	Offset     int
}

func admitProjectionQuery(raw any) (projectionQuery, error) {
	query := projectionQuery{MaxEdges: 2048, MaxRecords: 256}
	if raw == nil {
		return query, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return projectionQuery{}, fmt.Errorf("browser projection query must be an object")
	}
	if err := admit.KnownKeys(record, []string{"edgeOffset", "maxEdges", "maxRecords", "offset"}, "browser projection query"); err != nil {
		return projectionQuery{}, err
	}
	var err error
	if record["edgeOffset"] != nil {
		query.EdgeOffset, err = nonNegativeJSONInteger(record["edgeOffset"], "browser projection query edgeOffset")
		if err != nil || query.EdgeOffset > 80_000 {
			return projectionQuery{}, fmt.Errorf("browser projection query edgeOffset must be between 0 and 80000")
		}
	}
	if record["offset"] != nil {
		query.Offset, err = nonNegativeJSONInteger(record["offset"], "browser projection query offset")
		if err != nil || query.Offset > 20_000 {
			return projectionQuery{}, fmt.Errorf("browser projection query offset must be between 0 and 20000")
		}
	}
	if record["maxRecords"] != nil {
		query.MaxRecords, err = positiveJSONInteger(record["maxRecords"], "browser projection query maxRecords")
		if err != nil || query.MaxRecords > 2048 {
			return projectionQuery{}, fmt.Errorf("browser projection query maxRecords must be between 1 and 2048")
		}
	}
	if record["maxEdges"] != nil {
		query.MaxEdges, err = positiveJSONInteger(record["maxEdges"], "browser projection query maxEdges")
		if err != nil || query.MaxEdges > 16_384 {
			return projectionQuery{}, fmt.Errorf("browser projection query maxEdges must be between 1 and 16384")
		}
	}
	return query, nil
}

func diffWindow(full map[string]any, query projectionQuery) (map[string]any, string) {
	changes := full["changes"].([]any)
	start := min(query.Offset, len(changes))
	end := min(start+query.MaxRecords, len(changes))
	selected := append([]any{}, changes[start:end]...)
	state := "complete"
	if start > 0 || end < len(changes) {
		state = "partial_with_omissions"
	}
	return map[string]any{
		"authority":                   "lookup_fragment_only",
		"availableChangeCount":        len(changes),
		"baseBaselineVerification":    full["baseBaselineVerification"],
		"baseSnapshotId":              full["baseSnapshotId"],
		"changes":                     selected,
		"currentBaselineVerification": full["currentBaselineVerification"],
		"currentSnapshotId":           full["currentSnapshotId"],
		"nonClaims":                   full["nonClaims"],
		"omittedChangeCount":          len(changes) - len(selected),
		"projectionKind":              "proofkit.requirement-semantic-diff-fragment",
		"selectedChangeCount":         len(selected),
		"sourceDiffId":                full["diffId"],
	}, state
}

func graphWindow(full map[string]any, query projectionQuery) (map[string]any, string) {
	nodes := full["nodes"].([]any)
	start := min(query.Offset, len(nodes))
	end := min(start+query.MaxRecords, len(nodes))
	primaryNodes := append([]any{}, nodes[start:end]...)
	primaryIDs := map[string]struct{}{}
	for _, raw := range primaryNodes {
		primaryIDs[raw.(map[string]any)["nodeId"].(string)] = struct{}{}
	}
	incidentEdges := []any{}
	for _, raw := range full["edges"].([]any) {
		edge := raw.(map[string]any)
		_, from := primaryIDs[edge["fromNodeId"].(string)]
		_, to := primaryIDs[edge["toNodeId"].(string)]
		if from || to {
			incidentEdges = append(incidentEdges, edge)
		}
	}
	edgeStart := min(query.EdgeOffset, len(incidentEdges))
	edgeEnd := min(edgeStart+query.MaxEdges, len(incidentEdges))
	selectedEdges := append([]any{}, incidentEdges[edgeStart:edgeEnd]...)
	selectedIDs := map[string]struct{}{}
	for id := range primaryIDs {
		selectedIDs[id] = struct{}{}
	}
	for _, raw := range selectedEdges {
		edge := raw.(map[string]any)
		selectedIDs[edge["fromNodeId"].(string)] = struct{}{}
		selectedIDs[edge["toNodeId"].(string)] = struct{}{}
	}
	selectedNodes := make([]any, 0, len(selectedIDs))
	for _, raw := range nodes {
		if _, ok := selectedIDs[raw.(map[string]any)["nodeId"].(string)]; ok {
			selectedNodes = append(selectedNodes, raw)
		}
	}
	availableEdges := len(full["edges"].([]any))
	omittedNodes := len(nodes) - len(selectedNodes)
	omittedPrimaryNodes := len(nodes) - len(primaryNodes)
	omittedEdges := availableEdges - len(selectedEdges)
	state := "complete"
	if omittedNodes > 0 || omittedEdges > 0 || edgeStart > 0 || edgeEnd < len(incidentEdges) {
		state = "partial_with_omissions"
	}
	return map[string]any{
		"authority":                  "lookup_fragment_only",
		"availableEdgeCount":         availableEdges,
		"availableIncidentEdgeCount": len(incidentEdges),
		"availableNodeCount":         len(nodes),
		"boundaryNodeCount":          len(selectedNodes) - len(primaryNodes),
		"edgeOffset":                 edgeStart,
		"edges":                      selectedEdges,
		"nodes":                      selectedNodes,
		"nonClaims":                  full["nonClaims"],
		"omittedEdgeCount":           omittedEdges,
		"omittedIncidentEdgeCount":   len(incidentEdges) - len(selectedEdges),
		"omittedNodeCount":           omittedNodes,
		"omittedPrimaryNodeCount":    omittedPrimaryNodes,
		"primaryNodeCount":           len(primaryNodes),
		"projectionKind":             "proofkit.requirement-traceability-graph-fragment",
		"selectedEdgeCount":          len(selectedEdges),
		"selectedNodeCount":          len(selectedNodes),
		"sourceGraphId":              full["graphId"],
		"sourceSnapshotId":           full["snapshotId"],
	}, state
}

func serveCancel(response http.ResponseWriter, request *http.Request, expectedOrigin, capability string, session *workspaceSession, oneShot bool, terminal *terminalArbiter) {
	record, err := admitAPIRequest(request, expectedOrigin, capability, session, []string{"requestId", "snapshotId"})
	if err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	if _, err := admit.RuleID(record["requestId"], "requirement browser cancel requestId"); err != nil {
		writeAPIError(response, request.Method, err)
		return
	}
	packet := map[string]any{"handoffKind": "proofkit.requirement-browser-question", "nonClaims": admit.StringSliceToAny(serverNonClaims), "schemaVersion": json.Number("1"), "snapshotRefs": []any{map[string]any{"role": "current", "snapshotId": session.SnapshotID}}, "state": "cancelled"}
	if oneShot {
		if !terminal.TryCommit(packet) {
			response.WriteHeader(http.StatusConflict)
			return
		}
	}
	serveWorkspaceJSON(response, request.Method, packet)
}

func admitAPIRequest(request *http.Request, expectedOrigin, capability string, session *workspaceSession, keys []string) (map[string]any, error) {
	if session == nil || request.Header.Get("origin") != expectedOrigin || request.Header.Get("content-type") != "application/json" || !validCapability(request, capability) {
		return nil, fmt.Errorf("unauthorized browser API request")
	}
	if request.ContentLength > maxHandoffRequestBytes {
		return nil, fmt.Errorf("browser API request exceeds byte limit")
	}
	raw, err := admission.DecodeJSON(io.LimitReader(request.Body, maxHandoffRequestBytes+1), maxHandoffRequestBytes)
	if err != nil {
		return nil, err
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("browser API request must be an object")
	}
	if err := admit.KnownKeys(record, keys, "browser API request"); err != nil {
		return nil, err
	}
	if record["snapshotId"] != session.SnapshotID {
		return nil, fmt.Errorf("browser API request snapshot is stale")
	}
	return record, nil
}

func writeAPIError(response http.ResponseWriter, method string, err error) {
	status := http.StatusBadRequest
	if strings.Contains(err.Error(), "unauthorized") {
		status = http.StatusForbidden
	} else if strings.Contains(err.Error(), "stale") {
		status = http.StatusConflict
	}
	response.WriteHeader(status)
	writeBody(response, method, []byte("request rejected\n"))
}

func serveIndex(response http.ResponseWriter, method string, rendered renderedView) {
	if method != http.MethodGet && method != http.MethodHead {
		methodNotAllowed(response, method, "GET, HEAD")
		return
	}
	response.Header().Set("cache-control", "no-store")
	response.Header().Set("content-type", "text/html; charset=utf-8")
	if rendered.workspace != nil {
		setWorkspaceSecurityHeaders(response)
	}
	response.WriteHeader(http.StatusOK)
	writeBody(response, method, []byte(rendered.html))
}

func serveHealth(response http.ResponseWriter, method, view string, rendered renderedView) {
	if method != http.MethodGet && method != http.MethodHead {
		methodNotAllowed(response, method, "GET, HEAD")
		return
	}
	body, err := stablejson.Marshal(map[string]any{"authority": "presentation_adapter_status", "nonClaims": admit.StringSliceToAny(serverNonClaims), "state": "ok", "view": view, "viewKind": rendered.viewKind})
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.Header().Set("cache-control", "no-store")
	response.Header().Set("content-type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	writeBody(response, method, body)
}

func serveHandoff(response http.ResponseWriter, request *http.Request, expectedOrigin, capability string, session *workspaceSession, oneShot bool, terminal *terminalArbiter) {
	if session == nil || request.Method != http.MethodPost || request.Header.Get("origin") != expectedOrigin || request.Header.Get("content-type") != "application/json" || !validCapability(request, capability) {
		forbidden(response, request.Method)
		return
	}
	packet, err := buildHandoffPacket(request, *session)
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		writeBody(response, request.Method, []byte("invalid handoff\n"))
		return
	}
	if oneShot {
		if !terminal.TryCommit(packet) {
			response.WriteHeader(http.StatusConflict)
			return
		}
	}
	serveWorkspaceJSON(response, request.Method, packet)
}

func browserCapability() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate browser capability: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
func validCapability(request *http.Request, capability string) bool {
	expected, err := base64.RawURLEncoding.DecodeString(capability)
	if err != nil || len(expected) != 32 {
		return false
	}
	provided, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Proofkit-Browser-Capability"))
	if err != nil || len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(provided, expected) == 1
}
func setWorkspaceSecurityHeaders(response http.ResponseWriter) {
	response.Header().Set("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	response.Header().Set("cross-origin-opener-policy", "same-origin")
	response.Header().Set("cross-origin-resource-policy", "same-origin")
	response.Header().Set("permissions-policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()")
	response.Header().Set("x-content-type-options", "nosniff")
	response.Header().Set("referrer-policy", "no-referrer")
}
func serveWorkspaceAsset(response http.ResponseWriter, method string, body []byte, contentType string) {
	if method != http.MethodGet && method != http.MethodHead {
		methodNotAllowed(response, method, "GET, HEAD")
		return
	}
	response.Header().Set("cache-control", "no-store")
	response.Header().Set("content-type", contentType)
	setWorkspaceSecurityHeaders(response)
	response.WriteHeader(http.StatusOK)
	writeBody(response, method, body)
}
func serveWorkspaceJSON(response http.ResponseWriter, method string, value any) {
	body, err := stablejson.Marshal(value)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.Header().Set("cache-control", "no-store")
	response.Header().Set("content-type", "application/json; charset=utf-8")
	setWorkspaceSecurityHeaders(response)
	response.WriteHeader(http.StatusOK)
	writeBody(response, method, body)
}
func methodNotAllowed(response http.ResponseWriter, method, allow string) {
	response.Header().Set("allow", allow)
	response.WriteHeader(http.StatusMethodNotAllowed)
	writeBody(response, method, []byte("method not allowed\n"))
}
func forbidden(response http.ResponseWriter, method string) {
	response.Header().Set("content-type", "text/plain; charset=utf-8")
	response.WriteHeader(http.StatusForbidden)
	writeBody(response, method, []byte("forbidden\n"))
}

func buildHandoffPacket(request *http.Request, session workspaceSession) (map[string]any, error) {
	if request.ContentLength > 1<<20 {
		return nil, fmt.Errorf("handoff exceeds byte limit")
	}
	raw, err := admission.DecodeJSON(io.LimitReader(request.Body, (1<<20)+1), 1<<20)
	if err != nil {
		return nil, err
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("handoff must be an object")
	}
	if err := admit.KnownKeys(record, []string{"annotations"}, "browser handoff"); err != nil {
		return nil, err
	}
	values, ok := record["annotations"].([]any)
	if !ok || len(values) == 0 || len(values) > maxHandoffAnnotations {
		return nil, fmt.Errorf("handoff annotations must contain 1 to 64 records")
	}
	annotations := make([]any, 0, len(values))
	requirementIDs := map[string]struct{}{}
	seenTargets := map[string]struct{}{}
	for _, value := range values {
		annotation, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("handoff annotation must be an object")
		}
		admitted, err := admitAnnotation(annotation, session)
		if err != nil {
			return nil, err
		}
		targetID, err := handoffTargetID(admitted)
		if err != nil {
			return nil, err
		}
		if _, exists := seenTargets[targetID]; exists {
			return nil, fmt.Errorf("handoff target ids must be unique")
		}
		seenTargets[targetID] = struct{}{}
		admitted["targetId"] = targetID
		anchor := admitted["anchor"].(map[string]any)
		requirementIDs[anchor["requirementId"].(string)] = struct{}{}
		annotations = append(annotations, admitted)
	}
	orderedRequirementIDs := make([]string, 0, len(requirementIDs))
	for requirementID := range requirementIDs {
		orderedRequirementIDs = append(orderedRequirementIDs, requirementID)
	}
	sort.Strings(orderedRequirementIDs)
	selectedRequirementIDs := make([]any, len(orderedRequirementIDs))
	for index, requirementID := range orderedRequirementIDs {
		selectedRequirementIDs[index] = requirementID
	}
	slice, err := requirementcontext.Slice(map[string]any{
		"context":       session.ContextValue,
		"query":         map[string]any{"maxNodes": json.Number("4096"), "maxRequirements": json.Number("16384"), "profile": "review", "requirementIds": selectedRequirementIDs},
		"schemaVersion": json.Number("1"),
		"sliceId":       "browser.handoff.context",
	})
	if err != nil {
		return nil, err
	}
	contextBytes, err := stablejson.Marshal(slice)
	if err != nil || len(contextBytes) > maxHandoffContextBytes {
		return nil, fmt.Errorf("handoff review context exceeds byte limit")
	}
	packet := map[string]any{
		"annotations":          annotations,
		"context":              slice,
		"handoffKind":          "proofkit.requirement-browser-question",
		"instructionAuthority": "browser_session_submission",
		"nonClaims":            admit.StringSliceToAny(serverNonClaims),
		"schemaVersion":        json.Number("1"),
		"snapshotRefs":         []any{map[string]any{"role": "current", "snapshotId": session.SnapshotID}},
		"sourceTextAuthority":  "untrusted_context",
		"state":                "submitted",
	}
	findings, err := secretjson.Scan(packet, "browser_handoff")
	if err != nil || len(findings) > 0 {
		return nil, fmt.Errorf("handoff packet contains secret-shaped data")
	}
	encoded, err := stablejson.Marshal(packet)
	if err != nil || len(encoded) > maxHandoffPacketBytes {
		return nil, fmt.Errorf("handoff packet exceeds byte limit")
	}
	return packet, nil
}

func handoffTargetID(annotation map[string]any) (string, error) {
	identity := map[string]any{
		"anchor":         annotation["anchor"],
		"endCodePoint":   annotation["endCodePoint"],
		"exactQuote":     annotation["exactQuote"],
		"prefix":         annotation["prefix"],
		"startCodePoint": annotation["startCodePoint"],
		"suffix":         annotation["suffix"],
	}
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		return "", err
	}
	return digest.SHA256TextRef(string(encoded)), nil
}

func admitAnnotation(annotation map[string]any, session workspaceSession) (map[string]any, error) {
	if err := admit.KnownKeys(annotation, []string{"anchorId", "endCodePoint", "exactQuote", "question", "startCodePoint"}, "browser handoff annotation"); err != nil {
		return nil, err
	}
	anchorID, err := admit.RuleID(annotation["anchorId"], "browser handoff anchorId")
	if err != nil {
		return nil, err
	}
	anchor, ok := session.Anchors[anchorID]
	if !ok {
		return nil, fmt.Errorf("handoff references unknown anchor")
	}
	quote, ok := annotation["exactQuote"].(string)
	if !ok || strings.TrimSpace(quote) == "" || len([]byte(quote)) > maxHandoffQuoteBytes || admit.ContainsSecretLikeValue(quote) {
		return nil, fmt.Errorf("handoff quote is invalid")
	}
	start, err := nonNegativeJSONInteger(annotation["startCodePoint"], "browser handoff startCodePoint")
	if err != nil {
		return nil, err
	}
	end, err := nonNegativeJSONInteger(annotation["endCodePoint"], "browser handoff endCodePoint")
	anchorRunes := []rune(anchor.Text)
	if err != nil || start >= end || end > len(anchorRunes) || string(anchorRunes[start:end]) != quote {
		return nil, fmt.Errorf("handoff quote does not resolve inside anchor")
	}
	question, err := admit.NonEmptyText(annotation["question"], "browser handoff question")
	if err != nil {
		return nil, err
	}
	if len([]byte(question)) > maxHandoffQuestionBytes {
		return nil, fmt.Errorf("browser handoff question exceeds byte limit")
	}
	prefixStart := max(0, start-32)
	suffixEnd := min(len(anchorRunes), end+32)
	return map[string]any{"anchor": anchorValue(anchor), "endCodePoint": end, "exactQuote": quote, "prefix": string(anchorRunes[prefixStart:start]), "question": question, "startCodePoint": start, "suffix": string(anchorRunes[end:suffixEnd])}, nil
}

func nonNegativeJSONInteger(raw any, context string) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	value, err := strconv.Atoi(number.String())
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	return value, nil
}

func positiveJSONInteger(raw any, context string) (int, error) {
	value, err := nonNegativeJSONInteger(raw, context)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	return value, nil
}
