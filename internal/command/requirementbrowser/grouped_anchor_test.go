package requirementbrowser

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func TestGroupedAnchorResolvesUnicodeQuoteAcrossStemAndCompletion(t *testing.T) {
	fixture := workspaceFixture(t)
	context := fixture["context"].(map[string]any)
	source := context["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
	group := source["groups"].([]any)[0].(map[string]any)
	group["statementStem"] = "State \U0001f9ed"
	group["sharedPremises"] = []any{"Only an authenticated caller enters this operation."}
	first := workspaceSourceMember(context)
	first["statementCompletion"] = "e\u0301 remains explicit."
	second := cloneWorkspaceRecord(t, first)
	second["requirementId"], second["statementCompletion"] = "REQ-CONSUMER-002", "preserves the second contract."
	group["members"] = []any{second, first}
	other := cloneWorkspaceRecord(t, group)
	other["groupId"], other["statementStem"] = "RGRP-OTHER", ""
	third := cloneWorkspaceRecord(t, first)
	third["requirementId"], third["statementCompletion"] = "REQ-CONSUMER-003", "The independent contract remains explicit."
	other["members"] = []any{third}
	source["groups"] = []any{other, group}
	resignWorkspaceSnapshot(t, context)
	workspace, _, err := buildWorkspace(fixture)
	if err != nil {
		t.Fatal(err)
	}
	const anchorID = "requirement:REQ-CONSUMER-001:invariant"
	anchor := anchorValue(workspace.Anchors[anchorID])
	wantAnchor := map[string]any{
		"anchorId": anchorID, "coordinateSpace": "resolved_requirement", "jsonPointer": "/invariant",
		"sourceId": "consumer.requirements", "requirementId": "REQ-CONSUMER-001",
		"sourceDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if !reflect.DeepEqual(anchor, wantAnchor) {
		t.Fatalf("grouped anchor lost explicit coordinate identity: %#v", anchor)
	}
	// Same source, reverse physical group order: no positional identity may leak
	// into the resolved anchor or the canonical snapshot.
	source = context["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
	groups := source["groups"].([]any)
	groups[0], groups[1] = groups[1], groups[0]
	resignWorkspaceSnapshot(t, context)
	reordered, _, err := buildWorkspace(fixture)
	if err != nil || workspace.SnapshotID != reordered.SnapshotID || !reflect.DeepEqual(anchorValue(reordered.Anchors[anchorID]), wantAnchor) {
		t.Fatalf("group order changed semantic anchor: %v", err)
	}
	handle, capability := startWorkspaceTestServer(t, fixture, false)
	query := map[string]any{"requestId": "grouped.lookup", "snapshotId": handle.SnapshotID, "query": map[string]any{"searchText": "authenticated"}}
	lookup := projectHTTP(t, handle, capability, "requirements", query, http.StatusOK)
	rows := lookup["projection"].(map[string]any)["requirements"].([]any)
	if len(rows) != 3 || !reflect.DeepEqual(rows[0].(map[string]any)["sharedPremises"], group["sharedPremises"]) {
		t.Fatal("shared conditions were lost from lookup or search")
	}
	packet := projectHTTP(t, handle, capability, "handoff", map[string]any{"annotations": []any{map[string]any{
		"anchorId": anchorID, "startCodePoint": json.Number("6"), "endCodePoint": json.Number("10"),
		"exactQuote": "\U0001f9ed e\u0301", "question": "Does the shared statement preserve this invariant?",
	}}}, http.StatusOK)
	if packet["schemaVersion"] != json.Number("2") {
		t.Fatal("handoff did not version its new coordinate space")
	}
	annotation := packet["annotations"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(annotation["anchor"], wantAnchor) || annotation["exactQuote"] != "\U0001f9ed e\u0301" || annotation["prefix"] != "State " {
		t.Fatal("full-text Unicode quote across group/member boundary was altered")
	}
	fragments := packet["context"].(map[string]any)["projections"].(map[string]any)["requirementSources"].([]any)
	if len(fragments) != 1 || fragments[0].(map[string]any)["sourceId"] != "consumer.requirements" {
		t.Fatal("handoff does not uniquely identify its resolved source")
	}
	selected := fragments[0].(map[string]any)["requirements"].([]any)
	if len(selected) != 1 || selected[0].(map[string]any)["requirementId"] != "REQ-CONSUMER-001" {
		t.Fatal("handoff does not uniquely identify its resolved requirement")
	}
	resolved, err := jsonpointer.Select(selected[0], anchor["jsonPointer"].(string))
	if err != nil || resolved != "State \U0001f9ed e\u0301 remains explicit." {
		t.Fatalf("packet-local resolved pointer lost full invariant: %v, %v", resolved, err)
	}
}
