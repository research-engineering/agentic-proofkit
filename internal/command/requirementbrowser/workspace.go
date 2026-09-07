package requirementbrowser

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const workspaceCapabilityPlaceholder = "PROOFKIT_BROWSER_CAPABILITY_PLACEHOLDER"

type workspaceAnchor struct {
	AnchorID      string
	JSONPointer   string
	RequirementID string
	SourceDigest  string
	Text          string
}

type workspaceSession struct {
	Anchors    map[string]workspaceAnchor
	Diff       map[string]any
	Graph      map[string]any
	Manifest   map[string]any
	Lookup     workspaceLookupIndex
	Snapshot   requirementcontext.Snapshot
	SnapshotID string
}

func buildWorkspace(raw any) (workspaceSession, string, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return workspaceSession{}, "", fmt.Errorf("requirement browser workspace input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"context", "diffInput", "graphInput", "schemaVersion", "workspaceId"}, "requirement browser workspace input"); err != nil {
		return workspaceSession{}, "", err
	}
	if err := admitWorkspaceInputVersion(record); err != nil {
		return workspaceSession{}, "", err
	}
	workspaceID, err := admit.RuleID(record["workspaceId"], "requirement browser workspaceId")
	if err != nil {
		return workspaceSession{}, "", err
	}
	snapshot, err := requirementcontext.AdmitSnapshot(record["context"])
	if err != nil {
		return workspaceSession{}, "", err
	}
	var diff map[string]any
	if record["diffInput"] != nil {
		diff, err = requirementdiff.Build(record["diffInput"])
		if err != nil {
			return workspaceSession{}, "", err
		}
	}
	var graph map[string]any
	if record["graphInput"] != nil {
		graph, err = requirementgraph.Build(record["graphInput"])
		if err != nil {
			return workspaceSession{}, "", err
		}
	}
	return prepareWorkspace(workspaceID, snapshot, diff, graph, workspaceHTML)
}

func prepareWorkspace(workspaceID string, snapshot requirementcontext.Snapshot, diff, graph map[string]any, document func(string) string) (workspaceSession, string, error) {
	var err error
	if diff != nil {
		if diff["currentSnapshotId"] != snapshot.SnapshotID {
			return workspaceSession{}, "", fmt.Errorf("requirement browser diff input current context must equal workspace context")
		}
		diff, err = requirementdiff.AdmitOutput(diff, snapshot.SnapshotID)
		if err != nil {
			return workspaceSession{}, "", err
		}
	}
	if graph != nil {
		if graph["snapshotId"] != snapshot.SnapshotID {
			return workspaceSession{}, "", fmt.Errorf("requirement browser graph input context must equal workspace context")
		}
		graph, err = requirementgraph.AdmitOutput(graph, snapshot.SnapshotID)
		if err != nil {
			return workspaceSession{}, "", err
		}
		if err := validateGraphSnapshotClosure(snapshot, graph); err != nil {
			return workspaceSession{}, "", err
		}
	}
	lookup, anchors := buildWorkspaceLookupIndex(snapshot)
	manifest := map[string]any{
		"authority":              "presentation_adapter",
		"availableViews":         []any{"specifications", "coverage", "diff", "graph"},
		"coverageAvailable":      snapshot.Coverage != nil,
		"diffAvailable":          diff != nil,
		"expectedDigestCoverage": snapshot.ExpectedDigestCoverage,
		"graphAvailable":         graph != nil,
		"nonClaims":              admit.StringSliceToAny(serverNonClaims),
		"requirementCount":       len(lookup.Rows),
		"lookupFacets":           map[string]any{"ownerIds": workspaceSortedSet(lookup.Owners), "lifecycleStates": workspaceSortedSet(lookup.LifecycleStates)},
		"schemaVersion":          json.Number("2"),
		"snapshotId":             snapshot.SnapshotID,
		"workspaceId":            workspaceID,
	}
	return workspaceSession{Anchors: anchors, Diff: diff, Graph: graph, Manifest: manifest, Lookup: lookup, Snapshot: snapshot, SnapshotID: snapshot.SnapshotID}, document(workspaceID), nil
}

func admitWorkspaceInputVersion(record map[string]any) error {
	switch {
	case admit.JSONNumberEquals(record["schemaVersion"], 1):
		return admitV1WorkspaceInput(record)
	case admit.JSONNumberEquals(record["schemaVersion"], 2):
		return requireWorkspaceNestedVersions(record, 2)
	default:
		return fmt.Errorf("requirement browser workspace schemaVersion must be 1 or 2")
	}
}

func requireWorkspaceNestedVersions(record map[string]any, expected int) error {
	contextRecord, ok := record["context"].(map[string]any)
	if !ok || !admit.JSONNumberEquals(contextRecord["schemaVersion"], int64(expected)) {
		return fmt.Errorf("requirement browser workspace schemaVersion %d requires context schemaVersion %d", expected, expected)
	}
	if rawDiff := record["diffInput"]; rawDiff != nil {
		diff, ok := rawDiff.(map[string]any)
		if !ok || !admit.JSONNumberEquals(diff["schemaVersion"], int64(expected)) {
			return fmt.Errorf("requirement browser workspace schemaVersion %d requires diffInput schemaVersion %d", expected, expected)
		}
	}
	if rawGraph := record["graphInput"]; rawGraph != nil {
		graph, ok := rawGraph.(map[string]any)
		if !ok || !admit.JSONNumberEquals(graph["schemaVersion"], 2) {
			return fmt.Errorf("requirement browser workspace graphInput schemaVersion must be 2")
		}
		graphContext, ok := graph["context"].(map[string]any)
		if !ok || !admit.JSONNumberEquals(graphContext["schemaVersion"], int64(expected)) {
			return fmt.Errorf("requirement browser workspace schemaVersion %d requires graphInput context schemaVersion %d", expected, expected)
		}
	}
	return nil
}

func validateGraphSnapshotClosure(snapshot requirementcontext.Snapshot, graph map[string]any) error {
	expectedSpecs := map[string]struct{}{}
	for _, node := range snapshot.Tree.Nodes {
		expectedSpecs["spec:"+node.NodeID] = struct{}{}
	}
	expectedRequirements := map[string]struct{}{}
	for _, source := range snapshot.RequirementSources {
		for _, requirement := range source.Requirements {
			expectedRequirements["requirement:"+requirement.RequirementID] = struct{}{}
		}
	}
	expectedProof := map[string]struct{}{}
	if snapshot.ProofBinding != nil {
		for _, binding := range snapshot.ProofBinding.Bindings {
			expectedProof[proofClosureKey(binding.RequirementID, binding.ScenarioID, binding.WitnessID, binding.WitnessKind, binding.WitnessPath)] = struct{}{}
		}
	}
	actualSpecs := map[string]struct{}{}
	actualRequirements := map[string]struct{}{}
	actualProof := map[string]struct{}{}
	for _, raw := range graph["nodes"].([]any) {
		node := raw.(map[string]any)
		switch node["evidencePlane"] {
		case "specification_coverage":
			if node["kind"] == "requirement" {
				actualRequirements[node["nodeId"].(string)] = struct{}{}
			} else {
				actualSpecs[node["nodeId"].(string)] = struct{}{}
			}
		case "proof_coverage":
			actualProof[proofClosureKey(node["requirementId"].(string), node["scenarioId"].(string), node["witnessId"].(string), node["witnessKind"].(string), node["witnessPath"].(string))] = struct{}{}
		}
	}
	if !sameStringSet(expectedSpecs, actualSpecs) || !sameStringSet(expectedRequirements, actualRequirements) || !sameStringSet(expectedProof, actualProof) {
		return fmt.Errorf("requirement browser graph does not close over the admitted context")
	}
	return nil
}

func proofClosureKey(values ...string) string {
	return strings.Join(values, "\x00")
}

func sameStringSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, ok := right[value]; !ok {
			return false
		}
	}
	return true
}

func anchorValue(anchor workspaceAnchor) map[string]any {
	return map[string]any{"anchorId": anchor.AnchorID, "jsonPointer": anchor.JSONPointer, "requirementId": anchor.RequirementID, "sourceDigest": anchor.SourceDigest}
}

func workspaceHTML(workspaceID string) string {
	return strings.Join([]string{
		"<!doctype html>",
		"<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
		"<meta name=\"proofkit-browser-capability\" content=\"" + workspaceCapabilityPlaceholder + "\">",
		"<title>" + html.EscapeString(workspaceID) + " - Proofkit workspace</title>",
		"<link rel=\"stylesheet\" href=\"/assets/workspace.css\"></head>",
		`<body data-state="bootstrap-loading"><header class="product-bar">
<button id="open-navigation" class="icon-button" type="button" data-open-panel="navigation" data-icon="panel-left" aria-label="Toggle specification navigation" title="Toggle specification navigation" aria-controls="workspace-navigation" aria-expanded="false"></button>
<div class="product-identity"><strong>Proofkit</strong><h1>` + html.EscapeString(workspaceID) + `</h1></div>
<button id="open-inspector" class="icon-button" type="button" data-open-panel="inspector" data-icon="panel-right" aria-label="Toggle question inspector" title="Toggle question inspector" aria-controls="workspace-inspector" aria-expanded="false"></button></header>
<dialog id="workspace-navigation" class="workspace-panel" aria-labelledby="navigation-heading"><div class="panel-heading"><h2 id="navigation-heading">Browse</h2><button class="icon-button" type="button" data-close-panel data-icon="x" aria-label="Close navigation" title="Close navigation"></button></div>
<form id="workspace-search" role="search"><label for="requirement-search">Search requirements</label><div class="search-field"><input id="requirement-search" type="search" autocomplete="off" data-protected-request disabled><button class="icon-button" type="submit" data-icon="search" aria-label="Search requirements" title="Search requirements" data-protected-request disabled></button></div>
<label for="requirement-owner">Owner</label><select id="requirement-owner" data-protected-request disabled><option value="">All owners</option></select>
<label for="requirement-lifecycle">Lifecycle</label><select id="requirement-lifecycle" data-protected-request disabled><option value="">All lifecycle states</option></select>
<button id="reset-filters" type="button" data-protected-request disabled>Reset filters</button></form>
<section id="selected-scope" aria-label="Selected specification scope"></section><h3>Specification hierarchy</h3><button id="all-requirements" type="button" data-protected-request disabled>All requirements</button>
<div id="spec-navigation" aria-live="polite"></div></dialog>
<main><nav class="view-controls" aria-label="Workspace views"><button type="button" data-view="specifications" data-protected-request data-icon="file-text" disabled>Specifications</button><button type="button" data-view="coverage" data-protected-request data-icon="check" disabled>Coverage</button><button type="button" data-view="diff" data-protected-request data-icon="git-compare-arrows" disabled>Diff</button><button type="button" data-view="graph" data-protected-request data-icon="network" disabled>Traceability</button></nav>
<details id="workspace-authority" aria-label="Authority boundary"><summary data-icon="info">Derived view</summary><h2>Authority boundary</h2><p data-authority>Loading admitted authority...</p><ul data-non-claims></ul></details>
<section id="workspace-content" aria-busy="true"><h2>Loading workspace</h2><p role="status" aria-live="polite">Loading admitted manifest...</p></section></main>
<dialog id="workspace-inspector" class="workspace-panel" aria-labelledby="inspector-heading"><div class="panel-heading"><h2 id="inspector-heading">Ask about selection</h2><button class="icon-button" type="button" data-close-panel data-icon="x" aria-label="Close inspector" title="Close inspector"></button></div>
<h3>Selected source text</h3><ul id="selected-context" aria-label="Selected source text"></ul><button id="clear-selection" class="icon-button" type="button" data-icon="x" aria-label="Clear selection" title="Clear selection" disabled></button>
<label for="annotation-question">Question</label><textarea id="annotation-question" maxlength="4096"></textarea><button id="submit-question" type="button" data-protected-request data-icon="message-square" disabled>Create handoff packet</button><p id="handoff-status" role="status" aria-live="polite"></p><section id="handoff-output" aria-labelledby="handoff-packet-heading"><h3 id="handoff-packet-heading">Handoff packet</h3><div id="handoff-preview"></div><details><summary>Exact JSON</summary><pre id="handoff-packet"></pre></details></section></dialog>`,
		"<script type=\"module\" src=\"/assets/workspace.js\"></script></body></html>\n",
	}, "")
}
