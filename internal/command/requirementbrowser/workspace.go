package requirementbrowser

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
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
	Anchors      map[string]workspaceAnchor
	ContextValue map[string]any
	Diff         map[string]any
	Graph        map[string]any
	Manifest     map[string]any
	Requirements []any
	SnapshotID   string
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
	anchors, requirements, err := workspaceRequirements(snapshot)
	if err != nil {
		return workspaceSession{}, "", err
	}
	var diff map[string]any
	if record["diffInput"] != nil {
		diff, err = requirementdiff.Build(record["diffInput"])
		if err != nil {
			return workspaceSession{}, "", err
		}
		if diff["currentSnapshotId"] != snapshot.SnapshotID {
			return workspaceSession{}, "", fmt.Errorf("requirement browser diff input current context must equal workspace context")
		}
		diff, err = requirementdiff.AdmitOutput(diff, snapshot.SnapshotID)
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
	manifest := map[string]any{
		"authority":              "presentation_adapter",
		"availableViews":         []any{"specifications", "diff", "graph"},
		"diffAvailable":          diff != nil,
		"expectedDigestCoverage": snapshot.ExpectedDigestCoverage,
		"graphAvailable":         graph != nil,
		"nonClaims":              admit.StringSliceToAny(serverNonClaims),
		"requirementCount":       len(requirements),
		"schemaVersion":          json.Number("2"),
		"snapshotId":             snapshot.SnapshotID,
		"workspaceId":            workspaceID,
	}
	return workspaceSession{Anchors: anchors, ContextValue: requirementcontext.SnapshotValue(snapshot), Diff: diff, Graph: graph, Manifest: manifest, Requirements: requirements, SnapshotID: snapshot.SnapshotID}, workspaceHTML(workspaceID), nil
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

func workspaceRequirements(snapshot requirementcontext.Snapshot) (map[string]workspaceAnchor, []any, error) {
	rawSources, ok := snapshot.Projections["requirementSources"].([]any)
	if !ok {
		return nil, nil, fmt.Errorf("requirement browser workspace requires requirement source projections")
	}
	digestBySource := map[string]string{}
	for _, source := range snapshot.Sources {
		if source.Kind == "requirement_source" {
			digestBySource[source.SourceRef] = source.CurrentDigest
		}
	}
	anchors := map[string]workspaceAnchor{}
	requirements := []any{}
	for sourceIndex, rawSource := range rawSources {
		source, ok := rawSource.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("requirement browser workspace source projection is invalid")
		}
		sourceID, _ := source["sourceId"].(string)
		digest := digestBySource[sourceID]
		rawRequirements, ok := source["requirements"].([]any)
		if !ok {
			return nil, nil, fmt.Errorf("requirement browser workspace requirements projection is invalid")
		}
		for requirementIndex, rawRequirement := range rawRequirements {
			requirement, ok := rawRequirement.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("requirement browser workspace requirement projection is invalid")
			}
			id, _ := requirement["requirementId"].(string)
			invariant, _ := requirement["invariant"].(string)
			anchorID := "requirement:" + id + ":invariant"
			anchor := workspaceAnchor{AnchorID: anchorID, JSONPointer: fmt.Sprintf("/projections/requirementSources/%d/requirements/%d/invariant", sourceIndex, requirementIndex), RequirementID: id, SourceDigest: digest, Text: invariant}
			anchors[anchorID] = anchor
			requirements = append(requirements, map[string]any{
				"anchor":          anchorValue(anchor),
				"claimLevel":      requirement["claimLevel"],
				"invariant":       invariant,
				"nonClaims":       requirement["nonClaims"],
				"ownerId":         requirement["ownerId"],
				"requirementId":   id,
				"sourceNonClaims": source["nonClaims"],
			})
		}
	}
	sort.Slice(requirements, func(left, right int) bool {
		return requirements[left].(map[string]any)["requirementId"].(string) < requirements[right].(map[string]any)["requirementId"].(string)
	})
	return anchors, requirements, nil
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
		"<body data-state=\"bootstrap-loading\"><header><p>Proofkit semantic workspace</p><h1>" + html.EscapeString(workspaceID) + "</h1><section id=\"workspace-authority\" aria-label=\"Authority boundary\"><h2>Authority boundary</h2><p data-authority>Loading admitted authority...</p><ul data-non-claims></ul></section></header>",
		"<main><nav aria-label=\"Workspace views\"><button type=\"button\" data-view=\"specifications\" disabled>Specifications</button><button type=\"button\" data-view=\"diff\" disabled>Diff</button><button type=\"button\" data-view=\"graph\" disabled>Traceability</button></nav>",
		"<section id=\"workspace-content\" aria-busy=\"true\"><h2>Loading workspace</h2><p role=\"status\" aria-live=\"polite\">Loading admitted manifest...</p></section></main>",
		"<aside aria-label=\"Agent question\"><h2>Ask about selection</h2><h3>Selected source text</h3><ul id=\"selected-context\" aria-label=\"Selected source text\"></ul><button id=\"clear-selection\" type=\"button\" disabled>Clear selection</button><label for=\"annotation-question\">Question</label><textarea id=\"annotation-question\" maxlength=\"4096\"></textarea><button id=\"submit-question\" type=\"button\">Create handoff packet</button><p id=\"handoff-status\" role=\"status\" aria-live=\"polite\"></p><section id=\"handoff-output\" aria-labelledby=\"handoff-packet-heading\"><h3 id=\"handoff-packet-heading\">Handoff packet</h3><pre id=\"handoff-packet\"></pre></section></aside>",
		"<script type=\"module\" src=\"/assets/workspace.js\"></script></body></html>\n",
	}, "")
}
