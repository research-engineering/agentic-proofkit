package requirementspectree

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestBuildAdmitsSpecTree(t *testing.T) {
	record, exitCode, err := Build(validTreeInput())
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 || record.State != "passed" || record.ReportKind != reportKind {
		t.Fatalf("unexpected pass result exit=%d state=%s kind=%s", exitCode, record.State, record.ReportKind)
	}
	if containsAny(record.NonClaims, "Caller tree fixture is display-only.") {
		t.Fatalf("caller non-claim leaked into boundary nonClaims: %#v", record.NonClaims)
	}
	if !recordJSONContains(t, record, `"callerNonClaims"`) {
		t.Fatalf("report diagnostics must preserve caller non-claims")
	}
}

func TestBuildRejectsDAGAndStaleDigest(t *testing.T) {
	input := validTreeInput()
	edges := input["edges"].([]any)
	input["edges"] = append(edges, map[string]any{"parentNodeId": "meta", "childNodeId": "submodule"})
	sourceRefMap(input, "submodule", "source.submodule")["currentSourceDigest"] = digestB()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 1 || record.State != "failed" {
		t.Fatalf("unexpected failed result exit=%d state=%s", exitCode, record.State)
	}
	assertFailure(t, record, "source_ref.stale_digest:source.submodule")
	assertFailure(t, record, "topology.multi_parent:submodule")
}

func TestBuildRejectsTopologyFalsifiers(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		failure string
	}{
		{
			name: "duplicate node",
			mutate: func(input map[string]any) {
				input["nodes"] = append(input["nodes"].([]any), nodeRecord("module", "module_spec", "Duplicate module", 2, sourceIDRef("source.duplicate", "spec.duplicate")))
			},
			failure: "topology.duplicate_node:module",
		},
		{
			name: "missing root",
			mutate: func(input map[string]any) {
				input["rootNodeId"] = "missing.root"
			},
			failure: "topology.missing_root:missing.root",
		},
		{
			name: "duplicate edge",
			mutate: func(input map[string]any) {
				input["edges"] = append(input["edges"].([]any), map[string]any{"parentNodeId": "meta", "childNodeId": "module"})
			},
			failure: "topology.duplicate_edge:meta->module",
		},
		{
			name: "missing edge child endpoint",
			mutate: func(input map[string]any) {
				input["edges"] = append(input["edges"].([]any), map[string]any{"parentNodeId": "module", "childNodeId": "missing.node"})
			},
			failure: "topology.missing_edge_child:missing.node",
		},
		{
			name: "missing edge parent endpoint",
			mutate: func(input map[string]any) {
				input["edges"] = append(input["edges"].([]any), map[string]any{"parentNodeId": "missing.parent", "childNodeId": "submodule"})
			},
			failure: "topology.missing_edge_parent:missing.parent",
		},
		{
			name: "root parentage",
			mutate: func(input map[string]any) {
				input["edges"] = append(input["edges"].([]any), map[string]any{"parentNodeId": "submodule", "childNodeId": "meta"})
			},
			failure: "topology.root_has_parent:meta",
		},
		{
			name: "cycle",
			mutate: func(input map[string]any) {
				input["edges"] = []any{
					map[string]any{"parentNodeId": "meta", "childNodeId": "module"},
					map[string]any{"parentNodeId": "module", "childNodeId": "submodule"},
					map[string]any{"parentNodeId": "submodule", "childNodeId": "module"},
				}
			},
			failure: "topology.cycle:module",
		},
		{
			name: "missing parent",
			mutate: func(input map[string]any) {
				input["edges"] = []any{
					map[string]any{"parentNodeId": "meta", "childNodeId": "module"},
				}
			},
			failure: "topology.missing_parent:submodule",
		},
		{
			name: "disconnected alternate root",
			mutate: func(input map[string]any) {
				input["nodes"] = append(input["nodes"].([]any), nodeRecord("alternate", "module_spec", "Alternate", 4, sourceIDRef("source.alternate", "spec.alternate")))
			},
			failure: "topology.missing_parent:alternate",
		},
		{
			name: "unreachable node",
			mutate: func(input map[string]any) {
				input["nodes"] = append(input["nodes"].([]any), nodeRecord("orphan", "module_spec", "Orphan", 4, sourceIDRef("source.orphan", "spec.orphan")))
			},
			failure: "topology.unreachable_node:orphan",
		},
		{
			name: "sibling display order collision",
			mutate: func(input map[string]any) {
				input["nodes"] = append(input["nodes"].([]any), nodeRecord("sibling", "module_spec", "Sibling", 1, sourceIDRef("source.sibling", "spec.sibling")))
				input["edges"] = append(input["edges"].([]any), map[string]any{"parentNodeId": "meta", "childNodeId": "sibling"})
			},
			failure: "topology.sibling_display_order_collision:meta:module:sibling",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validTreeInput()
			item.mutate(input)
			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}
			if exitCode != 1 || record.State != "failed" {
				t.Fatalf("unexpected result exit=%d state=%s", exitCode, record.State)
			}
			assertFailure(t, record, item.failure)
		})
	}
}

func TestBuildRejectsSourceRefAdmissionAndSemanticFalsifiers(t *testing.T) {
	errorCases := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{
			name: "missing source id",
			mutate: func(input map[string]any) {
				delete(sourceRefMap(input, "meta", "source.meta"), "sourceId")
			},
			wantErr: "sourceId",
		},
		{
			name: "source id with path surplus",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "meta", "source.meta")["sourcePath"] = "docs/specs/meta/requirements.v1.json"
			},
			wantErr: "source_id must not include path or digest fields",
		},
		{
			name: "source id with recorded digest surplus",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "meta", "source.meta")["recordedSourceDigest"] = digestA()
			},
			wantErr: "source_id must not include path or digest fields",
		},
		{
			name: "source id with current digest surplus",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "meta", "source.meta")["currentSourceDigest"] = digestA()
			},
			wantErr: "source_id must not include path or digest fields",
		},
		{
			name: "source id with algorithm surplus",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "meta", "source.meta")["digestAlgorithm"] = "sha256"
			},
			wantErr: "source_id must not include path or digest fields",
		},
		{
			name: "unsupported source ref kind",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "meta", "source.meta")["sourceRefKind"] = "scan_repo"
			},
			wantErr: "sourceRefKind",
		},
		{
			name: "path digest missing path",
			mutate: func(input map[string]any) {
				delete(sourceRefMap(input, "submodule", "source.submodule"), "sourcePath")
			},
			wantErr: "sourcePath",
		},
		{
			name: "path digest missing recorded digest",
			mutate: func(input map[string]any) {
				delete(sourceRefMap(input, "submodule", "source.submodule"), "recordedSourceDigest")
			},
			wantErr: "recordedSourceDigest",
		},
		{
			name: "path digest missing current digest",
			mutate: func(input map[string]any) {
				delete(sourceRefMap(input, "submodule", "source.submodule"), "currentSourceDigest")
			},
			wantErr: "currentSourceDigest",
		},
		{
			name: "path digest missing algorithm",
			mutate: func(input map[string]any) {
				delete(sourceRefMap(input, "submodule", "source.submodule"), "digestAlgorithm")
			},
			wantErr: "digestAlgorithm",
		},
		{
			name: "path digest invalid algorithm",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "submodule", "source.submodule")["digestAlgorithm"] = "md5"
			},
			wantErr: "must be sha256",
		},
		{
			name: "path digest has source id",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "submodule", "source.submodule")["sourceId"] = "spec.submodule"
			},
			wantErr: "path_digest must not include sourceId",
		},
		{
			name: "invalid digest",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "submodule", "source.submodule")["recordedSourceDigest"] = "sha256:nothex"
			},
			wantErr: "sha256 digest",
		},
		{
			name: "unsafe path",
			mutate: func(input map[string]any) {
				sourceRefMap(input, "submodule", "source.submodule")["sourcePath"] = "../requirements.v1.json"
			},
			wantErr: "repository root",
		},
	}
	for _, item := range errorCases {
		t.Run(item.name, func(t *testing.T) {
			input := validTreeInput()
			item.mutate(input)
			if _, _, err := Build(input); err == nil {
				t.Fatalf("expected admission error")
			} else if !strings.Contains(err.Error(), item.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), item.wantErr)
			}
		})
	}

	input := validTreeInput()
	sourceRefMap(input, "module", "source.module")["sourceRefId"] = "source.meta"
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 1 || record.State != "failed" {
		t.Fatalf("unexpected result exit=%d state=%s", exitCode, record.State)
	}
	assertFailure(t, record, "source_ref.duplicate_id:source.meta")
}

func TestBuildRejectsOverlayFalsifiers(t *testing.T) {
	semanticCases := []struct {
		name    string
		mutate  func(map[string]any)
		failure string
	}{
		{
			name: "duplicate overlay",
			mutate: func(input map[string]any) {
				input["overlays"] = append(input["overlays"].([]any), overlayRecord("overlay.source.module", "module", "source.module"))
			},
			failure: "overlay.duplicate_id:overlay.source.module",
		},
		{
			name: "unknown target node",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["targetNodeId"] = "missing.node"
			},
			failure: "overlay.unknown_target_node:overlay.source.module:missing.node",
		},
		{
			name: "unknown source ref",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["refId"] = "source.missing"
			},
			failure: "overlay.unknown_source_ref:overlay.source.module:source.missing",
		},
	}
	for _, item := range semanticCases {
		t.Run(item.name, func(t *testing.T) {
			input := validTreeInput()
			item.mutate(input)
			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}
			if exitCode != 1 || record.State != "failed" {
				t.Fatalf("unexpected result exit=%d state=%s", exitCode, record.State)
			}
			assertFailure(t, record, item.failure)
		})
	}

	errorCases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "unsupported overlay kind",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["overlayKind"] = "merge"
			},
		},
		{
			name: "missing ref",
			mutate: func(input map[string]any) {
				delete(overlayMap(input, "overlay.source.module"), "refId")
			},
		},
		{
			name: "digest without path",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["refDigest"] = digestA()
			},
		},
		{
			name: "path without digest",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["refPath"] = "artifacts/source.html"
				overlayMap(input, "overlay.source.module")["digestAlgorithm"] = "sha256"
			},
		},
		{
			name: "path without algorithm",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["refPath"] = "artifacts/source.html"
				overlayMap(input, "overlay.source.module")["refDigest"] = digestA()
			},
		},
		{
			name: "invalid algorithm",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["refPath"] = "artifacts/source.html"
				overlayMap(input, "overlay.source.module")["refDigest"] = digestA()
				overlayMap(input, "overlay.source.module")["digestAlgorithm"] = "md5"
			},
		},
		{
			name: "invalid digest",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["refPath"] = "artifacts/source.html"
				overlayMap(input, "overlay.source.module")["refDigest"] = "sha256:nothex"
				overlayMap(input, "overlay.source.module")["digestAlgorithm"] = "sha256"
			},
		},
		{
			name: "unsafe path",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["refPath"] = "../source.html"
				overlayMap(input, "overlay.source.module")["refDigest"] = digestA()
				overlayMap(input, "overlay.source.module")["digestAlgorithm"] = "sha256"
			},
		},
		{
			name: "decision field",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["state"] = "passed"
			},
		},
		{
			name: "authority claim",
			mutate: func(input map[string]any) {
				overlayMap(input, "overlay.source.module")["callerNonClaims"] = []any{"This overlay proves freshness."}
			},
		},
	}
	for _, item := range errorCases {
		t.Run(item.name, func(t *testing.T) {
			input := validTreeInput()
			item.mutate(input)
			if _, _, err := Build(input); err == nil {
				t.Fatalf("expected admission error")
			}
		})
	}
}

func TestBuildRejectsAuthorityConfusingCallerNonClaims(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any, string)
		claim  string
	}{
		{
			name: "root merge approval",
			mutate: func(input map[string]any, claim string) {
				input["callerNonClaims"] = []any{claim}
			},
			claim: "This caller text claims merge approval.",
		},
		{
			name: "node release approval",
			mutate: func(input map[string]any, claim string) {
				nodeMap(input, "meta")["callerNonClaims"] = []any{claim}
			},
			claim: "This node text claims release approval.",
		},
		{
			name: "node rollout approval",
			mutate: func(input map[string]any, claim string) {
				nodeMap(input, "module")["callerNonClaims"] = []any{claim}
			},
			claim: "This node text claims rollout approval.",
		},
		{
			name: "overlay production readiness",
			mutate: func(input map[string]any, claim string) {
				overlayMap(input, "overlay.source.module")["callerNonClaims"] = []any{claim}
			},
			claim: "This overlay text claims production readiness.",
		},
		{
			name: "overlay proof freshness",
			mutate: func(input map[string]any, claim string) {
				overlayMap(input, "overlay.source.module")["callerNonClaims"] = []any{claim}
			},
			claim: "This overlay text claims proof freshness.",
		},
		{
			name: "overlay rendered authority",
			mutate: func(input map[string]any, claim string) {
				overlayMap(input, "overlay.source.module")["callerNonClaims"] = []any{claim}
			},
			claim: "This overlay text claims rendered view authority.",
		},
		{
			name: "overlay coverage completeness",
			mutate: func(input map[string]any, claim string) {
				overlayMap(input, "overlay.source.module")["callerNonClaims"] = []any{claim}
			},
			claim: "This overlay text claims coverage completeness.",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validTreeInput()
			item.mutate(input, item.claim)
			if _, _, err := Build(input); err == nil {
				t.Fatalf("expected authority-confusing admission error")
			} else if !strings.Contains(err.Error(), "authority-confusing claims") {
				t.Fatalf("error %q does not contain authority-confusing claims", err.Error())
			}
		})
	}
}

func TestBuildRejectsSchemaVersionDrift(t *testing.T) {
	cases := []struct {
		name   string
		value  any
		remove bool
	}{
		{name: "missing", remove: true},
		{name: "future", value: json.Number("2")},
		{name: "string", value: "1"},
		{name: "null", value: nil},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validTreeInput()
			if item.remove {
				delete(input, "schemaVersion")
			} else {
				input["schemaVersion"] = item.value
			}
			if _, _, err := Build(input); err == nil {
				t.Fatalf("expected schema admission error")
			}
		})
	}
}

func TestBuildOutputIsDeterministicForPermutedInput(t *testing.T) {
	left := validTreeInput()
	right := validTreeInput()
	reverseSlice(right["nodes"].([]any))
	reverseSlice(right["edges"].([]any))
	reverseSlice(right["overlays"].([]any))
	leftRecord, _, err := Build(left)
	if err != nil {
		t.Fatalf("left Build: %v", err)
	}
	rightRecord, _, err := Build(right)
	if err != nil {
		t.Fatalf("right Build: %v", err)
	}
	leftJSON, err := stablejson.Marshal(leftRecord.JSONValue())
	if err != nil {
		t.Fatalf("left marshal: %v", err)
	}
	rightJSON, err := stablejson.Marshal(rightRecord.JSONValue())
	if err != nil {
		t.Fatalf("right marshal: %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("permuted inputs produced different JSON\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
}

func TestBuildFailedOutputIsDeterministicAndSorted(t *testing.T) {
	left := invalidTreeInput()
	right := invalidTreeInput()
	reverseSlice(right["nodes"].([]any))
	reverseSlice(right["edges"].([]any))
	reverseSlice(right["overlays"].([]any))
	leftRecord, leftExit, err := Build(left)
	if err != nil {
		t.Fatalf("left Build: %v", err)
	}
	rightRecord, rightExit, err := Build(right)
	if err != nil {
		t.Fatalf("right Build: %v", err)
	}
	if leftExit != 1 || rightExit != 1 || leftRecord.State != "failed" || rightRecord.State != "failed" {
		t.Fatalf("expected failed reports, got left exit=%d state=%s right exit=%d state=%s", leftExit, leftRecord.State, rightExit, rightRecord.State)
	}
	leftJSON, err := stablejson.Marshal(leftRecord.JSONValue())
	if err != nil {
		t.Fatalf("left marshal: %v", err)
	}
	rightJSON, err := stablejson.Marshal(rightRecord.JSONValue())
	if err != nil {
		t.Fatalf("right marshal: %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("permuted invalid inputs produced different JSON\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
	assertSortedStrings(t, failureStrings(t, leftRecord), "top-level failures")
	for _, rule := range leftRecord.RuleResults {
		for _, diagnostic := range rule.Diagnostics {
			if diagnostic.Key == "failures" {
				assertSortedStrings(t, anyStrings(diagnostic.Value.([]any)), rule.RuleID+" failures")
			}
		}
	}
}

func TestBuildDoesNotAliasRawInput(t *testing.T) {
	input := validTreeInput()
	record, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	before, err := stablejson.Marshal(record.JSONValue())
	if err != nil {
		t.Fatalf("marshal before: %v", err)
	}
	input["treeId"] = "proofkit.spec_tree.mutated"
	input["callerNonClaims"].([]any)[0] = "Mutated root non-claim."
	input["edges"].([]any)[0].(map[string]any)["childNodeId"] = "mutated.child"
	nodeMap(input, "meta")["label"] = "Mutated"
	nodeMap(input, "meta")["callerNonClaims"].([]any)[0] = "Mutated node non-claim."
	overlayMap(input, "overlay.rendered.module")["label"] = "Mutated overlay"
	overlayMap(input, "overlay.rendered.module")["refPath"] = "artifacts/mutated.html"
	overlayMap(input, "overlay.rendered.module")["callerNonClaims"].([]any)[0] = "Mutated overlay non-claim."
	after, err := stablejson.Marshal(record.JSONValue())
	if err != nil {
		t.Fatalf("marshal after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("record aliases raw input\nbefore=%s\nafter=%s", before, after)
	}
}

func TestBuildViewRendersSpecTreeFromAdmittedInput(t *testing.T) {
	viewRaw, exitCode, err := BuildViewJSON(validTreeInput())
	if err != nil {
		t.Fatalf("BuildViewJSON returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildViewJSON exitCode=%d", exitCode)
	}
	view := viewRaw.(map[string]any)
	if view["viewKind"] != "proofkit.requirement-spec-tree-view" || view["authority"] != "presentation_only" {
		t.Fatalf("unexpected view identity: %#v", view)
	}
	nodes := view["nodes"].([]any)
	if len(nodes) != 3 {
		t.Fatalf("node count=%d want 3", len(nodes))
	}
	module := nodes[1].(map[string]any)
	if module["nodeId"] != "module" || module["parentNodeId"] != "meta" || module["depth"] != 2 {
		t.Fatalf("unexpected module projection: %#v", module)
	}
	if got := sourceRefIDs(module["sourceRefs"].([]any)); strings.Join(got, ",") != "source.module" {
		t.Fatalf("unexpected module source refs: %#v", got)
	}
	if got := overlayIDs(module["overlays"].([]any)); strings.Join(got, ",") != "overlay.rendered.module,overlay.source.module" {
		t.Fatalf("unexpected module overlays: %#v", got)
	}
}

func TestBuildViewFailsClosedForInvalidTree(t *testing.T) {
	_, exitCode, err := BuildViewJSON(invalidTreeInput())
	if err == nil || exitCode != 1 || !strings.Contains(err.Error(), "cannot build requirement spec tree view from failed requirement spec tree") {
		t.Fatalf("unexpected invalid view result exit=%d err=%v", exitCode, err)
	}
}

func TestBuildViewMarkdownAndHTMLAreDeterministicAndEscaped(t *testing.T) {
	input := validTreeInput()
	nodeMap(input, "module")["label"] = "Module <script>alert(1)</script>"
	overlayMap(input, "overlay.rendered.module")["label"] = "Rendered <img src=x onerror=alert(1)>"
	markdownOutput, markdownExit, err := BuildViewMarkdown(input)
	if err != nil || markdownExit != 0 {
		t.Fatalf("BuildViewMarkdown exit=%d err=%v", markdownExit, err)
	}
	if strings.Contains(markdownOutput, "<script>") || strings.Contains(markdownOutput, "<img") {
		t.Fatalf("markdown output contains raw structural payload:\n%s", markdownOutput)
	}
	if !strings.Contains(markdownOutput, "&lt;script&gt;alert\\(1\\)&lt;/script&gt;") {
		t.Fatalf("markdown output missing escaped payload:\n%s", markdownOutput)
	}
	leftHTML, leftExit, err := BuildViewHTML(input)
	if err != nil || leftExit != 0 {
		t.Fatalf("BuildViewHTML exit=%d err=%v", leftExit, err)
	}
	rightHTML, rightExit, err := BuildViewHTML(input)
	if err != nil || rightExit != 0 {
		t.Fatalf("BuildViewHTML second exit=%d err=%v", rightExit, err)
	}
	if leftHTML != rightHTML {
		t.Fatalf("HTML output is not byte-stable")
	}
	for _, forbidden := range []string{"<script>alert(1)</script>", "<img src=x"} {
		if strings.Contains(leftHTML, forbidden) {
			t.Fatalf("HTML output contains forbidden payload %q:\n%s", forbidden, leftHTML)
		}
	}
	for _, want := range []string{
		"Requirement Spec Tree View",
		"Specification tree",
		"data-proofkit-download",
		"Download Markdown",
		"Download HTML",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"Rendered &lt;img src=x onerror=alert(1)&gt;",
		"Caller tree fixture is display-only.",
		"Caller node fixture is display-only.",
		"Caller rendered overlay fixture is presentation only.",
		"docs/specs/submodule/requirements.v1.json",
		digestA(),
		"Requirement spec tree views do not prove coverage completeness",
	} {
		if !strings.Contains(leftHTML, want) {
			t.Fatalf("HTML output missing %q:\n%s", want, leftHTML)
		}
	}
	markdownExport := downloadContent(t, leftHTML, "proofkit.spec_tree.fixture.md")
	if markdownExport != markdownOutput {
		t.Fatalf("markdown export payload drifted\nwant=%s\ngot=%s", markdownOutput, markdownExport)
	}
	htmlExport := downloadContent(t, leftHTML, "proofkit.spec_tree.fixture.html")
	view, err := buildView(input)
	if err != nil {
		t.Fatalf("build expected view: %v", err)
	}
	expectedHTMLExport := html(view, nil)
	if htmlExport != expectedHTMLExport {
		t.Fatalf("HTML export payload drifted from the no-export view projection\nwant=%s\ngot=%s", expectedHTMLExport, htmlExport)
	}
}

func TestBuildViewJSONIsPermutationStable(t *testing.T) {
	left := validTreeInput()
	right := validTreeInput()
	reverseSlice(right["nodes"].([]any))
	reverseSlice(right["edges"].([]any))
	reverseSlice(right["overlays"].([]any))
	leftView, leftExit, err := BuildViewJSON(left)
	if err != nil || leftExit != 0 {
		t.Fatalf("left BuildViewJSON exit=%d err=%v", leftExit, err)
	}
	rightView, rightExit, err := BuildViewJSON(right)
	if err != nil || rightExit != 0 {
		t.Fatalf("right BuildViewJSON exit=%d err=%v", rightExit, err)
	}
	leftJSON, err := stablejson.Marshal(leftView)
	if err != nil {
		t.Fatalf("left marshal: %v", err)
	}
	rightJSON, err := stablejson.Marshal(rightView)
	if err != nil {
		t.Fatalf("right marshal: %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("permuted view inputs produced different JSON\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
}

func invalidTreeInput() map[string]any {
	input := validTreeInput()
	input["edges"] = append(input["edges"].([]any), map[string]any{"parentNodeId": "meta", "childNodeId": "submodule"})
	sourceRefMap(input, "submodule", "source.submodule")["currentSourceDigest"] = digestB()
	overlayMap(input, "overlay.source.module")["refId"] = "source.missing"
	return input
}

func validTreeInput() map[string]any {
	return map[string]any{
		"schemaVersion":   json.Number("1"),
		"treeId":          "proofkit.spec_tree.fixture",
		"rootNodeId":      "meta",
		"callerNonClaims": []any{"Caller tree fixture is display-only."},
		"nodes": []any{
			nodeRecord("meta", "meta_spec", "Meta specification", 1, sourceIDRef("source.meta", "spec.meta")),
			nodeRecord("module", "module_spec", "Module specification", 1, sourceIDRef("source.module", "spec.module")),
			nodeRecord("submodule", "submodule_spec", "Submodule specification", 1, pathDigestRef("source.submodule", "docs/specs/submodule/requirements.v1.json", digestA(), digestA())),
		},
		"edges": []any{
			map[string]any{"parentNodeId": "meta", "childNodeId": "module"},
			map[string]any{"parentNodeId": "module", "childNodeId": "submodule"},
		},
		"overlays": []any{
			overlayRecord("overlay.source.module", "module", "source.module"),
			map[string]any{
				"overlayId":       "overlay.rendered.module",
				"overlayKind":     "rendered_view",
				"targetNodeId":    "module",
				"refKind":         "rendered_artifact",
				"refId":           "artifact.module.view",
				"refPath":         "artifacts/module-view.html",
				"refDigest":       digestA(),
				"digestAlgorithm": "sha256",
				"label":           "Module rendered view",
				"callerNonClaims": []any{"Caller rendered overlay fixture is presentation only."},
			},
		},
	}
}

func nodeRecord(nodeID string, nodeKind string, label string, displayOrder int64, refs ...map[string]any) map[string]any {
	sourceRefs := make([]any, 0, len(refs))
	for _, ref := range refs {
		sourceRefs = append(sourceRefs, ref)
	}
	return map[string]any{
		"nodeId":          nodeID,
		"nodeKind":        nodeKind,
		"label":           label,
		"displayOrder":    json.Number(strconv.FormatInt(displayOrder, 10)),
		"sourceRefs":      sourceRefs,
		"callerNonClaims": []any{"Caller node fixture is display-only."},
	}
}

func sourceIDRef(sourceRefID string, sourceID string) map[string]any {
	return map[string]any{
		"sourceRefId":   sourceRefID,
		"sourceRole":    "requirements",
		"sourceRefKind": "source_id",
		"sourceId":      sourceID,
	}
}

func pathDigestRef(sourceRefID string, sourcePath string, recorded string, current string) map[string]any {
	return map[string]any{
		"sourceRefId":          sourceRefID,
		"sourceRole":           "requirements",
		"sourceRefKind":        "path_digest",
		"sourcePath":           sourcePath,
		"recordedSourceDigest": recorded,
		"currentSourceDigest":  current,
		"digestAlgorithm":      "sha256",
	}
}

func overlayRecord(overlayID string, targetNodeID string, refID string) map[string]any {
	return map[string]any{
		"overlayId":       overlayID,
		"overlayKind":     "source",
		"targetNodeId":    targetNodeID,
		"refKind":         "source_ref",
		"refId":           refID,
		"label":           "Source overlay",
		"callerNonClaims": []any{"Caller overlay fixture is display-only."},
	}
}

func nodeMap(input map[string]any, nodeID string) map[string]any {
	for _, raw := range input["nodes"].([]any) {
		item := raw.(map[string]any)
		if item["nodeId"] == nodeID {
			return item
		}
	}
	panic("missing node " + nodeID)
}

func sourceRefMap(input map[string]any, nodeID string, sourceRefID string) map[string]any {
	for _, raw := range nodeMap(input, nodeID)["sourceRefs"].([]any) {
		item := raw.(map[string]any)
		if item["sourceRefId"] == sourceRefID {
			return item
		}
	}
	panic("missing source ref " + sourceRefID)
}

func overlayMap(input map[string]any, overlayID string) map[string]any {
	for _, raw := range input["overlays"].([]any) {
		item := raw.(map[string]any)
		if item["overlayId"] == overlayID {
			return item
		}
	}
	panic("missing overlay " + overlayID)
}

func downloadContent(t *testing.T, output string, fileName string) string {
	t.Helper()
	fileNeedle := `data-download-file="` + fileName + `"`
	fileIndex := strings.Index(output, fileNeedle)
	if fileIndex < 0 {
		t.Fatalf("missing download file %q:\n%s", fileName, output)
	}
	segment := output[fileIndex:]
	contentNeedle := `data-download-content="`
	contentIndex := strings.Index(segment, contentNeedle)
	if contentIndex < 0 {
		t.Fatalf("missing download content for %q:\n%s", fileName, output)
	}
	start := contentIndex + len(contentNeedle)
	end := strings.Index(segment[start:], `"`)
	if end < 0 {
		t.Fatalf("unterminated download content for %q:\n%s", fileName, output)
	}
	decoded, err := base64.StdEncoding.DecodeString(segment[start : start+end])
	if err != nil {
		t.Fatalf("decode download content for %q: %v", fileName, err)
	}
	return string(decoded)
}

func assertFailure(t *testing.T, record report.Record, expected string) {
	t.Helper()
	for _, failure := range failureStrings(t, record) {
		if failure == expected {
			return
		}
	}
	t.Fatalf("missing failure %q in %#v", expected, failureStrings(t, record))
}

func failureStrings(t *testing.T, record report.Record) []string {
	t.Helper()
	for _, diagnostic := range record.Diagnostics {
		if diagnostic.Key != "failures" {
			continue
		}
		return anyStrings(diagnostic.Value.([]any))
	}
	t.Fatal("missing failures diagnostic")
	return nil
}

func anyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, raw := range values {
		result = append(result, raw.(string))
	}
	return result
}

func assertSortedStrings(t *testing.T, values []string, label string) {
	t.Helper()
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	for index := range values {
		if values[index] != sorted[index] {
			t.Fatalf("%s are not sorted: %#v", label, values)
		}
	}
}

func recordJSONContains(t *testing.T, record report.Record, needle string) bool {
	t.Helper()
	output, err := stablejson.Marshal(record.JSONValue())
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	return strings.Contains(string(output), needle)
}

func containsAny(values []any, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func reverseSlice(values []any) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func digestA() string {
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func digestB() string {
	return "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
