package requirementcontext

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// InputGuide delegates the child tree representation to its existing owner.
func InputGuide(renderer cliexec.Renderer) string {
	tree := requirementspectree.Tree{
		TreeID: "example.tree", RootNodeID: "example.root",
		Nodes: []requirementspectree.Node{{
			NodeID: "example.root", NodeKind: "meta_spec", Label: "Request behavior", DisplayOrder: 1,
			SourceRefs: []requirementspectree.SourceRef{{
				SourceRefID: "example.root.requirements", SourceRefKind: "source_id",
				SourceRole: "requirements", SourceID: "example.requirements",
			}},
		}},
	}
	packet := map[string]any{
		"tree": requirementspectree.TreeValue(tree),
		"catalog": map[string]any{
			"schemaVersion": 2, "catalogId": "example.context",
			"specTree": map[string]any{"path": "proofkit/spec-tree.json"},
			"requirementSources": []any{map[string]any{
				"path": "docs/specs/requests/requirements.v2.json", "nodeId": "example.root",
			}},
			"proofBinding": map[string]any{"path": "proofkit/requirement-bindings.json"},
		},
	}
	encoded, err := stablejson.Marshal(packet)
	if err != nil {
		panic("invalid static context guide template: " + err.Error())
	}
	return strings.NewReplacer("{{cli}}", renderer.DisplayCommand(), "{{packet}}", strings.TrimSuffix(string(encoded), "\n")).Replace(inputGuide)
}

const inputGuide = `Requirement context input guide:
  Compose a derived snapshot from explicitly named files under --repo-root.
  This command reads those files; it does not scan for specifications, write
  sources, approve meaning, execute witnesses or authenticate caller digests.

  First obtain connected source and binding inputs from:
    {{cli}} adopt materialize plan --help
  Its /requirementSources/0 has sourceId example.requirements and its binding
  is /requirementProofBinding/record. Review/adapt those complete inputs and
  persist them through the materialization recipe or an authorized repository
  writer. The paths below match that example; no admission report is a source.

  The tree below is a separate routing input, not a requirement source. Tree
  schemaVersion 2 does not mean requirement-source v2. Match each catalog nodeId
  to a tree node whose requirements-role sourceRef names that source's sourceId.
  Source IDs and global requirement IDs must remain unique within the context.
  Additional sources need their own catalog entries and matching tree references.

Connected context packet (store in a caller-selected scratch file):
` + "```json\n" + `{{packet}}
` + "```\n" + `
  Validate /tree, then persist that SAME tree input at proofkit/spec-tree.json
  under the selected root using an authorized repository writer. Do not store
  the requirement-spec-tree report in its place. This command does not create it.
  The packet's /catalog is the compose input; the outer packet is not the catalog.

  {{cli}} requirement-spec-tree --input <packet> --input-pointer /tree
  {{cli}} requirement-context-compose --input <packet> --input-pointer /catalog --repo-root <root>

  Require exit0 and state passed from tree admission. Compose exit0 emits a
  context, not a report with state passed. Retain its complete stdout bytes:
  projections contain child-owned canonical records; sources retain observed
  paths/digests; snapshotId binds this captured context. It is not proof that
  the files stayed unchanged, the witnesses ran or the producer is trusted.
  With no expectedSourceDigest operands, expectedDigestCoverage is none.
  For a previously captured expectation, put expectedSourceDigest on the
  relevant catalog entry as sha256:<64 lowercase hex digits>, computed from
  the exact retained file bytes. A mismatch rejects; computing an expectation
  from current bytes alone does not establish historical freshness or trust.

  proofBinding may be omitted when no binding is available. coverage may be
  added as {"path":"<coverage-input-path>"} after preparing an actual
  requirement-coverage-view INPUT, not its rendered report; see:
    {{cli}} requirement-coverage-input-compose --help
  Do not invent an empty passing coverage report. Continue with
  requirement-context-slice, requirement-semantic-diff or
  requirement-traceability-graph using their command-specific --help.
`
