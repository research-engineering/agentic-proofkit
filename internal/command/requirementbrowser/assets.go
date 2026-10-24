package requirementbrowser

import (
	_ "embed"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
)

//go:embed assets/workspace.js
var workspaceJavaScript []byte

//go:embed assets/selection-authority.js
var selectionAuthorityJavaScript []byte

//go:embed assets/workspace-icons.js
var workspaceIconsJavaScript []byte

//go:embed assets/workspace-panels.js
var workspacePanelsJavaScript []byte

//go:embed assets/workspace-requests.js
var workspaceRequestsJavaScript []byte

//go:embed assets/workspace-json.js
var workspaceJSONJavaScript []byte

//go:embed assets/workspace-navigation.js
var workspaceNavigationJavaScript []byte

//go:embed assets/workspace-coverage.js
var workspaceCoverageJavaScript []byte

//go:embed assets/workspace-diff.js
var workspaceDiffJavaScript []byte

//go:embed assets/workspace-graph.js
var workspaceGraphJavaScript []byte

//go:embed assets/workspace-handoff.js
var workspaceHandoffJavaScript []byte

//go:embed assets/workspace.css
var workspaceCSS []byte

// tokensCSS is the design-token stylesheet that browserdoc owns; the static
// views inline the same bytes.
var tokensCSS = []byte(browserdoc.TokenStylesheet())
