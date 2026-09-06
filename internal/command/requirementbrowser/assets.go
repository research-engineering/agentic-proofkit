package requirementbrowser

import _ "embed"

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

//go:embed assets/workspace-navigation.js
var workspaceNavigationJavaScript []byte

//go:embed assets/workspace.css
var workspaceCSS []byte
