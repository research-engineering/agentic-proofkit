package requirementbrowser

import _ "embed"

//go:embed assets/workspace.js
var workspaceJavaScript []byte

//go:embed assets/selection-authority.js
var selectionAuthorityJavaScript []byte

//go:embed assets/workspace.css
var workspaceCSS []byte
