package requirementspectree

import "regexp"

const reportKind = "proofkit.requirement-spec-tree"

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

var nodeKinds = map[string]struct{}{
	"capability_spec": {},
	"meta_spec":       {},
	"module_spec":     {},
	"submodule_spec":  {},
}

var sourceRoles = map[string]struct{}{
	"coverage_input": {},
	"overview":       {},
	"proof_binding":  {},
	"rendered_view":  {},
	"requirements":   {},
	"other":          {},
}

var sourceRefKinds = map[string]struct{}{
	"path_digest": {},
	"source_id":   {},
}

var overlayKinds = map[string]struct{}{
	"coverage":      {},
	"proof":         {},
	"rendered_view": {},
	"source":        {},
}

var overlayRefKinds = map[string]struct{}{
	"external_report":   {},
	"rendered_artifact": {},
	"source_ref":        {},
}

var boundaryNonClaims = []string{
	"Requirement spec tree caller annotations are untrusted display text and are not non-claim authority.",
	"Requirement spec tree reports do not approve merge, release, rollout, or production readiness.",
	"Requirement spec tree reports do not compute source digest freshness from repository files.",
	"Requirement spec tree reports do not execute native witnesses.",
	"Requirement spec tree reports do not infer hierarchy from repository layout.",
	"Requirement spec tree reports do not make rendered output authoritative.",
	"Requirement spec tree reports do not read requirement source files.",
	"Requirement spec tree reports do not validate requirement meaning, proof adequacy, coverage truth, or receipt freshness.",
}

type SourceRef struct {
	CurrentSourceDigest  string
	DigestAlgorithm      string
	RecordedSourceDigest string
	SourceID             string
	SourcePath           string
	SourceRefID          string
	SourceRefKind        string
	SourceRole           string
}

type sourceRef = SourceRef

type Node struct {
	CallerAnnotations []string
	DisplayOrder      int
	Label             string
	NodeID            string
	NodeKind          string
	SourceRefs        []sourceRef
}

type node = Node

type Edge struct {
	ChildNodeID  string
	ParentNodeID string
}

type edge = Edge

type Overlay struct {
	CallerAnnotations []string
	DigestAlgorithm   string
	Label             string
	OverlayID         string
	OverlayKind       string
	RefDigest         string
	RefID             string
	RefKind           string
	RefPath           string
	TargetNodeID      string
}

type overlay = Overlay

type Tree struct {
	CallerAnnotations []string
	Edges             []edge
	Nodes             []node
	Overlays          []overlay
	RootNodeID        string
	TreeID            string
}

type admittedInput = Tree
