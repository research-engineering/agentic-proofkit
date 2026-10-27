package main

import (
	"fmt"
	"slices"
)

// proofKind is one row of the closed table that maps an input manifest to the
// witness command, record path and record states it owns. The runtime row keeps
// the original manifest, command, record, states and run cleanup exactly. The
// visual row retains its run directory, passing or failing, because the run's
// captures, candidate inventory and observed environment are its gallery and
// the only admissible source of new references. The two matrix rows, one per
// family, write only passed records and clean their run directory like the
// runtime row. Rows that observe the recorded reference environment admit
// --require-reference-environment.
type proofKind struct {
	ManifestPath         string
	ManifestKind         string
	CommandID            string
	RecordPath           string
	RecordKind           string
	CandidateName        string
	States               []string
	RetainRun            bool
	ReferenceEnvironment bool
	Family               string
}

const (
	runtimeProofManifestPath         = "scripts/browser-runtime-proof-inputs.v1.json"
	visualProofManifestPath          = "scripts/browser-visual-proof-inputs.v1.json"
	matrixStaticProofManifestPath    = "scripts/browser-matrix-static-proof-inputs.v1.json"
	matrixWorkspaceProofManifestPath = "scripts/browser-matrix-workspace-proof-inputs.v1.json"
)

var proofKinds = []proofKind{
	{
		ManifestPath:  runtimeProofManifestPath,
		ManifestKind:  "proofkit.browser-runtime-proof-inputs",
		CommandID:     "proofkit.browser-check",
		RecordPath:    "artifacts/proofkit/browser-runtime-proof.json",
		RecordKind:    "proofkit.browser-runtime-proof",
		CandidateName: "browser-runtime-proof.candidate.json",
		States:        []string{"passed"},
	},
	{
		ManifestPath:         visualProofManifestPath,
		ManifestKind:         "proofkit.browser-visual-proof-inputs",
		CommandID:            "proofkit.browser-visual",
		RecordPath:           "artifacts/proofkit/browser-visual-proof.json",
		RecordKind:           "proofkit.browser-visual-proof",
		CandidateName:        "browser-visual-proof.candidate.json",
		States:               []string{"passed", "unverified"},
		RetainRun:            true,
		ReferenceEnvironment: true,
	},
	{
		ManifestPath:         matrixStaticProofManifestPath,
		ManifestKind:         "proofkit.browser-matrix-static-proof-inputs",
		CommandID:            "proofkit.browser-matrix-static",
		RecordPath:           "artifacts/proofkit/browser-matrix-static-proof.json",
		RecordKind:           matrixRecordKind,
		CandidateName:        "browser-matrix-static-proof.candidate.json",
		States:               []string{"passed"},
		ReferenceEnvironment: true,
		Family:               "static",
	},
	{
		ManifestPath:         matrixWorkspaceProofManifestPath,
		ManifestKind:         "proofkit.browser-matrix-workspace-proof-inputs",
		CommandID:            "proofkit.browser-matrix-workspace",
		RecordPath:           "artifacts/proofkit/browser-matrix-workspace-proof.json",
		RecordKind:           matrixRecordKind,
		CandidateName:        "browser-matrix-workspace-proof.candidate.json",
		States:               []string{"passed"},
		ReferenceEnvironment: true,
		Family:               "workspace",
	},
}

func runtimeProofKind() proofKind {
	return proofKinds[0]
}

func visualProofKind() proofKind {
	return proofKinds[1]
}

func (kind proofKind) isVisual() bool {
	return kind.ManifestPath == visualProofManifestPath
}

func (kind proofKind) isMatrix() bool {
	return kind.Family != ""
}

// expectedProjectTests returns the exact per-project test identities of a
// kind, or nil for the runtime kind, whose projects must pass one equal set.
func (kind proofKind) expectedProjectTests() map[string][]string {
	switch {
	case kind.isVisual():
		return expectedVisualProjectTests()
	case kind.isMatrix():
		return expectedMatrixProjectTests(kind.Family)
	}
	return nil
}

func (kind proofKind) admitsState(state string) bool {
	return slices.Contains(kind.States, state)
}

// selectProofKind admits only a manifest path that is a row of the table.
func selectProofKind(manifestPath string) (proofKind, error) {
	for _, kind := range proofKinds {
		if kind.ManifestPath == manifestPath {
			return kind, nil
		}
	}
	return proofKind{}, fmt.Errorf("browser proof manifest is not an admitted proof kind")
}
