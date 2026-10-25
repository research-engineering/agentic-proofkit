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
// the only admissible source of new references.
type proofKind struct {
	ManifestPath  string
	ManifestKind  string
	CommandID     string
	RecordPath    string
	RecordKind    string
	CandidateName string
	States        []string
	RetainRun     bool
}

const (
	runtimeProofManifestPath = "scripts/browser-runtime-proof-inputs.v1.json"
	visualProofManifestPath  = "scripts/browser-visual-proof-inputs.v1.json"
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
		ManifestPath:  visualProofManifestPath,
		ManifestKind:  "proofkit.browser-visual-proof-inputs",
		CommandID:     "proofkit.browser-visual",
		RecordPath:    "artifacts/proofkit/browser-visual-proof.json",
		RecordKind:    "proofkit.browser-visual-proof",
		CandidateName: "browser-visual-proof.candidate.json",
		States:        []string{"passed", "unverified"},
		RetainRun:     true,
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
