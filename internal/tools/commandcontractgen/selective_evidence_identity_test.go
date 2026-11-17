package main

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSelectiveEvidenceIdentitySeparatesArtifactMeaningFromWireVersion(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.selective-gate-evidence.output.v2.json-schema")
	if !ok || owner.semanticVersion != 2 || owner.direction != "output" || !slices.Equal(owner.commands, []string{"selective-gate-evidence"}) {
		t.Fatal("selective evidence semantic output owner is not v2")
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := owner.contractVersion(definition)
	if err != nil || wire != json.Number("1") || owner.contractID("selective-gate-evidence", wire) != "proofkit.selective-gate-evidence.output.v2" {
		t.Fatal("new artifact-reference meaning changed or concealed the wire version")
	}
	for _, old := range []string{"proofkit.selective-gate-evidence.output.v1.root-shape", "proofkit.selective-gate-evidence.output.v1.json-schema"} {
		if _, active := nativeStructureOwner(old); active || !slices.Contains(owner.predecessors, old) {
			t.Fatal("old artifact-path meaning remains active or lost its retirement guard")
		}
	}
}
