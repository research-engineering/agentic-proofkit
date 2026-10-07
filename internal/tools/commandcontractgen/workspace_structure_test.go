package main

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/workspacemanifestfacts"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceplanning"
)

func TestWorkspaceStructuresBindExactOwnersAndRejectRehashedDrift(t *testing.T) {
	families := []boundaryStructureFamily{
		{"workspace-manifest-facts", workspacemanifestfacts.InputStructure, workspacemanifestfacts.OutputStructure},
		{"workspace-changed-package-plan", workspaceplanning.ChangedPlanInputStructure, workspaceplanning.ChangedPlanOutputStructure},
		{"workspace-shard-partition", workspaceplanning.ShardInputStructure, workspaceplanning.ShardOutputStructure},
	}
	for _, family := range families {
		for direction, projection := range map[string]func() map[string]any{"input": family.input, "output": family.output} {
			prefix := "proofkit." + family.command + "." + direction
			id := prefix + ".v1.json-schema"
			predecessors := []string{prefix + ".v1.root-shape"}
			var semanticVersion uint
			if family.command == "workspace-shard-partition" {
				id = prefix + ".v2.json-schema"
				predecessors = append(predecessors, prefix+".v1.json-schema")
				semanticVersion = 2
			}
			t.Run(id, func(t *testing.T) {
				owners := nativeStructures()
				index := slices.IndexFunc(owners, func(owner nativeStructure) bool { return owner.id == id })
				if index < 0 {
					t.Fatal("missing native structure")
				}
				owner := owners[index]
				if owner.direction != direction || owner.semanticVersion != semanticVersion || !slices.Equal(owner.commands, []string{family.command}) || !slices.Equal(owner.predecessors, predecessors) {
					t.Fatal("incorrect native owner registration")
				}
				definition, err := owner.definition()
				if err != nil {
					t.Fatal(err)
				}
				variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
				if direction == "output" && family.command != "workspace-manifest-facts" {
					if len(variants) != 2 {
						t.Fatal("missing explicit planning/envelope output alternatives")
					}
					envelope, err := agentEnvelopeRootStructure()
					if err != nil || !reflect.DeepEqual(variants[0].(map[string]any)["schema"], envelope) {
						t.Fatal("agent envelope differs from shared owner")
					}
				} else if len(variants) != 1 {
					t.Fatal("unexpected root alternatives")
				}
				variant := variants[len(variants)-1].(map[string]any)
				if !reflect.DeepEqual(variant["schema"], projection()) {
					t.Fatal("projection differs from native owner")
				}
				if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err != nil {
					t.Fatal(err)
				}
				variant["schema"].(map[string]any)["properties"].(map[string]any)["schemaVersion"] = map[string]any{"const": 2}
				delete(definition, "canonicalDigest")
				encoded, err := canonicalJSON(definition)
				if err != nil {
					t.Fatal(err)
				}
				definition["canonicalDigest"] = sha256Digest(encoded)
				if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err == nil {
					t.Fatal("recomputed hash authorized caller-owned schema drift")
				}
				value := projection()
				before, err := canonicalJSON(value)
				if err != nil {
					t.Fatal(err)
				}
				restore := mutateStructureContainers(value)
				defer restore()
				after, err := canonicalJSON(projection())
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("returned schema mutation changed its native owner")
				}
			})
		}
	}
}
