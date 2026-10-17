package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/externalconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumerinputcompose"
	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
)

func TestConsumerEvidenceStructuresBindAllSixNativeDirections(t *testing.T) {
	owners := map[string]func() map[string]any{
		"external-consumer.input": externalconsumer.InputStructure, "external-consumer.output": externalconsumer.OutputStructure,
		"registry-consumer.input": registryconsumer.InputStructure, "registry-consumer.output": registryconsumer.OutputStructure,
		"registry-consumer-proof-input-compose.input": registryconsumerinputcompose.InputStructure, "registry-consumer-proof-input-compose.output": registryconsumerinputcompose.OutputStructure,
	}
	for name, build := range owners {
		want := build()
		version, semanticVersion := "1", uint(0)
		if strings.HasSuffix(name, ".input") {
			version, semanticVersion = "2", 2
		}
		found := 0
		for _, structure := range nativeStructures() {
			if structure.id != "proofkit."+name+".v"+version+".json-schema" {
				continue
			}
			found++
			actual, err := structure.schema()
			if err != nil || !reflect.DeepEqual(actual, want) {
				t.Fatalf("%s projection differs from native owner: %v", name, err)
			}
			if structure.semanticVersion != semanticVersion || !reflect.DeepEqual(structure.predecessors, []string{"proofkit." + name + ".v1.root-shape"}) {
				t.Fatalf("%s changed existing identity or predecessor", name)
			}
		}
		if found != 1 {
			t.Fatalf("%s native owner count=%d, want1", name, found)
		}
	}
	composition := registryconsumerinputcompose.OutputStructure()["properties"].(map[string]any)["registryConsumerInput"].(map[string]any)["oneOf"].([]any)
	if len(composition) != 2 || !reflect.DeepEqual(composition[1], expectedMaterializedRegistryConsumerInput(t)) {
		t.Fatal("composer does not publish the registry-owned input projection with its admitted release-authority input")
	}
}

// The composer materializes registryConsumerInput only for a passed composition,
// so its release-authority member is the header3 owner projection with exactly
// the literals and presence that releaseAuthorityFailures requires.
func expectedMaterializedRegistryConsumerInput(t *testing.T) map[string]any {
	t.Helper()
	release, err := releaseauthority.InputStructure(3)
	if err != nil {
		t.Fatal(err)
	}
	delete(release, "$schema")
	properties := release["properties"].(map[string]any)
	properties["channel"] = map[string]any{"type": "string", "const": "registry_release"}
	properties["rolloutClaim"] = map[string]any{"type": "boolean", "const": false}
	properties["registryAuthority"] = properties["registryAuthority"].(map[string]any)["anyOf"].([]any)[1]
	releasePackage := properties["package"].(map[string]any)
	packageProperties := releasePackage["properties"].(map[string]any)
	packageProperties["publishConfigRegistry"] = packageProperties["publishConfigRegistry"].(map[string]any)["anyOf"].([]any)[1]
	releasePackage["required"] = []any{"artifactPath", "manifestPrivate", "name", "packManifestPath", "packageManagerLockfile", "publishConfigRegistry", "version"}
	release["description"] = "Admitted release-authority input re-serialized by a passed composition: header3, channel registry_release, rolloutClaim false, a non-null registryAuthority and a present non-null package publishConfigRegistry. Other members keep the release-authority input structure; release-authority evaluation owns the remaining channel, package, consumer and publisher relations."
	schema := registryconsumer.InputStructure()
	input := schema["properties"].(map[string]any)["input"].(map[string]any)
	input["properties"].(map[string]any)["releaseAuthorityInput"] = release
	input["required"] = []any{"consumerId", "dependencyName", "dependencySpec", "nonClaims", "packageName", "packageVersion", "registryUrl", "releaseAuthorityInput", "rollbackVersionPin", "schemaVersion", "tarballFileName", "tarballIntegrity", "tarballShasum"}
	schema["description"] = "Materialized only for a passed composition. The registry consumer owner's input structure, except that inner releaseAuthorityInput is required and is the admitted release-authority input: header3, channel registry_release, rolloutClaim false, a non-null registryAuthority and a present non-null package publishConfigRegistry. Native Build emits it only after registryconsumer.Build passes on it."
	return schema
}
