package adoptionmaterialization

import "testing"

func TestManifestStructureBindsSourceRouteSuffixOnlyForSourceKind(t *testing.T) {
	routes, ok := ManifestShape().Property("routes")
	if !ok {
		t.Fatal("manifest has no routes")
	}
	route, ok := routes.Element()
	if !ok {
		t.Fatal("manifest routes have no item structure")
	}
	for _, item := range []struct {
		kind, path string
		valid      bool
	}{
		{ArtifactRequirementSource, "docs/specs/a/requirements.v2.json", true},
		{ArtifactRequirementSource, "docs/specs/a/requirements.v1.json", false},
		{ArtifactRequirementBinding, "proofkit/bindings.json", true},
		{ArtifactTestInventory, "proofkit/inventory.json", true},
	} {
		_, err := route.Admit(map[string]any{"artifactId": "sha256:fixture", "artifactKind": item.kind, "path": item.path}, "route")
		if (err == nil) != item.valid {
			t.Fatalf("%s %s: error=%v, want valid=%t", item.kind, item.path, err, item.valid)
		}
	}
}
