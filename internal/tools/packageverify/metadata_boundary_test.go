package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestNPMVerifierMetadataBoundaryOrdinarySourceControl(t *testing.T) {
	source := mustReadBytes(t, filepath.Join("..", "..", "..", "package.json"))
	artifact := npmMetadataBoundaryArtifact(t, source)
	manifest, err := readManifestFromTar(artifact)
	if err != nil {
		t.Fatalf("captured ordinary source manifest: %v", err)
	}
	if manifest.Description == "" || manifest.Version != artifact.Record.Version {
		t.Fatal("ordinary source control lost its selected metadata")
	}
	if err := verifyRootManifestBoundary(artifact); err != nil {
		t.Fatalf("ordinary source control failed root boundary: %v", err)
	}
}

func TestNPMVerifierMetadataBoundaryRejectsCapturedSecrets(t *testing.T) {
	const synthetic = "api_key=synthetic_boundary_dummy_0123456789"
	source := mustReadBytes(t, filepath.Join("..", "..", "..", "package.json"))
	for _, field := range []string{"name", "version", "description", "license", "repository.type", "repository.url"} {
		t.Run(field, func(t *testing.T) {
			content := patchNPMBoundaryManifest(t, source, field, synthetic)
			artifact := npmMetadataBoundaryArtifact(t, content)
			want := "package metadata " + field + " contains a secret-like value"
			if _, err := readManifestFromTar(artifact); err == nil || err.Error() != want {
				t.Fatalf("captured manifest must refuse common metadata with fixed error %q, got %v", want, err)
			}
			if err := verifyRootManifestBoundary(artifact); err == nil || err.Error() != want {
				t.Fatalf("root boundary must propagate captured metadata refusal %q, got %v", want, err)
			}
		})
	}
}

func TestNPMVerifierMetadataBoundaryPreservesTypeAndUnknownKeyPolicy(t *testing.T) {
	source := mustReadBytes(t, filepath.Join("..", "..", "..", "package.json"))
	for _, tc := range []struct {
		name, field, want string
		value             any
	}{
		{"null selected string", "description", "package metadata description must be a string", nil},
		{"non-string selected field", "description", "package metadata description must be a string", true},
		{"null repository leaf", "repository.type", "package metadata repository.type must be a string", nil},
		{"null repository", "repository", "package metadata repository must be an object", nil},
		{"shorthand repository", "repository", "package metadata repository must be an object", "https://example.test/repo"},
		{"unknown top-level field", "unadmittedBoundaryField", "package manifest has 1 unsupported top-level field(s)", "ordinary text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := patchNPMBoundaryManifest(t, source, tc.field, tc.value)
			artifact := npmMetadataBoundaryArtifact(t, content)
			if _, err := readManifestFromTar(artifact); err == nil || err.Error() != tc.want {
				t.Fatalf("captured manifest classification: want %q, got %v", tc.want, err)
			}
			if err := verifyRootManifestBoundary(artifact); err == nil || err.Error() != tc.want {
				t.Fatalf("root boundary classification: want %q, got %v", tc.want, err)
			}
		})
	}
}

func patchNPMBoundaryManifest(t *testing.T, source []byte, field string, value any) []byte {
	t.Helper()
	var manifest map[string]any
	if err := json.Unmarshal(source, &manifest); err != nil {
		t.Fatal(err)
	}
	switch field {
	case "repository.type":
		manifest["repository"].(map[string]any)["type"] = value
	case "repository.url":
		manifest["repository"].(map[string]any)["url"] = value
	default:
		manifest[field] = value
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func npmMetadataBoundaryArtifact(t *testing.T, content []byte) rootPackageArtifact {
	t.Helper()
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	archive := writePackageTarball(t, map[string]string{"package/package.json": string(content)})
	artifact := tarballArtifact(t, archive)
	artifact.Record = packRecord{
		Name:      rootPackageName,
		Version:   manifest.Version,
		Filename:  filepath.Base(archive),
		Shasum:    testSHA1(artifact.Content),
		Integrity: testNPMIntegrity(artifact.Content),
	}
	return artifact
}
