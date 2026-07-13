package retainedevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestUsesDownloadableArtifactPaths(t *testing.T) {
	root := retainedEvidenceFixture(t)
	if err := Write(root); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, ManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		"attestations/github-artifact-attestations.json": "attestation\n",
		"release/github-release.json":                    "release\n",
	} {
		sum := sha256.Sum256([]byte(value))
		line := hex.EncodeToString(sum[:]) + "  " + path
		if !strings.Contains(string(content), line) {
			t.Fatalf("manifest missing executable path line %q:\n%s", line, content)
		}
	}
	if strings.Contains(string(content), "  github-release.json") {
		t.Fatalf("manifest collapsed artifact topology to basenames:\n%s", content)
	}
}

func TestManifestRejectsUnboundAttestationAndSymlink(t *testing.T) {
	t.Run("extra attestation", func(t *testing.T) {
		root := retainedEvidenceFixture(t)
		writeRetainedFixture(t, root, "attestations/extra.json", "extra\n")
		if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "file set") {
			t.Fatalf("Build() error = %v, want exact-set rejection", err)
		}
	})
	t.Run("extra non-JSON file", func(t *testing.T) {
		root := retainedEvidenceFixture(t)
		writeRetainedFixture(t, root, "attestations/unbound.txt", "extra\n")
		if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "file set") {
			t.Fatalf("Build() error = %v, want exact-set rejection", err)
		}
	})
	t.Run("extra symlink", func(t *testing.T) {
		root := retainedEvidenceFixture(t)
		if err := os.Symlink(
			filepath.Join(root, "release", "github-release.json"),
			filepath.Join(root, "attestations", "unbound.json"),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "file set") {
			t.Fatalf("Build() error = %v, want symlink-set rejection", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := retainedEvidenceFixture(t)
		target := filepath.Join(root, "release", "target.json")
		writeRetainedFixture(t, root, "release/target.json", "release\n")
		if err := os.Remove(filepath.Join(root, "release", "github-release.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "release", "github-release.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "symlinks") {
			t.Fatalf("Build() error = %v, want symlink rejection", err)
		}
	})
}

func TestVerifyRejectsManifestAddressDrift(t *testing.T) {
	root := retainedEvidenceFixture(t)
	if err := Write(root); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, ManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	drifted := strings.ReplaceAll(string(content), "attestations/github-artifact-attestations.json", "github-artifact-attestations.json")
	if err := os.WriteFile(filepath.Join(root, ManifestPath), []byte(drifted), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err == nil || !strings.Contains(err.Error(), "artifact topology") {
		t.Fatalf("Verify() error = %v, want topology rejection", err)
	}
}

func retainedEvidenceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeRetainedFixture(t, root, "attestations/github-artifact-attestations.json", "attestation\n")
	writeRetainedFixture(t, root, "release/github-release.json", "release\n")
	return root
}

func writeRetainedFixture(t *testing.T, root, path, content string) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
