package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBuildsCanonicalTypedRegistryEvidence(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "artifacts", "package", "npm-pack.json"), `[{
  "name":"@research-engineering/agentic-proofkit","version":"1.2.3","filename":"agentic-proofkit-1.2.3.tgz","integrity":"sha512-x","shasum":"abc"
}]`)
	writeFixture(t, filepath.Join(root, "artifacts", "registry", "npm-pack.json"), `[{
  "name":"@research-engineering/agentic-proofkit","version":"1.2.3","filename":"agentic-proofkit-1.2.3.tgz","integrity":"sha512-x","shasum":"abc","providerField":"ignored"
}]`)
	writeFixture(t, filepath.Join(root, "artifacts", "registry", "npm-publication-mode.txt"), "existing_byte_match\n")
	if err := run(root); err != nil {
		t.Fatalf("run() error=%v", err)
	}
	file, err := os.Open(filepath.Join(root, "artifacts", "registry", "published-registry-artifact-set.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var record registryArtifactSet
	if err := json.NewDecoder(file).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record.ArtifactKind != artifactKind || record.PublicationMode != "existing_byte_match" || len(record.Packages) != 1 {
		t.Fatalf("registry evidence=%#v, want canonical typed record", record)
	}
}

func TestRunRejectsRegistryPackageSetSubstitution(t *testing.T) {
	root := t.TempDir()
	local := `[
  {"name":"a","version":"1.2.3","filename":"a.tgz","integrity":"sha512-a","shasum":"a"},
  {"name":"b","version":"1.2.3","filename":"b.tgz","integrity":"sha512-b","shasum":"b"}
]`
	registry := `[
  {"name":"a","version":"1.2.3","filename":"a.tgz","integrity":"sha512-a","shasum":"a"},
  {"name":"a","version":"1.2.3","filename":"a.tgz","integrity":"sha512-a","shasum":"a"}
]`
	writeFixture(t, filepath.Join(root, "artifacts", "package", "npm-pack.json"), local)
	writeFixture(t, filepath.Join(root, "artifacts", "registry", "npm-pack.json"), registry)
	writeFixture(t, filepath.Join(root, "artifacts", "registry", "npm-publication-mode.txt"), "existing_byte_match\n")
	if err := run(root); err == nil || !strings.Contains(err.Error(), "duplicate package") {
		t.Fatalf("run() error=%v, want duplicate substitution rejection", err)
	}
}

func writeFixture(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
