package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

type registryOutputTransport func(*http.Request) (*http.Response, error)

func (transport registryOutputTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestRunConfinesRegistryOutput(t *testing.T) {
	t.Chdir(t.TempDir())
	candidates := pythonPackageSet{ArtifactKind: packageKind, SchemaVersion: schemaVersion, PackageName: packageName, PackageVersion: "1.2.3"}
	registry := pypiResponse{}
	registry.Info.Name = packageName
	registry.Info.Version = candidates.PackageVersion
	for _, target := range releaseplatform.Targets() {
		candidate := wheelRecordForTarget(target, candidates.PackageVersion, "wheel")
		candidates.Packages = append(candidates.Packages, candidate)
		file := pypiFile{Filename: candidate.Filename, PackageType: "bdist_wheel", PythonVersion: "py3", URL: "https://files.pythonhosted.org/packages/fixture.whl", Yanked: new(false)}
		file.Digests.SHA256 = candidate.Sha256
		registry.URLs = append(registry.URLs, file)
	}
	writeFixture := func(path string, value any) {
		t.Helper()
		content, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture("package.json", packageJSON{Name: "@research-engineering/agentic-proofkit", Version: candidates.PackageVersion})
	writeFixture("artifacts/pypi/python-packages.json", candidates)
	wire, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	priorTransport := http.DefaultTransport
	requests := 0
	http.DefaultTransport = registryOutputTransport(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "https://pypi.org/pypi/agentic-proofkit/1.2.3/json" {
			t.Fatalf("unexpected registry request: %s %s", request.Method, request.URL)
		}
		requests++
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(wire)), Header: make(http.Header)}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = priorTransport })
	if err := run(); err != nil {
		t.Fatalf("ordinary registry output: %v", err)
	}
	const output = "artifacts/pypi-registry/pypi-release.json"
	expectedEvidence, err := compareRegistryFiles(candidates, registry)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.MarshalIndent(registryArtifactOutput(candidates.PackageVersion, expectedEvidence), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	readOutput := func() {
		t.Helper()
		content, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(content, expected) {
			t.Fatalf("registry output bytes differ: %v", err)
		}
		info, err := os.Lstat(output)
		if err != nil || info.Mode() != 0o600 {
			t.Fatalf("registry output must be regular owner-only file: %v, %v", info, err)
		}
	}
	readOutput()
	sentinel := filepath.Join(t.TempDir(), "outside-sentinel")
	original := []byte("unchanged outside sentinel\n")
	if err := os.WriteFile(sentinel, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, output); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("registry writer accepted symlink output")
	}
	actual, err := os.ReadFile(sentinel)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatalf("outside sentinel changed: %v", err)
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(sentinel, output); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatalf("replace hardlinked registry output: %v", err)
	}
	actual, err = os.ReadFile(sentinel)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatalf("hardlink peer changed: %v", err)
	}
	readOutput()
	if requests != 3 {
		t.Fatalf("registry request count = %d, want 3", requests)
	}
}
