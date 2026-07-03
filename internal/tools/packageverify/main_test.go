package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestPackageVerifyReadersRejectAmbiguousJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
		read    func(string) error
		want    string
	}{
		{
			name:    "pack records duplicate key",
			content: `[{"name":"agentic-proofkit","name":"other","version":"1.2.3","filename":"agentic-proofkit.tgz","integrity":"sha512-x","shasum":"abc"}]`,
			read: func(path string) error {
				_, err := readPackRecords(path)
				return err
			},
			want: "duplicate object key",
		},
		{
			name:    "requirement bindings trailing value",
			content: `{"requirements":[{"specPath":"docs/specs/example/requirements.v1.json"}]} true`,
			read: func(path string) error {
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read source: %v", err)
				}
				_, err = decodeRequirementBindings(content)
				return err
			},
			want: "multiple JSON values",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(item.content), 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			err := item.read(path)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("reader error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestVerifySpecReferenceClosureReadsTarballBindings(t *testing.T) {
	t.Parallel()

	tarball := writePackageTarball(t, map[string]string{
		"package/proofkit/requirement-bindings.json": `{"requirements":[{"specPath":"docs/specs/example/requirements.v1.json"}]} true`,
	})
	err := verifySpecReferenceClosure(tarballArtifact(t, tarball), map[string]struct{}{
		"package/docs/specs/example/requirements.v1.json": {},
	})
	if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("verifySpecReferenceClosure() error=%v, want tarball JSON failure", err)
	}
}

func TestVerifyPackRecordBytesRejectsStaleMetadata(t *testing.T) {
	root := t.TempDir()
	withWorkingDirectory(t, root)
	filename := "agentic-proofkit-1.2.3.tgz"
	content := []byte("package")
	writeFileBytes(t, filepath.Join(root, "artifacts", "package", filename), content)

	valid := packRecord{
		Filename:  filename,
		Integrity: testNPMIntegrity(content),
		Name:      rootPackageName,
		Shasum:    testSHA1(content),
		Version:   "1.2.3",
	}
	if err := verifyPackRecordBytes(valid); err != nil {
		t.Fatalf("verifyPackRecordBytes(valid) error = %v", err)
	}
	for _, item := range []struct {
		name   string
		record packRecord
		want   string
	}{
		{
			name: "stale shasum",
			record: packRecord{
				Filename:  filename,
				Integrity: valid.Integrity,
				Name:      rootPackageName,
				Shasum:    strings.Repeat("0", 40),
				Version:   "1.2.3",
			},
			want: "shasum mismatch",
		},
		{
			name: "stale integrity",
			record: packRecord{
				Filename:  filename,
				Integrity: "sha512-" + strings.Repeat("A", 88),
				Name:      rootPackageName,
				Shasum:    valid.Shasum,
				Version:   "1.2.3",
			},
			want: "integrity mismatch",
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := verifyPackRecordBytes(item.record)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("verifyPackRecordBytes() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestVerifyRootManifestBoundaryRejectsWrongRepository(t *testing.T) {
	root := t.TempDir()
	withWorkingDirectory(t, root)
	filename := "agentic-proofkit-1.2.3.tgz"
	tarball := writePackageTarball(t, map[string]string{
		"package/package.json": packageManifestFixture("git+https://github.com/example/agentic-proofkit.git"),
	})
	content, err := os.ReadFile(tarball)
	if err != nil {
		t.Fatalf("read package tarball: %v", err)
	}
	writeFileBytes(t, filepath.Join(root, "artifacts", "package", filename), content)
	record := packRecord{
		Filename:  filename,
		Integrity: testNPMIntegrity(content),
		Name:      rootPackageName,
		Shasum:    testSHA1(content),
		Version:   "1.2.3",
	}

	err = verifyRootManifestBoundary(rootPackageArtifact{Content: content, Record: record})
	if err == nil || !strings.Contains(err.Error(), "root package repository") {
		t.Fatalf("verifyRootManifestBoundary() error=%v, want repository failure", err)
	}
}

func TestSnapshotReadersDoNotRereadMutableTarballPath(t *testing.T) {
	tarball := writePackageTarball(t, map[string]string{
		"package/AGENTS.md":                               "package docs describe embedded Go binaries.",
		"package/docs/proofkit-contract-map.md":           "package docs describe embedded Go binaries.",
		"package/package.json":                            packageManifestFixture("git+https://github.com/research-engineering/agentic-proofkit.git"),
		"package/proofkit/requirement-bindings.json":      `{"requirements":[{"specPath":"docs/specs/example/requirements.v1.json"}]}`,
		"package/docs/specs/example/requirements.v1.json": `{"requirements":[]}`,
	})
	artifact := tarballArtifact(t, tarball)
	if err := os.WriteFile(tarball, []byte("not-a-gzip-tarball"), 0o644); err != nil {
		t.Fatalf("mutate tarball path: %v", err)
	}
	if _, err := readManifestFromTar(artifact); err != nil {
		t.Fatalf("readManifestFromTar(snapshot) error = %v", err)
	}
	if err := verifyNoStalePackageDocs(artifact); err != nil {
		t.Fatalf("verifyNoStalePackageDocs(snapshot) error = %v", err)
	}
	if err := verifySpecReferenceClosure(artifact, map[string]struct{}{
		"package/docs/specs/example/requirements.v1.json": {},
	}); err != nil {
		t.Fatalf("verifySpecReferenceClosure(snapshot) error = %v", err)
	}
}

func TestVerifyNoStalePackageDocsReadsTarballDocs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		path      string
		wantPath  string
		staleText string
	}{
		{
			name:      "top level package doc",
			path:      "package/README.md",
			wantPath:  "package/README.md",
			staleText: "runtime JavaScript",
		},
		{
			name:      "shipped contract map doc outside legacy short list",
			path:      "package/docs/proofkit-contract-map.md",
			wantPath:  "package/docs/proofkit-contract-map.md",
			staleText: "optional package",
		},
		{
			name:      "shipped spec json contract",
			path:      "package/proofkit/cli-contract.v1.json",
			wantPath:  "package/proofkit/cli-contract.v1.json",
			staleText: "public/root API",
		},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			entries := packageDocEntries("package docs describe embedded Go binaries.")
			entries[item.path] = item.staleText
			tarball := writePackageTarball(t, entries)

			err := verifyNoStalePackageDocs(tarballArtifact(t, tarball))
			if err == nil || !strings.Contains(err.Error(), item.wantPath+" contains stale package-boundary term") {
				t.Fatalf("verifyNoStalePackageDocs() error=%v, want tarball stale-doc failure for %s", err, item.wantPath)
			}
		})
	}
}

func TestVerifyNoStalePackageDocsDoesNotFlagCrossPlatformNonClaim(t *testing.T) {
	t.Parallel()

	entries := packageDocEntries("package docs describe embedded Go binaries.")
	entries["package/proofkit/witness-plan.json"] = "Local-go environment policy does not claim cross-platform package publication readiness."
	tarball := writePackageTarball(t, entries)

	if err := verifyNoStalePackageDocs(tarballArtifact(t, tarball)); err != nil {
		t.Fatalf("verifyNoStalePackageDocs() error=%v, want no stale-doc failure for cross-platform non-claim", err)
	}
}

func TestVerifyTarEntryHeadersRejectsUnsafeBinaryShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{
			name: "duplicate entry",
			entries: []tarEntry{
				{Name: "package/README.md", Typeflag: tar.TypeReg, Size: 10},
				{Name: "package/README.md", Typeflag: tar.TypeReg, Size: 10},
			},
			want: "duplicate tar entry",
		},
		{
			name: "parent directory path",
			entries: []tarEntry{
				{Name: "package/../dist/agentic-proofkit", Typeflag: tar.TypeReg, Mode: 0o755, Size: 10},
			},
			want: "unsafe tar entry path",
		},
		{
			name: "symlink binary",
			entries: []tarEntry{
				{Name: samplePlatformBinaryEntry(), Typeflag: tar.TypeSymlink, Mode: 0o755, Size: 10},
			},
			want: "must be a regular file",
		},
		{
			name: "non executable binary",
			entries: []tarEntry{
				{Name: samplePlatformBinaryEntry(), Typeflag: tar.TypeReg, Mode: 0o644, Size: 10},
			},
			want: "must be executable",
		},
		{
			name: "empty binary",
			entries: []tarEntry{
				{Name: samplePlatformBinaryEntry(), Typeflag: tar.TypeReg, Mode: 0o755, Size: 0},
			},
			want: "invalid size",
		},
		{
			name: "oversized file",
			entries: []tarEntry{
				{Name: "package/README.md", Typeflag: tar.TypeReg, Size: maxTarEntryBytes + 1},
			},
			want: "invalid size",
		},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			err := verifyTarEntryHeaders(item.entries)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("verifyTarEntryHeaders error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestVerifyTarEntryHeadersAcceptsRegularExecutableBinaries(t *testing.T) {
	t.Parallel()

	err := verifyTarEntryHeaders([]tarEntry{
		{Name: "package/README.md", Typeflag: tar.TypeReg, Size: 10},
		{Name: "package/dist/agentic-proofkit", Typeflag: tar.TypeReg, Mode: 0o755, Size: 10},
		{Name: samplePlatformBinaryEntry(), Typeflag: tar.TypeReg, Mode: 0o755, Size: 10},
	})
	if err != nil {
		t.Fatalf("verifyTarEntryHeaders returned error: %v", err)
	}
}

func TestAllowedRootEntryRejectsDevelopmentPlans(t *testing.T) {
	for _, path := range []string{
		"package/docs/requirement-authoring-plan-implementation-plan.md",
		"package/docs/scaffold-profile-plan-design.md",
	} {
		t.Run(path, func(t *testing.T) {
			if allowedRootEntry(path) {
				t.Fatalf("allowedRootEntry(%q)=true, want false for development-only docs", path)
			}
		})
	}
	for _, path := range []string{
		"package/docs/proofkit-contract-map.md",
		"package/docs/release-process.md",
	} {
		t.Run(path, func(t *testing.T) {
			if !allowedRootEntry(path) {
				t.Fatalf("allowedRootEntry(%q)=false, want true for package-public docs", path)
			}
		})
	}
}

func TestVerifyRequiredRootEntriesRequiresEveryReleasePlatformBinary(t *testing.T) {
	entrySet := map[string]struct{}{}
	for _, entry := range requiredRootEntries() {
		entrySet[entry] = struct{}{}
	}
	for _, target := range releaseplatform.Targets() {
		t.Run(target.PlatformSuffix, func(t *testing.T) {
			mutated := map[string]struct{}{}
			for entry := range entrySet {
				mutated[entry] = struct{}{}
			}
			delete(mutated, target.PackageTarEntry)

			err := verifyRequiredRootEntries(mutated)
			if err == nil || !strings.Contains(err.Error(), target.PackageTarEntry) {
				t.Fatalf("verifyRequiredRootEntries() error=%v, want missing %s", err, target.PackageTarEntry)
			}
		})
	}
}

func TestVerifyRequiredRootEntriesRequiresPackagePublicDocs(t *testing.T) {
	entrySet := map[string]struct{}{}
	for _, entry := range requiredRootEntries() {
		entrySet[entry] = struct{}{}
	}
	for _, entry := range []string{
		"package/docs/proofkit-contract-map.md",
		"package/docs/release-process.md",
	} {
		t.Run(entry, func(t *testing.T) {
			mutated := map[string]struct{}{}
			for existing := range entrySet {
				mutated[existing] = struct{}{}
			}
			delete(mutated, entry)

			err := verifyRequiredRootEntries(mutated)
			if err == nil || !strings.Contains(err.Error(), entry) {
				t.Fatalf("verifyRequiredRootEntries() error=%v, want missing %s", err, entry)
			}
		})
	}
}

func TestVerifyTextPolicySmokeReportRequiresJSONABI(t *testing.T) {
	wantSummary := textPolicySmokeSummary{
		CheckedTextFileCount: 1,
		FailureCount:         0,
		InputFileCount:       1,
	}
	valid := installedCommandResult{
		ExitCode: 0,
		Stdout:   []byte(`{"reportId":"proofkit.package-smoke.success","reportKind":"proofkit.text-policy","state":"passed","summary":{"checkedTextFileCount":1,"failureCount":0,"inputFileCount":1}}`),
	}
	if err := verifyTextPolicySmokeReport(valid, "proofkit.package-smoke.success", "passed", 0, wantSummary); err != nil {
		t.Fatalf("verifyTextPolicySmokeReport(valid) error = %v", err)
	}
	cases := []struct {
		name   string
		result installedCommandResult
		want   string
	}{
		{
			name: "wrong exit",
			result: installedCommandResult{
				ExitCode: 1,
				Stdout:   valid.Stdout,
			},
			want: "exit code 1",
		},
		{
			name: "stderr",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   valid.Stdout,
				Stderr:   []byte("diagnostic"),
			},
			want: "stderr must be empty",
		},
		{
			name: "non JSON stdout",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   []byte("not-json"),
			},
			want: "stdout must be one JSON report",
		},
		{
			name: "wrong report kind",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   []byte(`{"reportId":"proofkit.package-smoke.success","reportKind":"proofkit.other","state":"passed","summary":{"checkedTextFileCount":1,"failureCount":0,"inputFileCount":1}}`),
			},
			want: "reportKind=proofkit.other",
		},
		{
			name: "wrong state",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   []byte(`{"reportId":"proofkit.package-smoke.success","reportKind":"proofkit.text-policy","state":"failed","summary":{"checkedTextFileCount":1,"failureCount":0,"inputFileCount":1}}`),
			},
			want: "state=failed",
		},
		{
			name: "wrong explicit input count",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   []byte(`{"reportId":"proofkit.package-smoke.success","reportKind":"proofkit.text-policy","state":"passed","summary":{"checkedTextFileCount":2,"failureCount":0,"inputFileCount":2}}`),
			},
			want: "summary.inputFileCount=2",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := verifyTextPolicySmokeReport(item.result, "proofkit.package-smoke.success", "passed", 0, wantSummary)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("verifyTextPolicySmokeReport() error=%v, want %q", err, item.want)
			}
		})
	}
}

func samplePlatformBinaryEntry() string {
	return releaseplatform.PackageTarEntries()[len(releaseplatform.PackageTarEntries())-1]
}

func packageDocEntries(content string) map[string]string {
	return map[string]string{
		"package/AGENTS.md":                                        content,
		"package/CONTRIBUTING.md":                                  content,
		"package/NON_CLAIMS.md":                                    content,
		"package/README.md":                                        content,
		"package/SECURITY.md":                                      content,
		"package/docs/proofkit-contract-map.md":                    content,
		"package/docs/release-process.md":                          content,
		"package/docs/specs/proofkit-package-boundary/overview.md": content,
		"package/proofkit/cli-contract.v1.json":                    content,
	}
}

func writePackageTarball(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agentic-proofkit.tgz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tarball: %v", err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range entries {
		body := []byte(content)
		if err := tarWriter.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close tarball: %v", err)
	}
	return path
}

func tarballArtifact(t *testing.T, path string) rootPackageArtifact {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tarball: %v", err)
	}
	return rootPackageArtifact{Content: content}
}

func withWorkingDirectory(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
}

func writeFileBytes(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create parent directory: %v", err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func testSHA1(content []byte) string {
	sum := sha1.Sum(content)
	return hex.EncodeToString(sum[:])
}

func testNPMIntegrity(content []byte) string {
	hash := sha512.New()
	_, _ = hash.Write(content)
	return "sha512-" + base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func packageManifestFixture(repositoryURL string) string {
	return `{
  "name": "agentic-proofkit",
  "version": "1.2.3",
  "license": "MIT",
  "packageManager": "npm@11.17.0",
  "repository": {
    "type": "git",
    "url": "` + repositoryURL + `"
  },
  "publishConfig": {
    "access": "public",
    "registry": "https://registry.npmjs.org"
  },
  "bin": {
    "agentic-proofkit": "dist/agentic-proofkit"
  },
  "exports": {
    "./package.json": "./package.json"
  },
  "os": [
    "darwin",
    "linux"
  ],
  "cpu": [
    "arm64",
    "x64"
  ],
  "files": [
    "AGENTS.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NON_CLAIMS.md",
    "README.md",
    "SECURITY.md",
    "dist/**",
    "docs/proofkit-contract-map.md",
    "docs/release-process.md",
    "docs/specs/**/*",
    "proofkit/*.json"
  ]
}`
}
