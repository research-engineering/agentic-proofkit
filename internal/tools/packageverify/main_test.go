package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
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
			content: `[{"name":"@research-engineering/agentic-proofkit","name":"other","version":"1.2.3","filename":"agentic-proofkit.tgz","integrity":"sha512-x","shasum":"abc"}]`,
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

func TestVerifyRootManifestBoundaryRejectsPackageManifestRuntimeDrift(t *testing.T) {
	cases := []struct {
		name   string
		patch  func(string) string
		wanted string
	}{
		{
			name: "commonjs type",
			patch: func(manifest string) string {
				return strings.Replace(manifest, `"type": "module"`, `"type": "commonjs"`, 1)
			},
			wanted: "type must be module",
		},
		{
			name: "side effects enabled",
			patch: func(manifest string) string {
				return strings.Replace(manifest, `"sideEffects": false`, `"sideEffects": true`, 1)
			},
			wanted: "sideEffects must be false",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			filename := "agentic-proofkit-1.2.3.tgz"
			manifest := item.patch(packageManifestFixture("git+https://github.com/research-engineering/agentic-proofkit.git"))
			tarball := writePackageTarball(t, map[string]string{
				"package/package.json": manifest,
			})
			content, err := os.ReadFile(tarball)
			if err != nil {
				t.Fatalf("read package tarball: %v", err)
			}
			record := packRecord{
				Filename:  filename,
				Integrity: testNPMIntegrity(content),
				Name:      rootPackageName,
				Shasum:    testSHA1(content),
				Version:   "1.2.3",
			}

			err = verifyRootManifestBoundary(rootPackageArtifact{Content: content, Record: record})
			if err == nil || !strings.Contains(err.Error(), item.wanted) {
				t.Fatalf("verifyRootManifestBoundary() error=%v, want %q", err, item.wanted)
			}
		})
	}
}

func TestReadManifestFromTarRejectsUnknownPackageManifestFields(t *testing.T) {
	secretShapedKey := "api_key=ghp_1234567890abcdefghijklmnopqrstuvwx"
	tarball := writePackageTarball(t, map[string]string{
		"package/package.json": strings.Replace(packageManifestFixture("git+https://github.com/research-engineering/agentic-proofkit.git"), "\n}", ",\n  \""+secretShapedKey+"\": true\n}", 1),
	})

	_, err := readManifestFromTar(tarballArtifact(t, tarball))
	if err == nil || !strings.Contains(err.Error(), "unsupported top-level field") {
		t.Fatalf("readManifestFromTar() error=%v, want unsupported field rejection", err)
	}
	if strings.Contains(err.Error(), secretShapedKey) || strings.Contains(err.Error(), "ghp_") {
		t.Fatalf("readManifestFromTar() leaked unsupported field name: %v", err)
	}
}

func TestVerifyRootManifestBoundaryRejectsLifecycleScripts(t *testing.T) {
	root := t.TempDir()
	withWorkingDirectory(t, root)
	filename := "agentic-proofkit-1.2.3.tgz"
	manifest := strings.Replace(packageManifestFixture("git+https://github.com/research-engineering/agentic-proofkit.git"), "\n}", ",\n  \"scripts\": {\"preinstall\": \"node install.js\"}\n}", 1)
	tarball := writePackageTarball(t, map[string]string{"package/package.json": manifest})
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
	if err == nil || !strings.Contains(err.Error(), "lifecycle script preinstall") {
		t.Fatalf("verifyRootManifestBoundary() error=%v, want lifecycle script rejection", err)
	}
}

func TestSnapshotReadersDoNotRereadMutableTarballPath(t *testing.T) {
	tarball := writePackageTarball(t, map[string]string{
		"package/ADOPTION.md":                             "package docs describe embedded Go binaries.",
		"package/AGENTS.md":                               "package docs describe embedded Go binaries.",
		"package/BACKLOG.md":                              "package docs describe embedded Go binaries.",
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
			name:      "adoption doc private namespace",
			path:      "package/ADOPTION.md",
			wantPath:  "package/ADOPTION.md",
			staleText: "repository " + "W25" + "X80" + "/agentic-proofkit",
		},
		{
			name:      "backlog doc personal namespace",
			path:      "package/BACKLOG.md",
			wantPath:  "package/BACKLOG.md",
			staleText: "published by " + "ipe" + "rev",
		},
		{
			name:      "adoption doc consumer scoped package",
			path:      "package/ADOPTION.md",
			wantPath:  "package/ADOPTION.md",
			staleText: "old package " + "@" + "a" + "fc" + "/proofkit",
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

func TestVerifyNoStalePackageDocsRejectsMutableReleaseFactsInMarkdown(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
	}{
		{
			name: "exact release version",
			text: "Current release is @research-engineering/agentic-proofkit@0.1.143.",
		},
		{
			name: "future major package coordinate",
			text: "Current release is @research-engineering/agentic-proofkit@1.0.0.",
		},
		{
			name: "tag version token",
			text: "Public-source provenance is admitted for v1.2.3.",
		},
		{
			name: "provider run URL",
			text: "Provider run: https://github.com/research-engineering/agentic-proofkit/actions/runs/28703265655",
		},
		{
			name: "provider run URL embedded in another URL",
			text: "Provider run mirror: https://example.invalid/?next=https://github.com/research-engineering/agentic-proofkit/actions/runs/28703265655",
		},
		{
			name: "registry tarball URL",
			text: "Tarball: https://registry.npmjs.org/@research-engineering/agentic-proofkit/-/agentic-proofkit-0.1.143.tgz",
		},
		{
			name: "integrity",
			text: "integrity sha512-ilPzGnhVL2BJUXjY3bxGZ4w80gxTFCSyvOMH1kmvm1p+YX5XRl0EHF4uDvY35joXOanvjXxJj3qUGLvjfhcY2Q==",
		},
		{
			name: "release sha",
			text: "source commit 202909459f66af97013af209c2b2fc97e9c4981f",
		},
		{
			name: "uppercase release sha",
			text: "shasum 202909459F66AF97013AF209C2B2FC97E9C4981F",
		},
		{
			name: "short source ref",
			text: "source ref 2029094",
		},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			entries := packageDocEntries("package docs describe embedded Go binaries.")
			entries["package/BACKLOG.md"] = item.text
			tarball := writePackageTarball(t, entries)

			err := verifyNoStalePackageDocs(tarballArtifact(t, tarball))
			if err == nil || !strings.Contains(err.Error(), "package/BACKLOG.md contains mutable package-public release fact") {
				t.Fatalf("verifyNoStalePackageDocs() error=%v, want mutable release fact failure", err)
			}
		})
	}
}

func TestVerifyNoStalePackageDocsAllowsManifestVersionOutsideMarkdown(t *testing.T) {
	t.Parallel()

	entries := packageDocEntries("Use @research-engineering/agentic-proofkit@<version> for exact release installs.")
	entries["package/package.json"] = packageManifestFixture("git+https://github.com/research-engineering/agentic-proofkit.git")
	tarball := writePackageTarball(t, entries)

	if err := verifyNoStalePackageDocs(tarballArtifact(t, tarball)); err != nil {
		t.Fatalf("verifyNoStalePackageDocs() error=%v, want package manifest version accepted", err)
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
		"package/ADOPTION.md",
		"package/BACKLOG.md",
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
		"package/ADOPTION.md",
		"package/BACKLOG.md",
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

func TestVerifyJSONAdapterSourceSmokeReportRequiresHardenedGenerator(t *testing.T) {
	source := hardenedAdapterSmokeSource()
	valid := installedCommandResult{
		ExitCode: 0,
		Stdout:   jsonAdapterSmokeStdout(source, digest.SHA256TextRef(source), "proofkit.json-report-cli-adapter-source"),
	}
	if err := verifyJSONAdapterSourceSmokeReport(valid, source); err != nil {
		t.Fatalf("verifyJSONAdapterSourceSmokeReport(valid) error = %v", err)
	}
	missingBoundedReader := strings.ReplaceAll(source, "function readProofkitBoundedTextFile", "function readProofkitTextFile")
	staleUnboundedRead := source + "\nreadFileSync(filePath, \"utf8\");\n"
	cases := []struct {
		name           string
		result         installedCommandResult
		expectedSource string
		want           string
	}{
		{
			name: "stderr",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   valid.Stdout,
				Stderr:   []byte("diagnostic"),
			},
			expectedSource: source,
			want:           "stderr must be empty",
		},
		{
			name: "wrong report kind",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   jsonAdapterSmokeStdout(source, digest.SHA256TextRef(source), "proofkit.other"),
			},
			expectedSource: source,
			want:           "artifactKind=proofkit.other",
		},
		{
			name: "stale hash",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   jsonAdapterSmokeStdout(source, "sha256:stale", "proofkit.json-report-cli-adapter-source"),
			},
			expectedSource: source,
			want:           "hash mismatch",
		},
		{
			name: "self consistent stale source",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   jsonAdapterSmokeStdout(missingBoundedReader, digest.SHA256TextRef(missingBoundedReader), "proofkit.json-report-cli-adapter-source"),
			},
			expectedSource: source,
			want:           "does not match current owner source",
		},
		{
			name: "missing bounded file reader",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   jsonAdapterSmokeStdout(missingBoundedReader, digest.SHA256TextRef(missingBoundedReader), "proofkit.json-report-cli-adapter-source"),
			},
			expectedSource: missingBoundedReader,
			want:           "readProofkitBoundedTextFile",
		},
		{
			name: "stale unbounded read token",
			result: installedCommandResult{
				ExitCode: 0,
				Stdout:   jsonAdapterSmokeStdout(staleUnboundedRead, digest.SHA256TextRef(staleUnboundedRead), "proofkit.json-report-cli-adapter-source"),
			},
			expectedSource: staleUnboundedRead,
			want:           "forbidden stale token",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := verifyJSONAdapterSourceSmokeReport(item.result, item.expectedSource)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("verifyJSONAdapterSourceSmokeReport() error=%v, want %q", err, item.want)
			}
		})
	}
}

func samplePlatformBinaryEntry() string {
	return releaseplatform.PackageTarEntries()[len(releaseplatform.PackageTarEntries())-1]
}

func hardenedAdapterSmokeSource() string {
	return `function readProofkitBoundedTextFile(filePath: string): string {
  const file = openSync(filePath, "r");
  return String(file);
}

export function runProofkitNoInputJsonCommand(): void {
  if (options.inputMode === "none") {
    throw new Error("stable JSON value must not contain unsafe integer numbers");
  }
}
`
}

func jsonAdapterSmokeStdout(source string, sourceHash string, artifactKind string) []byte {
	return []byte(`{"schemaVersion":1,"artifactKind":` + quotedJSON(artifactKind) + `,"format":"json","generatorId":"proofkit.json-report-cli-adapter-source.typescript.v1","language":"typescript","source":` + quotedJSON(source) + `,"sourceFileName":"proofkit-json-report-cli-adapter.ts","sourceSha256":` + quotedJSON(sourceHash) + `,"summary":{"exportedSymbolCount":24,"lineCount":600}}`)
}

func quotedJSON(value string) string {
	content, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(content)
}

func packageDocEntries(content string) map[string]string {
	return map[string]string{
		"package/ADOPTION.md":                                      content,
		"package/AGENTS.md":                                        content,
		"package/BACKLOG.md":                                       content,
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
  "name": "@research-engineering/agentic-proofkit",
  "version": "1.2.3",
  "license": "MIT",
  "packageManager": "npm@11.18.0",
  "type": "module",
  "sideEffects": false,
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
    "ADOPTION.md",
    "AGENTS.md",
    "BACKLOG.md",
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
