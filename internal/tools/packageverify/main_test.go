package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func TestVerifyPackedOwnerRecordsRejectsSourceArtifactContentDrift(t *testing.T) {
	root := t.TempDir()
	withWorkingDirectory(t, root)
	entries := []string{
		"package/LICENSE",
		"package/package.json",
		"package/docs/specs/example/requirements.v1.json",
		"package/proofkit/cli-contract.v2.json",
	}
	for _, entry := range entries {
		sourcePath := strings.TrimPrefix(entry, "package/")
		writeFileBytes(t, filepath.Join(root, filepath.FromSlash(sourcePath)), []byte("source-owner\n"))
		tarball := writePackageTarball(t, map[string]string{entry: "corrupted-packed-owner\n"})
		artifact := tarballArtifact(t, tarball)
		artifact.Entries = []string{entry}

		err := verifyPackedOwnerRecordsMatchSource(artifact)
		if err == nil || !strings.Contains(err.Error(), "does not match source owner") {
			t.Fatalf("verifyPackedOwnerRecordsMatchSource(%s) error=%v, want content-identity failure", entry, err)
		}
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

func TestVerifyRootManifestBoundaryRejectsDevDependencyDrift(t *testing.T) {
	cases := []struct {
		name  string
		patch func(string) string
	}{
		{
			name: "missing dependency",
			patch: func(manifest string) string {
				return strings.Replace(manifest, "    \"axe-core\": \"4.12.1\",\n", "", 1)
			},
		},
		{
			name: "wrong dependency version",
			patch: func(manifest string) string {
				return strings.Replace(manifest, "\"axe-core\": \"4.12.1\"", "\"axe-core\": \"4.12.0\"", 1)
			},
		},
		{
			name: "surplus wrapper dependency",
			patch: func(manifest string) string {
				return strings.Replace(
					manifest,
					"  \"devDependencies\": {\n",
					"  \"devDependencies\": {\n    \"@axe-core/playwright\": \"4.12.1\",\n",
					1,
				)
			},
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
			if err == nil || !strings.Contains(err.Error(), "devDependencies must equal") {
				t.Fatalf("verifyRootManifestBoundary() error=%v, want devDependencies failure", err)
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

func TestPackageVerifierDiagnosticNondisclosure(t *testing.T) {
	for _, value := range []string{
		"package verification failed for api_key=abc123456789",
		"package verification failed for line\nbreak",
		"package verification failed for unsafe\u200bvalue",
		string([]byte{'p', 'a', 't', 'h', 0xff}),
	} {
		var output bytes.Buffer
		writeVerificationFailure(&output, errors.New(value))
		if got, want := output.String(), "<redacted-diagnostic-value>\n"; got != want {
			t.Fatalf("visible package diagnostic = %q, want %q", got, want)
		}
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
		"package/NON_CLAIMS.md":                           "package docs describe embedded Go binaries.",
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
			name:      "security doc personal namespace",
			path:      "package/SECURITY.md",
			wantPath:  "package/SECURITY.md",
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
			path:      "package/proofkit/cli-contract.v2.json",
			wantPath:  "package/proofkit/cli-contract.v2.json",
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
			entries["package/README.md"] = item.text
			tarball := writePackageTarball(t, entries)

			err := verifyNoStalePackageDocs(tarballArtifact(t, tarball))
			if err == nil || !strings.Contains(err.Error(), "package/README.md contains mutable package-public release fact") {
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

func TestPackagePublicReferenceClosure(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{name: "valid closure"},
		{
			name: "source-only backlog owner row",
			mutate: func(entries map[string]string) {
				entries["package/README.md"] = strings.Replace(
					entries["package/README.md"],
					"\n\n[Adoption]",
					"\n| Active work ledger | `BACKLOG.md` |\n\n[Adoption]",
					1,
				)
			},
			want: "dangling package-public route BACKLOG.md",
		},
		{
			name: "dangling Markdown destination",
			mutate: func(entries map[string]string) {
				entries["package/README.md"] += "[Missing](MISSING.md)\n"
			},
			want: "dangling package-public Markdown destination MISSING.md",
		},
		{
			name: "dangling reference-style Markdown destination",
			mutate: func(entries map[string]string) {
				entries["package/README.md"] += "[Missing][missing]\n[missing]: MISSING.md\n"
			},
			want: "dangling package-public Markdown destination MISSING.md",
		},
		{
			name: "dangling route-bearing README code span",
			mutate: func(entries map[string]string) {
				entries["package/README.md"] = strings.Replace(
					entries["package/README.md"],
					"docs/proofkit-contract-map.md",
					"docs/MISSING.md",
					1,
				)
			},
			want: "dangling package-public route docs/MISSING.md",
		},
		{
			name: "dangling machine route",
			mutate: func(entries map[string]string) {
				entries["package/proofkit/receipt-producer-policy.json"] = `{"producers":[{"producerId":"local.developer","evidenceRefs":["docs/missing.json"]}]}`
			},
			want: "dangling package-public route docs/missing.json",
		},
		{
			name: "source-only witness misclassified as package public",
			mutate: func(entries map[string]string) {
				entries["package/proofkit/cli-contract.v2.json"] = `{"commands":[{"command":"fixture","inputContract":{"nativeSource":{"path":"internal/fixture.go","evidenceClass":"package_public"}}}]}`
			},
			want: "must declare evidenceClass=source_checkout",
		},
		{
			name: "dangling help catalog source",
			mutate: func(entries map[string]string) {
				entries["package/proofkit/cli-contract.v2.json"] = `{"processContract":{"helpGrammar":{"helpCatalogFormsSource":"MISSING.json"}},"commands":[]}`
			},
			want: "dangling package-public route MISSING.json",
		},
		{
			name: "dangling binding witness path",
			mutate: func(entries map[string]string) {
				entries["package/proofkit/requirement-bindings.json"] = `{"requirements":[{"specPath":"docs/specs/example/requirements.v1.json"}],"bindings":[{"witnessPath":"MISSING.go"}]}`
			},
			want: "dangling source-checkout route MISSING.go",
		},
		{
			name: "dangling requirement source overview path",
			mutate: func(entries map[string]string) {
				entries["package/docs/specs/example/requirements.v1.json"] = `{"specPackagePath":"docs/specs/example","overviewPath":"MISSING.md","requirementsPath":"docs/specs/example/requirements.v1.json","requirements":[]}`
			},
			want: "dangling package-public route MISSING.md",
		},
		{
			name: "dangling witness plan source selector",
			mutate: func(entries map[string]string) {
				entries["package/proofkit/witness-plan.json"] = `{"commands":[],"policies":[{"inputSelectors":["MISSING.md"],"outputSelectors":[],"cacheAdmissionRefs":[]}]}`
			},
			want: "dangling source-checkout route MISSING.md",
		},
		{
			name: "unclassified future machine reference",
			mutate: func(entries map[string]string) {
				entries["package/proofkit/command-families.v1.json"] = `{"families":[],"documentationPath":"MISSING.md"}`
			},
			want: "unclassified reference-bearing field /documentationPath",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			entries := packageReferenceClosureFixture()
			if test.mutate != nil {
				test.mutate(entries)
			}
			tarball := writePackageTarball(t, entries)
			artifact := tarballArtifact(t, tarball)
			entrySet := map[string]struct{}{}
			for entry := range entries {
				entrySet[entry] = struct{}{}
			}
			err := verifyPackagePublicReferenceClosure(artifact, entrySet)
			if test.want == "" {
				if err != nil {
					t.Fatalf("verifyPackagePublicReferenceClosure() error=%v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verifyPackagePublicReferenceClosure() error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestExactTarballOnboardingTrace(t *testing.T) {
	readme := mustReadBytes(t, filepath.Join("..", "..", "..", "README.md"))
	contract := mustReadBytes(t, filepath.Join("..", "..", "..", "proofkit", "cli-contract.v2.json"))
	target, err := releaseplatform.CurrentTarget()
	if err != nil {
		t.Fatalf("current platform has no admitted npm package target: %v", err)
	}
	binaryPath := filepath.Join(t.TempDir(), "agentic-proofkit")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/agentic-proofkit")
	build.Dir = filepath.Join("..", "..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build current product binary: %v\n%s", err, output)
	}
	binary := mustReadBytes(t, binaryPath)
	tarball := writePackageTarball(t, map[string]string{
		"package/package.json":                  `{"name":"@research-engineering/agentic-proofkit","version":"1.2.3","bin":{"agentic-proofkit":"dist/agentic-proofkit"}}`,
		"package/dist/agentic-proofkit":         installedNPMWrapperFixture(target.PlatformSuffix),
		target.PackageTarEntry:                  string(binary),
		"package/README.md":                     string(readme),
		"package/proofkit/cli-contract.v2.json": string(contract),
	})
	content := mustReadBytes(t, tarball)
	artifact := rootPackageArtifact{
		Content: content,
		Record:  packRecord{Filename: "agentic-proofkit-1.2.3.tgz"},
	}
	quotedTempRoot := filepath.Join(t.TempDir(), `proof"kit`)
	if err := os.Mkdir(quotedTempRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", quotedTempRoot)
	if err := withExactTarballConsumer(artifact, func(consumer string) error {
		return verifyInstalledOnboardingTrace(consumer, runInstalledWithInput)
	}); err != nil {
		t.Fatalf("exact tarball onboarding trace failed: %v", err)
	}
}

func installedNPMWrapperFixture(platformSuffix string) string {
	return `#!/usr/bin/env sh
set -eu

script="$0"
while [ -L "$script" ]; do
  link=$(readlink "$script")
  case "$link" in
    /*) script="$link" ;;
    *) script=$(CDPATH= cd -- "$(dirname -- "$script")" && pwd)/"$link" ;;
  esac
done

dir=$(CDPATH= cd -- "$(dirname -- "$script")" && pwd)
package_dir=$(CDPATH= cd -- "$dir/.." && pwd)
binary="$package_dir/dist/platform/` + platformSuffix + `/agentic-proofkit"

AGENTIC_PROOFKIT_LAUNCHER_PROFILE=npm_offline
AGENTIC_PROOFKIT_PYTHON_EXECUTABLE=
export AGENTIC_PROOFKIT_LAUNCHER_PROFILE
export AGENTIC_PROOFKIT_PYTHON_EXECUTABLE

exec "$binary" "$@"
`
}

func TestREADMEInstallPolicyRequiresPreOneExactPinExplanation(t *testing.T) {
	if err := verifyREADMEInstallPolicy(readmePreOneExactPinPolicy); err != nil {
		t.Fatalf("owner policy rejected: %v", err)
	}
	for _, content := range []string{
		"",
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit",
		readmePreOneExactPinPolicy + "\n" + readmePreOneExactPinPolicy,
	} {
		if err := verifyREADMEInstallPolicy(content); err == nil {
			t.Fatalf("invalid README install policy was admitted: %q", content)
		}
	}
}

func TestOnboardingTraceCoversEveryDiscoveredPresetAndREADMEInput(t *testing.T) {
	consumer := t.TempDir()
	rootHelpRoute := "npm exec --offline -- agentic-proofkit help families"
	familyRoutePrefix := "npm exec --offline -- agentic-proofkit help family "
	stackHelpRoute := "npm exec --offline -- agentic-proofkit help stack-preset"
	requirementSourceHelpRoute := "npm exec --offline -- agentic-proofkit help requirement-source-admission"
	selfCheckHelpRoute := "npm exec --offline -- agentic-proofkit help self-check"
	stackInstalledInvocation := ""
	requirementSourceInstalledInvocation := "npm exec --offline -- agentic-proofkit requirement-source-admission --input <path|-> [--input-pointer <pointer>]"
	selfCheckInstalledInvocation := "npm exec --offline -- agentic-proofkit self-check --input <path|->"
	presetRoutePrefix := "npm exec --offline -- agentic-proofkit stack-preset --preset "
	readmeContinuation := "Path: node_modules/@research-engineering/agentic-proofkit/README.md"
	installedRoot := filepath.Join(consumer, "node_modules", "@research-engineering", "agentic-proofkit")
	for _, source := range []string{"README.md", "proofkit/cli-contract.v2.json"} {
		content, err := os.ReadFile(filepath.Join("..", "..", "..", filepath.FromSlash(source)))
		if err != nil {
			t.Fatal(err)
		}
		writeFileBytes(t, filepath.Join(installedRoot, filepath.FromSlash(source)), content)
	}
	choices, err := installedContractPresetIDs(mustReadBytes(t, filepath.Join(installedRoot, "proofkit", "cli-contract.v2.json")))
	if err != nil {
		t.Fatal(err)
	}
	stackInstalledInvocation = "npm exec --offline -- agentic-proofkit stack-preset --preset <" + strings.Join(choices, "|") + ">"
	seenPresets := map[string]struct{}{}
	presetExecutionCounts := map[string]int{}
	presetSuggestedCommands := func(presetID string) []string {
		return []string{
			installedNPMExecCommandPrefix + "stack-preset --preset " + presetID,
			installedNPMExecCommandPrefix + "self-check --input -",
		}
	}
	execute := func(_ string, input []byte, args ...string) (installedCommandResult, error) {
		stdout := ""
		switch {
		case slices.Equal(args, []string{"help"}):
			stdout = rootHelpRoute + "\nCLI/JSON is the public cross-language contract.\n"
		case slices.Equal(args, []string{"help", "families"}):
			stdout = "Command families:\n" +
				"  scaffolding\tScaffolding\n" +
				"    Scaffold projects.\n" +
				"    " + familyRoutePrefix + "scaffolding\n" +
				"  quality\tQuality\n" +
				"    Verify quality.\n" +
				"    " + familyRoutePrefix + "quality\n" +
				"  requirement-source-lifecycle\tRequirement source lifecycle\n" +
				"    Admit requirement sources.\n" +
				"    " + familyRoutePrefix + "requirement-source-lifecycle\n"
		case slices.Equal(args, []string{"help", "family", "scaffolding"}):
			stdout = "Commands:\n  stack-preset\n    " + stackHelpRoute + "\n"
		case slices.Equal(args, []string{"help", "family", "quality"}):
			stdout = "Commands:\n  self-check\n    " + selfCheckHelpRoute + "\n"
		case slices.Equal(args, []string{"help", "family", "requirement-source-lifecycle"}):
			stdout = "Commands:\n  requirement-source-admission\n    " + requirementSourceHelpRoute + "\n"
		case slices.Equal(args, []string{"help", "stack-preset"}):
			stdout = "Usage:\n  agentic-proofkit stack-preset --preset <" + strings.Join(choices, "|") + ">\n" +
				"\nInstalled invocation:\n  " + stackInstalledInvocation + "\n" +
				"Copyable preset commands:\n"
			for _, choice := range choices {
				stdout += "  " + presetRoutePrefix + choice + "\n"
			}
		case slices.Equal(args, []string{"help", "requirement-source-admission"}):
			stdout = "Usage:\n  agentic-proofkit requirement-source-admission --input <path|-> [--input-pointer <pointer>]\n" +
				"\nInstalled invocation:\n  " + requirementSourceInstalledInvocation + "\n" +
				"Continue with the installed README first-valid-input example:\n  " + readmeContinuation + "\n"
		case slices.Equal(args, []string{"help", "self-check"}):
			stdout = "Usage:\n  agentic-proofkit self-check --input <path|->\n" +
				"\nInstalled invocation:\n  " + selfCheckInstalledInvocation + "\n"
		case len(args) == 3 && args[0] == "stack-preset" && args[1] == "--preset":
			seenPresets[args[2]] = struct{}{}
			presetExecutionCounts[args[2]]++
			content, err := json.Marshal(map[string]any{
				"diagnostics": []any{map[string]any{
					"key": "preset",
					"value": map[string]any{
						"suggestedCommands": presetSuggestedCommands(args[2]),
					},
				}},
				"state": "passed",
			})
			if err != nil {
				t.Fatal(err)
			}
			stdout = string(content) + "\n"
		case slices.Equal(args, []string{"requirement-source-admission", "--input", "-"}):
			if len(input) == 0 {
				t.Fatal("README first-input command received empty stdin")
			}
			stdout = `{"state":"passed"}` + "\n"
		default:
			t.Fatalf("unexpected installed argv: %v", args)
		}
		return installedCommandResult{Stdout: []byte(stdout)}, nil
	}
	if err := verifyInstalledOnboardingTrace(consumer, execute); err != nil {
		t.Fatalf("verifyInstalledOnboardingTrace() error=%v", err)
	}
	if len(seenPresets) != len(choices) {
		t.Fatalf("executed preset count=%d, want %d", len(seenPresets), len(choices))
	}
	for _, choice := range choices {
		if _, ok := seenPresets[choice]; !ok {
			t.Fatalf("installed onboarding did not execute preset %s", choice)
		}
	}
	for index, choice := range choices {
		want := 1
		if index == 0 {
			want = 2
		}
		if presetExecutionCounts[choice] != want {
			t.Fatalf("installed preset %s execution count=%d, want %d", choice, presetExecutionCounts[choice], want)
		}
	}

	validPresetSuggestedCommands := presetSuggestedCommands
	for _, mutant := range []struct {
		name     string
		commands func(string) []string
		want     string
	}{
		{
			name: "missing generated commands",
			commands: func(string) []string {
				return nil
			},
			want: "must expose non-empty suggestedCommands",
		},
		{
			name: "bare non-first generated command",
			commands: func(presetID string) []string {
				return []string{
					installedNPMExecCommandPrefix + "stack-preset --preset " + presetID,
					"agentic-proofkit self-check --input -",
				}
			},
			want: "suggestedCommands[1] must use the exact npm exec --offline prefix",
		},
		{
			name: "wrong self-continuation",
			commands: func(string) []string {
				return []string{installedNPMExecCommandPrefix + "stack-preset --preset other"}
			},
			want: "first suggested command must be its exact self-continuation",
		},
		{
			name: "equivalent but non-canonical self-continuation",
			commands: func(presetID string) []string {
				return []string{installedNPMExecCommandPrefix + "stack-preset --preset '" + presetID + "'"}
			},
			want: "first suggested command must be its exact self-continuation",
		},
	} {
		presetSuggestedCommands = mutant.commands
		if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
			!strings.Contains(err.Error(), mutant.want) {
			t.Fatalf("%s error=%v, want %q", mutant.name, err, mutant.want)
		}
	}
	presetSuggestedCommands = validPresetSuggestedCommands

	for _, mutant := range []struct {
		name  string
		route string
		want  string
	}{
		{name: "bare executable", route: "agentic-proofkit help families", want: "must use npm exec --offline"},
		{name: "leading NBSP", route: "\u00a0npm exec --offline -- agentic-proofkit help families", want: "must use npm exec --offline"},
		{name: "trailing NBSP", route: "npm exec --offline -- agentic-proofkit help families\u00a0", want: "must resolve to help families"},
	} {
		rootHelpRoute = mutant.route
		if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
			!strings.Contains(err.Error(), mutant.want) {
			t.Fatalf("%s root-help route error=%v, want %q", mutant.name, err, mutant.want)
		}
	}
	rootHelpRoute = "npm exec --offline -- agentic-proofkit help families"

	familyRoutePrefix = "agentic-proofkit help family "
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "family discovery route must use npm exec --offline") {
		t.Fatalf("bare family route error=%v, want npm exec --offline rejection", err)
	}
	familyRoutePrefix = "npm exec --offline -- agentic-proofkit help family "

	stackHelpRoute = "agentic-proofkit help stack-preset"
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "leaf help route must use npm exec --offline") {
		t.Fatalf("bare leaf route error=%v, want npm exec --offline rejection", err)
	}
	stackHelpRoute = "npm exec --offline -- agentic-proofkit help stack-preset"

	requirementSourceHelpRoute = "agentic-proofkit help requirement-source-admission"
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "leaf help route must use npm exec --offline") {
		t.Fatalf("bare requirement-source leaf route error=%v, want npm exec --offline rejection", err)
	}
	requirementSourceHelpRoute = "npm exec --offline -- agentic-proofkit help requirement-source-admission"

	selfCheckHelpRoute = "agentic-proofkit help self-check"
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "leaf help route must use npm exec --offline") {
		t.Fatalf("bare ordinary leaf route error=%v, want npm exec --offline rejection", err)
	}
	selfCheckHelpRoute = "npm exec --offline -- agentic-proofkit help self-check"

	stackInstalledInvocation = "agentic-proofkit stack-preset --preset <" + strings.Join(choices, "|") + ">"
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "installed invocation must prefix its exact usage with npm exec --offline") {
		t.Fatalf("bare stack invocation error=%v, want installed invocation rejection", err)
	}
	stackInstalledInvocation = "npm exec --offline -- agentic-proofkit stack-preset --preset <" + strings.Join(choices, "|") + ">"

	requirementSourceInstalledInvocation = "agentic-proofkit requirement-source-admission --input <path|-> [--input-pointer <pointer>]"
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "installed invocation must prefix its exact usage with npm exec --offline") {
		t.Fatalf("bare requirement-source invocation error=%v, want installed invocation rejection", err)
	}
	requirementSourceInstalledInvocation = "npm exec --offline -- agentic-proofkit requirement-source-admission --input <path|-> [--input-pointer <pointer>]"

	selfCheckInstalledInvocation = "agentic-proofkit self-check --input <path|->"
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "installed invocation must prefix its exact usage with npm exec --offline") {
		t.Fatalf("bare ordinary invocation error=%v, want installed invocation rejection", err)
	}
	selfCheckInstalledInvocation = "npm exec --offline -- agentic-proofkit self-check --input <path|->"

	presetRoutePrefix = "agentic-proofkit stack-preset --preset "
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "stack preset route must use npm exec --offline") {
		t.Fatalf("bare preset route error=%v, want npm exec --offline rejection", err)
	}
	presetRoutePrefix = "npm exec --offline -- agentic-proofkit stack-preset --preset "

	readmeContinuation = ""
	if err := verifyInstalledOnboardingTrace(consumer, execute); err == nil ||
		!strings.Contains(err.Error(), "must expose the exact installed README path") {
		t.Fatalf("missing README continuation error=%v, want exact path rejection", err)
	}
}

func TestInstalledHelpRouteParsersRejectDuplicateOwnerIDs(t *testing.T) {
	familyHelp := "Command families:\n" +
		"  quality\tQuality\n" +
		"    npm exec --offline -- agentic-proofkit help family quality\n" +
		"  quality\tDuplicate\n" +
		"    npm exec --offline -- agentic-proofkit help family other\n"
	if _, err := parseInstalledFamilyRoutes(familyHelp); err == nil ||
		!strings.Contains(err.Error(), "duplicated family id") {
		t.Fatalf("duplicate family id error=%v", err)
	}

	leafHelp := "Commands:\n" +
		"  self-check\n" +
		"    npm exec --offline -- agentic-proofkit help self-check\n" +
		"  self-check\n" +
		"    npm exec --offline -- agentic-proofkit help other\n"
	if _, err := parseInstalledLeafHelpRoutes(leafHelp); err == nil ||
		!strings.Contains(err.Error(), "duplicate command id") {
		t.Fatalf("duplicate command id error=%v", err)
	}
}

func TestInstalledInvocationRequiresAuthoredOrderAndExactCommandToken(t *testing.T) {
	valid := "Usage:\n" +
		"  agentic-proofkit self-check --input <path|->\n\n" +
		"Installed invocation:\n" +
		"  npm exec --offline -- agentic-proofkit self-check --input <path|->\n"
	if err := requireInstalledInvocationSyntax([]byte(valid), "self-check"); err != nil {
		t.Fatalf("owner installed invocation: %v", err)
	}
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "installed block before usage",
			content: "Installed invocation:\n" +
				"  npm exec --offline -- \n" +
				"Usage:\n" +
				"  agentic-proofkit self-check --input <path|->\n",
		},
		{
			name: "command token prefix collision",
			content: "Usage:\n" +
				"  agentic-proofkit self-checkevil --input <path|->\n\n" +
				"Installed invocation:\n" +
				"  npm exec --offline -- agentic-proofkit self-checkevil --input <path|->\n",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if err := requireInstalledInvocationSyntax([]byte(item.content), "self-check"); err == nil {
				t.Fatal("invalid installed invocation was admitted")
			}
		})
	}
}

func TestInstalledREADMEFirstInputRejectsAmbiguousFences(t *testing.T) {
	valid := `<!-- proofkit:first-valid-input:start -->
` + "```bash\nnpm exec --offline -- agentic-proofkit requirement-source-admission --input -\n```\n\n" + "```json\n{}\n```\n" + `<!-- proofkit:first-valid-input:end -->`
	cases := []struct {
		name    string
		content string
	}{
		{
			name:    "duplicate bash",
			content: strings.Replace(valid, "```json", "```bash\nnpm exec --offline -- agentic-proofkit help\n```\n\n```json", 1),
		},
		{
			name:    "duplicate JSON",
			content: strings.Replace(valid, "<!-- proofkit:first-valid-input:end -->", "```json\n{}\n```\n<!-- proofkit:first-valid-input:end -->", 1),
		},
		{
			name:    "tilde bash",
			content: strings.Replace(valid, "<!-- proofkit:first-valid-input:end -->", "~~~bash\nnpm exec --offline -- agentic-proofkit help\n~~~\n<!-- proofkit:first-valid-input:end -->", 1),
		},
		{
			name:    "tilde JSON",
			content: strings.Replace(valid, "<!-- proofkit:first-valid-input:end -->", "~~~json\n{}\n~~~\n<!-- proofkit:first-valid-input:end -->", 1),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := installedREADMEFirstInput([]byte(test.content))
			if err == nil || !strings.Contains(err.Error(), "must contain one bash command and one JSON value") {
				t.Fatalf("installedREADMEFirstInput() error=%v", err)
			}
		})
	}
}

func TestInstalledREADMEFirstInputUsesBoundedLiteralShellWords(t *testing.T) {
	readme := func(command string) []byte {
		return []byte(`<!-- proofkit:first-valid-input:start -->
` + "```bash\n" + command + "\n```\n\n```json\n{}\n```\n" + `<!-- proofkit:first-valid-input:end -->`)
	}
	accepted := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "single and double quotes",
			command: `npm exec --offline -- agentic-proofkit "requirement-source-admission" --input '-'`,
			want:    []string{"requirement-source-admission", "--input", "-"},
		},
		{
			name:    "escaped literal",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input \-`,
			want:    []string{"requirement-source-admission", "--input", "-"},
		},
		{
			name:    "escaped trailing space",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input value\ `,
			want:    []string{"requirement-source-admission", "--input", "value "},
		},
		{
			name:    "escaped trailing tab",
			command: "npm exec --offline -- agentic-proofkit requirement-source-admission --input value\\\t",
			want:    []string{"requirement-source-admission", "--input", "value\t"},
		},
		{
			name:    "concatenated literal segments",
			command: `npm exec --offline -- agentic-proofkit 'requirement-'source-admission --input "-"`,
			want:    []string{"requirement-source-admission", "--input", "-"},
		},
		{
			name:    "vertical tab is literal",
			command: "npm exec --offline -- agentic-proofkit requirement-source-admission --input -\v",
			want:    []string{"requirement-source-admission", "--input", "-\v"},
		},
		{
			name:    "non-breaking space is literal",
			command: "npm exec --offline -- agentic-proofkit requirement-source-admission --input -\u00a0",
			want:    []string{"requirement-source-admission", "--input", "-\u00a0"},
		},
		{
			name:    "double quoted one-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input "\!"`,
			want:    []string{"requirement-source-admission", "--input", `\!`},
		},
		{
			name:    "double quoted two-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input "\\!"`,
			want:    []string{"requirement-source-admission", "--input", `\!`},
		},
		{
			name:    "double quoted three-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input "\\\!"`,
			want:    []string{"requirement-source-admission", "--input", `\\!`},
		},
		{
			name:    "double quoted four-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input "\\\\!"`,
			want:    []string{"requirement-source-admission", "--input", `\\!`},
		},
		{
			name:    "unquoted one-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input \!`,
			want:    []string{"requirement-source-admission", "--input", `!`},
		},
		{
			name:    "unquoted two-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input \\!`,
			want:    []string{"requirement-source-admission", "--input", `\!`},
		},
		{
			name:    "unquoted three-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input \\\!`,
			want:    []string{"requirement-source-admission", "--input", `\!`},
		},
		{
			name:    "unquoted four-backslash history marker",
			command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input \\\\!`,
			want:    []string{"requirement-source-admission", "--input", `\\!`},
		},
	}
	for _, test := range accepted {
		t.Run("accept/"+test.name, func(t *testing.T) {
			got, _, err := installedREADMEFirstInput(readme(test.command))
			if err != nil {
				t.Fatalf("installedREADMEFirstInput() error=%v", err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("installedREADMEFirstInput() argv=%v, want %v", got, test.want)
			}
		})
	}

	rejected := []struct {
		name    string
		command string
	}{
		{name: "unquoted expansion", command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input $INPUT`},
		{name: "double quoted expansion", command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input "$INPUT"`},
		{name: "double quoted history expansion", command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input "!!"`},
		{name: "control operator", command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input -; true`},
		{name: "glob", command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input *`},
		{name: "unterminated quote", command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input '-'` + "'"},
		{name: "trailing escape", command: `npm exec --offline -- agentic-proofkit requirement-source-admission --input \`},
		{name: "unquoted NUL", command: "npm exec --offline -- agentic-proofkit requirement-source-admission --input \x00"},
		{name: "single quoted NUL", command: "npm exec --offline -- agentic-proofkit requirement-source-admission --input '\x00'"},
		{name: "double quoted NUL", command: "npm exec --offline -- agentic-proofkit requirement-source-admission --input \"\x00\""},
		{name: "escaped NUL", command: "npm exec --offline -- agentic-proofkit requirement-source-admission --input \\" + "\x00"},
	}
	for _, test := range rejected {
		t.Run("reject/"+test.name, func(t *testing.T) {
			_, _, err := installedREADMEFirstInput(readme(test.command))
			if err == nil || !strings.Contains(err.Error(), "bounded literal shell words") {
				t.Fatalf("installedREADMEFirstInput() error=%v", err)
			}
		})
	}
}

func TestInstalledREADMEFirstInputPreservesJSONExampleBytes(t *testing.T) {
	readme := func(input string) []byte {
		return []byte(`<!-- proofkit:first-valid-input:start -->
` + "```bash\nnpm exec --offline -- agentic-proofkit requirement-source-admission --input -\n```\n\n```json\n" + input + "\n```\n" + `<!-- proofkit:first-valid-input:end -->`)
	}

	const validInput = "{\"requirements\":[]} \t"
	_, got, err := installedREADMEFirstInput(readme(validInput))
	if err != nil {
		t.Fatalf("installedREADMEFirstInput() error=%v", err)
	}
	if want := validInput + "\n"; string(got) != want {
		t.Fatalf("installedREADMEFirstInput() input=%q, want %q", got, want)
	}

	_, _, err = installedREADMEFirstInput(readme("{}\u00a0"))
	if err == nil || !strings.Contains(err.Error(), "JSON is invalid") {
		t.Fatalf("installedREADMEFirstInput() NBSP error=%v", err)
	}
}

func TestLiteralShellWordsConsumesLongBackslashRun(t *testing.T) {
	const backslashCount = 128 << 10
	command := strings.Repeat("\\", backslashCount) + "value"
	got, err := parseLiteralShellWords(command)
	if err != nil {
		t.Fatalf("parseLiteralShellWords() error=%v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parseLiteralShellWords() word count=%d, want 1", len(got))
	}
	want := strings.Repeat("\\", backslashCount/2) + "value"
	if got[0] != want {
		t.Fatalf("parseLiteralShellWords() word length=%d, want %d", len(got[0]), len(want))
	}
}

func mustReadBytes(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func packageReferenceClosureFixture() map[string]string {
	return map[string]string{
		"package/README.md":                               readmePreOneExactPinPolicy + "\n\nThe full machine-readable command inventory remains\n`proofkit/cli-contract.v2.json`; the human route map is\n`docs/proofkit-contract-map.md`.\n\n| Need | Owner |\n|---|---|\n| Adoption | `ADOPTION.md` |\n\n[Adoption](ADOPTION.md \"Guide\")\n[Adoption reference][adoption]\n[adoption]: ADOPTION.md \"Guide\"\n",
		"package/ADOPTION.md":                             "Adoption.\n",
		"package/docs/proofkit-contract-map.md":           "Contract map.\n",
		"package/docs/specs/example/overview.md":          "Example.\n",
		"package/docs/specs/example/requirements.v1.json": `{"specPackagePath":"docs/specs/example","overviewPath":"docs/specs/example/overview.md","requirementsPath":"docs/specs/example/requirements.v1.json","requirements":[]}`,
		"package/proofkit/requirement-bindings.json":      `{"requirements":[{"specPath":"docs/specs/example/requirements.v1.json"}],"bindings":[{"witnessPath":"internal/tools/packageverify/main_test.go","witnessSelectors":[{"selector":"TestPackagePublicReferenceClosure","command":"go test ./internal/tools/packageverify -run '^TestPackagePublicReferenceClosure$'"}]}]}`,
		"package/proofkit/witness-plan.json":              `{"commands":[],"policies":[]}`,
		"package/proofkit/command-families.v1.json":       `{"families":[]}`,
		"package/proofkit/receipt-producer-policy.json":   `{"producers":[{"producerId":"local.developer","evidenceRefs":["docs/specs/example/requirements.v1.json"]}]}`,
		"package/proofkit/cli-contract.v2.json":           `{"processContract":{"helpGrammar":{"helpCatalogFormsSource":"proofkit/command-families.v1.json"}},"commands":[{"command":"fixture","inputContract":{"nativeSource":{"path":"internal/tools/packageverify/main.go","evidenceClass":"source_checkout"}}}]}`,
	}
}

func TestVerifyRootPackageRejectsEachForbiddenRootEntry(t *testing.T) {
	forbiddenEntries := []string{
		"package/bun.lock",
		"package/dist/cli.js",
		"package/dist/index.js",
		"package/proofkit/sdk-cli-parity.v1.json",
		"package/tsconfig.json",
		"package/dist/fixture.d.ts",
		"package/dist/fixture.ts",
		"package/dist/fixture.map",
	}
	for _, forbidden := range forbiddenEntries {
		t.Run(forbidden, func(t *testing.T) {
			root := t.TempDir()
			withWorkingDirectory(t, root)
			entries := map[string]string{}
			for _, required := range requiredRootEntries() {
				entries[required] = "fixture"
			}
			entries[forbidden] = "forbidden"
			tarball := writePackageTarball(t, entries)
			content, err := os.ReadFile(tarball)
			if err != nil {
				t.Fatalf("read package tarball: %v", err)
			}
			filename := "agentic-proofkit-1.2.3.tgz"
			writeFileBytes(t, filepath.Join(root, "artifacts", "package", filename), content)
			record := packRecord{
				Filename:  filename,
				Integrity: testNPMIntegrity(content),
				Name:      rootPackageName,
				Shasum:    testSHA1(content),
				Version:   "1.2.3",
			}

			_, err = verifyRootPackage(record)
			if err == nil || !strings.Contains(err.Error(), "forbidden entry "+forbidden) {
				t.Fatalf("verifyRootPackage() error=%v, want rejection of %s", err, forbidden)
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
	return []byte(`{"schemaVersion":1,"artifactKind":` + quotedJSON(artifactKind) + `,"format":"json","generatorId":"proofkit.json-report-cli-adapter-source.typescript.v2","language":"typescript","source":` + quotedJSON(source) + `,"sourceFileName":"proofkit-json-report-cli-adapter.ts","sourceSha256":` + quotedJSON(sourceHash) + `,"summary":{"exportedSymbolCount":24,"lineCount":600}}`)
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
		"package/NON_CLAIMS.md":                                    content,
		"package/README.md":                                        content,
		"package/SECURITY.md":                                      content,
		"package/docs/proofkit-contract-map.md":                    content,
		"package/docs/release-process.md":                          content,
		"package/docs/specs/proofkit-package-boundary/overview.md": content,
		"package/proofkit/cli-contract.v2.json":                    content,
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
		mode := int64(0o644)
		if rootBinaryEntry(name) {
			mode = 0o755
		}
		if err := tarWriter.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     mode,
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
  "devDependencies": {
    "@playwright/test": "1.62.0",
    "axe-core": "4.12.1",
    "typescript": "7.0.2"
  },
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
