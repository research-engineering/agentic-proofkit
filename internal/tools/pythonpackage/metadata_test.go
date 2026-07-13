package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testLicenseContent = "MIT License\n"

func TestPythonPackageReadersRejectAmbiguousJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
		read    func(string) error
		want    string
	}{
		{
			name:    "package manifest duplicate key",
			content: `{"name":"@research-engineering/agentic-proofkit","name":"other","version":"1.2.3","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			read: func(path string) error {
				return withPackageJSON(t, path, func() error {
					_, err := readPackageJSON()
					return err
				})
			},
			want: "duplicate object key",
		},
		{
			name:    "package set trailing value",
			content: `{"artifactKind":"proofkit.python-package-set.v1","schemaVersion":1,"packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[]} true`,
			read: func(path string) error {
				_, err := readPackageSet(path)
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

func TestReadPackageJSONRejectsUnsafeWheelMetadata(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "filename unsafe semver prerelease",
			content: `{"name":"@research-engineering/agentic-proofkit","version":"1.2.3-beta.1","description":"Proofkit CLI","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			want:    "PEP 440-compatible wheel version",
		},
		{
			name:    "header injection",
			content: `{"name":"@research-engineering/agentic-proofkit","version":"1.2.3","description":"Proofkit CLI\nClassifier: unsafe","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			want:    "single-line metadata field",
		},
		{
			name:    "missing description",
			content: `{"name":"@research-engineering/agentic-proofkit","version":"1.2.3","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			want:    "must include description",
		},
		{
			name:    "license expression disagrees with repository license",
			content: `{"name":"@research-engineering/agentic-proofkit","version":"1.2.3","description":"Proofkit CLI","license":"Apache-2.0","repository":{"url":"https://example.test/repo"}}`,
			want:    "license must be MIT",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "package.json")
			if err := os.WriteFile(path, []byte(item.content), 0o600); err != nil {
				t.Fatalf("write package.json: %v", err)
			}
			err := withPackageJSON(t, path, func() error {
				_, err := readPackageJSON()
				return err
			})
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("readPackageJSON() error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestMetadataUsesCoreMetadata24LicenseFields(t *testing.T) {
	content := metadata(testPackageManifest("1.2.3"))
	for _, required := range []string{
		"Metadata-Version: 2.4\n",
		"License-Expression: MIT\n",
		"License-File: LICENSE\n",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("metadata() missing %q:\n%s", required, content)
		}
	}
	if strings.Contains(content, "\nLicense: ") {
		t.Fatalf("metadata() retained deprecated License field:\n%s", content)
	}
}

func TestWheelEntriesIncludeCanonicalLicense(t *testing.T) {
	root := t.TempDir()
	for _, source := range []string{
		"python/agentic_proofkit/__init__.py",
		"python/agentic_proofkit/__main__.py",
		"python/agentic_proofkit/cli.py",
	} {
		path := filepath.Join(root, source)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, licenseFilename), []byte(testLicenseContent), 0o600); err != nil {
		t.Fatal(err)
	}

	var entries []wheelEntry
	withWorkingDirectory(t, root, func() {
		var err error
		entries, err = wheelEntries(testPackageManifest("1.2.3"), releaseTargets()[2], []byte("binary"))
		if err != nil {
			t.Fatalf("wheelEntries() error: %v", err)
		}
	})
	wantPath := distInfoDir("1.2.3") + "/licenses/" + licenseFilename
	for _, entry := range entries {
		if entry.Path == wantPath {
			if string(entry.Content) != testLicenseContent {
				t.Fatalf("wheel license = %q, want canonical source license", entry.Content)
			}
			return
		}
	}
	t.Fatalf("wheelEntries() missing %s", wantPath)
}

func TestVerifyWheelContentsRequiresExactWheelMetadata(t *testing.T) {
	target := releaseTargets()[0]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheel(t, path, version, wheelMetadata(target)+"Tag: py3-none-conflicting\n")

	err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256([]byte("binary")), []byte(testLicenseContent))
	if err == nil || !strings.Contains(err.Error(), "WHEEL metadata must match release platform target") {
		t.Fatalf("verifyWheelContents() error=%v, want exact WHEEL metadata rejection", err)
	}
}

func TestWriteWheelAvoidsDataDescriptors(t *testing.T) {
	target := releaseTargets()[0]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheel(t, path, version, wheelMetadata(target))

	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open wheel: %v", err)
	}
	defer reader.Close()
	for _, file := range reader.File {
		if file.Flags&zipDataDescriptorFlag != 0 {
			t.Fatalf("entry %s uses ZIP data descriptor flag", file.Name)
		}
	}
}

func TestVerifyWheelContentsRejectsDataDescriptors(t *testing.T) {
	target := releaseTargets()[0]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeDataDescriptorWheel(t, path, version, wheelMetadata(target))

	err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256([]byte("binary")), []byte(testLicenseContent))
	if err == nil || !strings.Contains(err.Error(), "ZIP data descriptor") {
		t.Fatalf("verifyWheelContents() error=%v, want data descriptor rejection", err)
	}
}

func TestVerifyWheelContentsRejectsEmbeddedBinaryDifferentFromSourceRecord(t *testing.T) {
	target := releaseTargets()[0]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheelWithBinary(t, path, version, wheelMetadata(target), []byte("corrupted-binary"))

	err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256([]byte("source-binary")), []byte(testLicenseContent))
	if err == nil || !strings.Contains(err.Error(), "embedded binary sha256 mismatch") {
		t.Fatalf("verifyWheelContents() error=%v, want embedded/source binary identity rejection", err)
	}
}

func TestVerifyWheelContentsRejectsDarwinTagBelowMachOMinimum(t *testing.T) {
	target := releaseTargets()[0]
	target.PlatformTag = "macosx_11_0_arm64"
	target.WheelTag = "py3-none-" + target.PlatformTag
	version := "1.2.3"
	binaryContent := macho64WithMinimumMacOS(12, 0, 0)
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheelWithBinary(t, path, version, wheelMetadata(target), binaryContent)

	err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256(binaryContent), []byte(testLicenseContent))
	if err == nil || !strings.Contains(err.Error(), "embedded Mach-O requires macOS 12.0") {
		t.Fatalf("verifyWheelContents() error=%v, want stale Darwin tag rejection", err)
	}
}

func TestVerifyWheelContentsAcceptsDarwinTagAtOrAboveMachOMinimum(t *testing.T) {
	for _, platformTag := range []string{"macosx_12_0_arm64", "macosx_13_0_arm64"} {
		t.Run(platformTag, func(t *testing.T) {
			target := releaseTargets()[0]
			target.PlatformTag = platformTag
			target.WheelTag = "py3-none-" + platformTag
			version := "1.2.3"
			binaryContent := macho64WithMinimumMacOS(12, 0, 0)
			path := filepath.Join(t.TempDir(), "wheel.whl")
			writeMinimalWheelWithBinary(t, path, version, wheelMetadata(target), binaryContent)

			if err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256(binaryContent), []byte(testLicenseContent)); err != nil {
				t.Fatalf("verifyWheelContents() error=%v, want truthful Darwin tag accepted", err)
			}
		})
	}
}

func TestMachOMinimumMacOSRejectsTruncatedBuildVersion(t *testing.T) {
	content := macho64WithMinimumMacOS(12, 0, 0)
	binary.LittleEndian.PutUint32(content[36:40], 8)

	_, err := machoMinimumMacOS(content)
	if err == nil {
		t.Fatalf("machoMinimumMacOS() error=%v, want truncated command rejection", err)
	}
}

func TestMachOMinimumMacOSAcceptsLegacyVersionCommand(t *testing.T) {
	content := macho64WithMinimumMacOS(12, 0, 0)
	binary.LittleEndian.PutUint32(content[32:36], machoMinimumVersionCommand)
	binary.LittleEndian.PutUint32(content[36:40], machoMinimumVersionCommandSize)
	binary.LittleEndian.PutUint32(content[20:24], machoMinimumVersionCommandSize)
	binary.LittleEndian.PutUint32(content[40:44], 12<<16)
	content = content[:32+machoMinimumVersionCommandSize]

	minimum, err := machoMinimumMacOS(content)
	if err != nil {
		t.Fatalf("machoMinimumMacOS() error=%v", err)
	}
	if minimum != 12<<16 {
		t.Fatalf("machoMinimumMacOS()=%#x, want macOS 12.0", minimum)
	}
}

func TestVerifyWheelContentsRejectsLegacyLicenseMetadata(t *testing.T) {
	target := releaseTargets()[2]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheelFixture(t, path, version, wheelMetadata(target), []byte("binary"), "Metadata-Version: 2.1\nLicense: MIT\n", true, []byte(testLicenseContent))

	err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256([]byte("binary")), []byte(testLicenseContent))
	if err == nil || !strings.Contains(err.Error(), "METADATA mismatch") {
		t.Fatalf("verifyWheelContents() error=%v, want legacy METADATA rejection", err)
	}
}

func TestVerifyWheelContentsRequiresLicenseFile(t *testing.T) {
	target := releaseTargets()[2]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheelFixture(t, path, version, wheelMetadata(target), []byte("binary"), metadata(testPackageManifest(version)), false, nil)

	err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256([]byte("binary")), []byte(testLicenseContent))
	if err == nil || !strings.Contains(err.Error(), "licenses/LICENSE") {
		t.Fatalf("verifyWheelContents() error=%v, want missing license rejection", err)
	}
}

func TestVerifyWheelContentsRejectsDifferentLicenseFile(t *testing.T) {
	target := releaseTargets()[2]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheelFixture(t, path, version, wheelMetadata(target), []byte("binary"), metadata(testPackageManifest(version)), true, []byte("different license\n"))

	err := verifyWheelContents(path, testPackageManifest(version), target, binarySHA256([]byte("binary")), []byte(testLicenseContent))
	if err == nil || !strings.Contains(err.Error(), "embedded LICENSE mismatch") {
		t.Fatalf("verifyWheelContents() error=%v, want source/artifact license mismatch rejection", err)
	}
}

func writeMinimalWheel(t *testing.T, path string, version string, wheel string) {
	writeMinimalWheelWithBinary(t, path, version, wheel, []byte("binary"))
}

func writeMinimalWheelWithBinary(t *testing.T, path string, version string, wheel string, binary []byte) {
	writeMinimalWheelFixture(t, path, version, wheel, binary, metadata(testPackageManifest(version)), true, []byte(testLicenseContent))
}

func writeMinimalWheelFixture(t *testing.T, path string, version string, wheel string, binary []byte, metadataContent string, includeLicense bool, license []byte) {
	t.Helper()
	distInfo := distInfoDir(version)
	entries := []wheelEntry{
		{Path: "agentic_proofkit/__init__.py", Mode: 0o644},
		{Path: "agentic_proofkit/__main__.py", Mode: 0o644},
		{Path: "agentic_proofkit/cli.py", Mode: 0o644},
		{Path: "agentic_proofkit/bin/agentic-proofkit", Content: binary, Mode: 0o755},
		{Path: distInfo + "/METADATA", Content: []byte(metadataContent), Mode: 0o644},
		{Path: distInfo + "/WHEEL", Content: []byte(wheel), Mode: 0o644},
		{Path: distInfo + "/entry_points.txt", Content: []byte(entryPoints()), Mode: 0o644},
	}
	if includeLicense {
		entries = append(entries, wheelEntry{Path: distInfo + "/licenses/LICENSE", Content: license, Mode: 0o644})
	}
	recordPath := distInfo + "/RECORD"
	entries = append(entries, wheelEntry{Path: recordPath, Content: recordContent(entries, recordPath), Mode: 0o644})
	if err := writeWheel(path, entries); err != nil {
		t.Fatalf("write wheel: %v", err)
	}
}

func testPackageManifest(version string) packageJSON {
	return packageJSON{
		Description: "Proofkit CLI",
		License:     "MIT",
		Name:        npmPackageName,
		Repository: repositoryJSON{
			URL: "git+https://example.test/proofkit.git",
		},
		Version: version,
	}
}

func macho64WithMinimumMacOS(major uint32, minor uint32, patch uint32) []byte {
	const (
		machoHeader64Size = 32
		buildVersionSize  = 24
	)
	content := make([]byte, machoHeader64Size+buildVersionSize)
	binary.LittleEndian.PutUint32(content[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(content[4:8], 0x0100000c)
	binary.LittleEndian.PutUint32(content[12:16], 2)
	binary.LittleEndian.PutUint32(content[16:20], 1)
	binary.LittleEndian.PutUint32(content[20:24], buildVersionSize)
	binary.LittleEndian.PutUint32(content[32:36], 0x32)
	binary.LittleEndian.PutUint32(content[36:40], buildVersionSize)
	binary.LittleEndian.PutUint32(content[40:44], 1)
	minimum := major<<16 | minor<<8 | patch
	binary.LittleEndian.PutUint32(content[44:48], minimum)
	binary.LittleEndian.PutUint32(content[48:52], minimum)
	return content
}

func binarySHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:])
}

func writeDataDescriptorWheel(t *testing.T, path string, version string, wheel string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create wheel: %v", err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	defer writer.Close()
	distInfo := distInfoDir(version)
	entries := map[string]string{
		"agentic_proofkit/__init__.py":          "",
		"agentic_proofkit/__main__.py":          "",
		"agentic_proofkit/cli.py":               "",
		"agentic_proofkit/bin/agentic-proofkit": "binary",
		distInfo + "/METADATA":                  "Metadata-Version: 2.1\n",
		distInfo + "/WHEEL":                     wheel,
		distInfo + "/entry_points.txt":          entryPoints(),
		distInfo + "/RECORD":                    "",
	}
	for name, content := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
}

func withPackageJSON(t *testing.T, source string, fn func() error) error {
	t.Helper()
	root := t.TempDir()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), content, 0o600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	var result error
	withWorkingDirectory(t, root, func() {
		result = fn()
	})
	return result
}

func withWorkingDirectory(t *testing.T, root string, fn func()) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir temp root: %v", err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()
	fn()
}
