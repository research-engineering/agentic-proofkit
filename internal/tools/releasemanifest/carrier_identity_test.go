package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestCrossCarrierBinaryIdentityReadsFinalArchives(t *testing.T) {
	t.Run("matching_carriers", func(t *testing.T) {
		packageDir, pythonDir, records, packages := writeCarrierFixture(t, "")
		identities, err := verifyCrossCarrierBinaryIdentity(packageDir, pythonDir, records, packages)
		if err != nil {
			t.Fatal(err)
		}
		if len(identities.wheelsByName) != len(releaseplatform.Targets()) {
			t.Fatalf("decoded wheel identity count=%d", len(identities.wheelsByName))
		}
		for _, target := range releaseplatform.Targets() {
			filename := target.PlatformSuffix + ".whl"
			want := sha256.Sum256(carrierBinary(target.PlatformSuffix))
			if got := identities.wheelsByName[filename].binarySHA256; got != fmt.Sprintf("%x", want) {
				t.Fatalf("binary digest for %s=%s", filename, got)
			}
		}
	})

	t.Run("wheel_mutation", func(t *testing.T) {
		packageDir, pythonDir, records, packages := writeCarrierFixture(t, "linux-x64")
		_, err := verifyCrossCarrierBinaryIdentity(packageDir, pythonDir, records, packages)
		if err == nil || !strings.Contains(err.Error(), "different release-platform binary bytes") {
			t.Fatalf("mutated wheel was not rejected: %v", err)
		}
	})

	t.Run("duplicate_tar_member", func(t *testing.T) {
		packageDir, pythonDir, records, packages := writeCarrierFixture(t, "")
		writeNPMCarrier(t, filepath.Join(packageDir, records[0].Filename), "binary")
		_, err := verifyCrossCarrierBinaryIdentity(packageDir, pythonDir, records, packages)
		if err == nil || !strings.Contains(err.Error(), "duplicate tar entry") {
			t.Fatalf("duplicate npm binary was not rejected: %v", err)
		}
	})

	t.Run("duplicate_non_binary_tar_member", func(t *testing.T) {
		packageDir, pythonDir, records, packages := writeCarrierFixture(t, "")
		writeNPMCarrier(t, filepath.Join(packageDir, records[0].Filename), "metadata")
		_, err := verifyCrossCarrierBinaryIdentity(packageDir, pythonDir, records, packages)
		if err == nil || !strings.Contains(err.Error(), "duplicate tar entry") {
			t.Fatalf("duplicate npm metadata entry was not rejected: %v", err)
		}
	})
}

func TestCrossCarrierTraversalCountsPAXMetadata(t *testing.T) {
	for _, count := range []int{1, 1024} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			packageDir, pythonDir, records, packages := writeCarrierFixture(t, "")
			path := filepath.Join(packageDir, records[0].Filename)
			writeNPMCarrierWithMetadata(t, path, "", count)
			info, err := os.Stat(path)
			if err != nil || info.Size() >= 256<<20 {
				t.Fatalf("metadata fixture must fit compressed budget: %v", err)
			}
			_, err = verifyCrossCarrierBinaryIdentity(packageDir, pythonDir, records, packages)
			if count == 1 {
				if err != nil {
					t.Fatalf("valid PAX carrier rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "expanded byte limit") {
				t.Fatalf("PAX traversal did not reject by its physical byte budget: %v", err)
			}
		})
	}
}

func TestCrossCarrierTraversalRequiresGzipIntegrity(t *testing.T) {
	packageDir, pythonDir, records, packages := writeCarrierFixture(t, "")
	path := filepath.Join(packageDir, records[0].Filename)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-8] ^= 1
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = verifyCrossCarrierBinaryIdentity(packageDir, pythonDir, records, packages)
	if !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("carrier CRC failure was not propagated: %v", err)
	}
}

func TestWheelCarrierChecksTopologyAndSameLengthContent(t *testing.T) {
	expectedPath := filepath.Join(t.TempDir(), "expected")
	writeFile(t, expectedPath, "binary-a")
	extra := zip.FileHeader{Name: "agentic_proofkit/extra.py", Method: zip.Store}
	extra.SetMode(0o644)
	symlink := extra
	symlink.SetMode(os.ModeSymlink | 0o777)
	for _, test := range []struct {
		name, content string
		extras        []zip.FileHeader
		equal         bool
		wantError     string
	}{
		{"matching", "binary-a", []zip.FileHeader{extra}, true, ""},
		{"different bytes", "binary-b", nil, false, ""},
		{"unsafe member", "binary-a", []zip.FileHeader{symlink}, false, "canonical regular ZIP entries"},
		{"duplicate member", "binary-a", []zip.FileHeader{extra, extra}, false, "duplicate ZIP entries"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "carrier.whl")
			writeWheelCarrier(t, path, []byte(test.content), test.extras...)
			equal, _, err := wheelCarrierBinaryEquals(path, extractedCarrierBinary{path: expectedPath, size: int64(len("binary-a"))})
			if equal != test.equal ||
				(test.wantError == "" && err != nil) ||
				(test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError))) {
				t.Fatalf("wheel carrier equal=%v err=%v", equal, err)
			}
		})
	}
}

func TestReleaseManifestRejectsCorruptNPMOnlyCarrier(t *testing.T) {
	carrier, _, _ := writeReleaseManifestFixture(t, false)
	if err := run(); err != nil {
		t.Fatalf("valid npm-only release rejected: %v", err)
	}
	metadata := retainReleaseOutputs(t)
	content, err := os.ReadFile(carrier)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-8] ^= 1
	writeFile(t, carrier, string(content))
	writeFixtureNPMRecord(t, carrier)
	if err := run(); !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("generator did not reject the hash-matching CRC mutation: %v", err)
	}
	assertRetainedReleaseOutputs(t, metadata)
}

func writeCarrierFixture(t *testing.T, mutatedWheelSuffix string) (string, string, []packRecord, *pythonPackageSet) {
	t.Helper()
	root := t.TempDir()
	packageDir := filepath.Join(root, "package")
	pythonDir := filepath.Join(root, "pypi")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pythonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	records := []packRecord{{Filename: "proofkit.tgz"}}
	writeNPMCarrier(t, filepath.Join(packageDir, records[0].Filename), "")
	packages := &pythonPackageSet{Packages: make([]pythonWheelRecord, 0, len(releaseplatform.Targets()))}
	for _, target := range releaseplatform.Targets() {
		filename := target.PlatformSuffix + ".whl"
		content := carrierBinary(target.PlatformSuffix)
		if target.PlatformSuffix == mutatedWheelSuffix {
			content = append(content, []byte("-mutated")...)
		}
		writeWheelCarrier(t, filepath.Join(pythonDir, filename), content)
		packages.Packages = append(packages.Packages, pythonWheelRecord{
			Filename:       filename,
			PlatformSuffix: target.PlatformSuffix,
		})
	}
	return packageDir, pythonDir, records, packages
}

func writeNPMCarrier(t *testing.T, path string, duplicate string) {
	t.Helper()
	writeNPMCarrierWithMetadata(t, path, duplicate, 0)
}

func writeNPMCarrierWithMetadata(t *testing.T, path string, duplicate string, metadataEntries int) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	if metadataEntries > 0 {
		comment := strings.Repeat("m", 600<<10)
		for index := range metadataEntries {
			header := tar.Header{Name: fmt.Sprintf("package/pax-%d", index), Mode: 0o644, Typeflag: tar.TypeReg, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": comment}}
			if err := tarWriter.WriteHeader(&header); err != nil {
				t.Fatal(err)
			}
		}
	}
	if duplicate == "metadata" {
		for range 2 {
			content := []byte("metadata")
			if err := tarWriter.WriteHeader(&tar.Header{Name: "package/README.md", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tarWriter.Write(content); err != nil {
				t.Fatal(err)
			}
		}
	}
	for index, target := range releaseplatform.Targets() {
		copies := 1
		if duplicate == "binary" && index == 0 {
			copies = 2
		}
		for range copies {
			content := carrierBinary(target.PlatformSuffix)
			if err := tarWriter.WriteHeader(&tar.Header{Name: target.PackageTarEntry, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tarWriter.Write(content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeWheelCarrier(t *testing.T, path string, content []byte, extras ...zip.FileHeader) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	wheel := zip.NewWriter(file)
	header := &zip.FileHeader{Name: wheelBinaryEntry, Method: zip.Store}
	header.SetMode(0o755)
	member, err := wheel.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(content); err != nil {
		t.Fatal(err)
	}
	for _, extra := range extras {
		if _, err := wheel.CreateHeader(&extra); err != nil {
			t.Fatal(err)
		}
	}
	if err := wheel.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func carrierBinary(platformSuffix string) []byte {
	return []byte("binary:" + platformSuffix)
}
