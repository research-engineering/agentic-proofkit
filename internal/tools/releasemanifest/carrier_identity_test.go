package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
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
		if len(identities) != len(releaseplatform.Targets()) {
			t.Fatalf("decoded identity count=%d", len(identities))
		}
		for _, target := range releaseplatform.Targets() {
			filename := target.PlatformSuffix + ".whl"
			want := sha256.Sum256(carrierBinary(target.PlatformSuffix))
			if got := identities[filename].binarySHA256; got != fmt.Sprintf("%x", want) {
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
		if err == nil || !strings.Contains(err.Error(), "contains duplicate entries") {
			t.Fatalf("duplicate npm binary was not rejected: %v", err)
		}
	})

	t.Run("duplicate_non_binary_tar_member", func(t *testing.T) {
		packageDir, pythonDir, records, packages := writeCarrierFixture(t, "")
		writeNPMCarrier(t, filepath.Join(packageDir, records[0].Filename), "metadata")
		_, err := verifyCrossCarrierBinaryIdentity(packageDir, pythonDir, records, packages)
		if err == nil || !strings.Contains(err.Error(), "contains duplicate entries") {
			t.Fatalf("duplicate npm metadata entry was not rejected: %v", err)
		}
	})
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
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
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

func writeWheelCarrier(t *testing.T, path string, content []byte) {
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
