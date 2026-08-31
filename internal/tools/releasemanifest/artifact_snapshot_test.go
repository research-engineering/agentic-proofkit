package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestReleaseArtifactSnapshotOwnsOneImmutableEpoch(t *testing.T) {
	root := t.TempDir()
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
	for _, directory := range []string{"artifacts/package", "artifacts/pypi", "artifacts/release"} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	records := []packRecord{{Filename: "proofkit.tgz"}}
	writeNPMCarrier(t, filepath.Join("artifacts", "package", records[0].Filename), "")
	records[0].Shasum, records[0].Integrity = npmFileClaims(t, filepath.Join("artifacts", "package", records[0].Filename))
	packages := &pythonPackageSet{Packages: make([]pythonWheelRecord, 0, len(releaseplatform.Targets()))}
	for _, target := range releaseplatform.Targets() {
		filename := target.PlatformSuffix + ".whl"
		binary := carrierBinary(target.PlatformSuffix)
		path := filepath.Join("artifacts", "pypi", filename)
		writeWheelCarrier(t, path, binary)
		wheelSHA256, err := fileSHA256(path)
		if err != nil {
			t.Fatal(err)
		}
		binarySHA256 := sha256.Sum256(binary)
		packages.Packages = append(packages.Packages, pythonWheelRecord{
			BinarySha256:   fmt.Sprintf("%x", binarySHA256),
			Filename:       filename,
			PlatformSuffix: target.PlatformSuffix,
			Sha256:         wheelSHA256,
		})
	}
	writeFile(t, filepath.Join("artifacts", "release", "sbom.cdx.json"), "{}")

	snapshot, err := newReleaseArtifactSnapshot(records, packages)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snapshot.Close(); err != nil {
			t.Fatal(err)
		}
	})
	admittedRecords, err := snapshot.AdmittedNPMRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(admittedRecords) != 1 || admittedRecords[0].Shasum != records[0].Shasum || admittedRecords[0].Integrity != records[0].Integrity {
		t.Fatalf("admitted npm records drifted: %#v", admittedRecords)
	}
	for _, mutant := range []struct {
		name   string
		mutate func(*packRecord)
	}{
		{name: "npm shasum", mutate: func(record *packRecord) { record.Shasum = strings.Repeat("0", 40) }},
		{name: "npm integrity", mutate: func(record *packRecord) { record.Integrity = "sha512-" + strings.Repeat("A", 88) }},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			mutated := append([]packRecord(nil), records...)
			mutant.mutate(&mutated[0])
			if err := requireRegistryRecordsMatchLocal(mutated, mutated); err != nil {
				t.Fatalf("declaration-only control should agree before byte admission: %v", err)
			}
			if _, err := snapshot.AdmittedNPMRecords(mutated); err == nil || !strings.Contains(err.Error(), "digest claims do not match") {
				t.Fatalf("npm digest mutant was admitted: %v", err)
			}
		})
	}
	if err := snapshot.VerifyCrossCarrierBinaryIdentity(records, packages); err != nil {
		t.Fatal(err)
	}
	for _, mutant := range []struct {
		name   string
		mutate func(*pythonWheelRecord)
	}{
		{name: "wheel digest", mutate: func(record *pythonWheelRecord) { record.Sha256 = strings.Repeat("0", 64) }},
		{name: "binary digest", mutate: func(record *pythonWheelRecord) { record.BinarySha256 = strings.Repeat("0", 64) }},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			mutated := *packages
			mutated.Packages = append([]pythonWheelRecord(nil), packages.Packages...)
			mutant.mutate(&mutated.Packages[0])
			if err := snapshot.VerifyCrossCarrierBinaryIdentity(records, &mutated); err == nil || !strings.Contains(err.Error(), "digest claims do not match") {
				t.Fatalf("digest mutant was admitted: %v", err)
			}
			if _, err := snapshot.AdmittedPythonPackageSet(packages); err == nil {
				t.Fatal("failed digest verification retained stale admitted identities")
			}
			if err := snapshot.VerifyCrossCarrierBinaryIdentity(records, packages); err != nil {
				t.Fatal(err)
			}
		})
	}
	admittedPackages, err := snapshot.AdmittedPythonPackageSet(packages)
	if err != nil {
		t.Fatal(err)
	}
	for index := range admittedPackages.Packages {
		if admittedPackages.Packages[index].Sha256 != packages.Packages[index].Sha256 || admittedPackages.Packages[index].BinarySha256 != packages.Packages[index].BinarySha256 {
			t.Fatalf("derived package identity %d drifted", index)
		}
	}
	assets, checksums, subjectChecksums, err := snapshot.ReleaseEvidence(records, packages)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != len(releaseplatform.Targets())+2 || len(checksums) != len(assets) || len(subjectChecksums) != len(assets)-1 {
		t.Fatalf("snapshot evidence sizes=(%d,%d,%d)", len(assets), len(checksums), len(subjectChecksums))
	}
	for _, subject := range subjectChecksums {
		parts := strings.SplitN(subject, "  ", 2)
		if len(parts) != 2 || !containsChecksumLine(checksums, subject) {
			t.Fatalf("SBOM subject checksum does not reuse the admitted asset identity: %q", subject)
		}
	}

	writeFile(t, filepath.Join("artifacts", "package", records[0].Filename), "replacement")
	if err := snapshot.RevalidateSources(); err == nil || !strings.Contains(err.Error(), "changed after immutable admission") {
		t.Fatalf("same-path replacement was not rejected: %v", err)
	}
	if err := snapshot.VerifyCrossCarrierBinaryIdentity(records, packages); err != nil {
		t.Fatalf("immutable snapshot changed after source replacement: %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := snapshot.ReleaseEvidence(records, packages); err == nil || !strings.Contains(err.Error(), "snapshot is closed") {
		t.Fatalf("closed snapshot remained readable: %v", err)
	}
}

func npmFileClaims(t *testing.T, path string) (string, string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sha1Sum := sha1.Sum(content)
	sha512Sum := sha512.Sum512(content)
	return hex.EncodeToString(sha1Sum[:]), "sha512-" + base64.StdEncoding.EncodeToString(sha512Sum[:])
}

func containsChecksumLine(lines []string, expected string) bool {
	for _, line := range lines {
		if line == expected {
			return true
		}
	}
	return false
}
