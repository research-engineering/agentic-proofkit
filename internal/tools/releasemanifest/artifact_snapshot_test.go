package main

import (
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
	packages := &pythonPackageSet{Packages: make([]pythonWheelRecord, 0, len(releaseplatform.Targets()))}
	for _, target := range releaseplatform.Targets() {
		filename := target.PlatformSuffix + ".whl"
		writeWheelCarrier(t, filepath.Join("artifacts", "pypi", filename), carrierBinary(target.PlatformSuffix))
		packages.Packages = append(packages.Packages, pythonWheelRecord{Filename: filename, PlatformSuffix: target.PlatformSuffix})
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
	if err := snapshot.VerifyCrossCarrierBinaryIdentity(records, packages); err != nil {
		t.Fatal(err)
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

func containsChecksumLine(lines []string, expected string) bool {
	for _, line := range lines {
		if line == expected {
			return true
		}
	}
	return false
}
