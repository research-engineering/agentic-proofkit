package packageartifactrecord

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateCurrentBindsSourceAndArtifactSnapshots(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "proofkit@example.invalid")
	runGit(t, root, "config", "user.name", "Proofkit Test")
	writeFixture(t, root, "source.txt", "source-v1")
	writeFixture(t, root, ".gitignore", "artifacts/\n")
	runGit(t, root, "add", "source.txt", ".gitignore")
	runGit(t, root, "commit", "-m", "fixture")
	baseline, err := ArtifactEvidenceBaseline(root)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "artifacts/package/package.tgz", "artifact-v1")

	revision, sourceDigest, err := SourceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	artifactEvidence, err := ArtifactEvidenceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{
		Argv:                            CanonicalCommandArgv(),
		ArtifactFreshnessBaselineDigest: baseline.FreshnessDigest,
		ArtifactFreshnessDigest:         artifactEvidence.FreshnessDigest,
		ArtifactSnapshotDigest:          artifactEvidence.SnapshotDigest,
		CommandID:                       CommandID,
		EnvironmentDigest:               strings.Repeat("a", 64),
		ExecutionArgv:                   CanonicalExecutionArgv(),
		ExitCode:                        0,
		FinishedAt:                      "2026-07-11T10:00:01Z",
		SchemaVersion:                   SchemaVersion,
		SourceRevision:                  revision,
		SourceSnapshotDigest:            sourceDigest,
		StartedAt:                       "2026-07-11T10:00:00Z",
		Status:                          "passed",
		ToolchainDigest:                 strings.Repeat("b", 64),
	}
	if err := ValidateCurrent(root, record); err != nil {
		t.Fatalf("ValidateCurrent() valid record error = %v", err)
	}

	writeFixture(t, root, "source.txt", "source-v2")
	if err := ValidateCurrent(root, record); err == nil || !strings.Contains(err.Error(), "source snapshot is stale") {
		t.Fatalf("ValidateCurrent() source mutation error = %v", err)
	}
	writeFixture(t, root, "source.txt", "source-v1")
	writeFixture(t, root, "artifacts/package/package.tgz", "artifact-v2")
	if err := ValidateCurrent(root, record); err == nil || !strings.Contains(err.Error(), "artifact snapshot is stale") {
		t.Fatalf("ValidateCurrent() artifact mutation error = %v", err)
	}
}

func TestCanonicalArgvAccessorsReturnMutationIsolatedCopies(t *testing.T) {
	command := CanonicalCommandArgv()
	execution := CanonicalExecutionArgv()
	command[0] = "mutated"
	execution[0] = "mutated"
	if got := CanonicalCommandArgv(); got[0] != "npm" {
		t.Fatalf("canonical command argv was mutated through returned copy: %v", got)
	}
	if got := CanonicalExecutionArgv(); got[0] != "npm" {
		t.Fatalf("canonical execution argv was mutated through returned copy: %v", got)
	}
}

func TestEnvironmentDigestBindsAllowlistedBuildFactsWithoutHashingArbitrarySecrets(t *testing.T) {
	baseline := EnvironmentDigest([]string{"GOFLAGS=-mod=readonly", "SECRET_TOKEN=low-entropy-secret"})
	if got := EnvironmentDigest([]string{"GOFLAGS=-mod=readonly", "SECRET_TOKEN=different-secret"}); got != baseline {
		t.Fatalf("arbitrary secret-bearing environment changed admitted environment digest: %s != %s", got, baseline)
	}
	if got := EnvironmentDigest([]string{"GOFLAGS=-mod=vendor", "SECRET_TOKEN=low-entropy-secret"}); got == baseline {
		t.Fatal("allowlisted build environment change did not change digest")
	}
}

func TestSourceSnapshotRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	writeFixture(t, root, "target.txt", "target")
	if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "target.txt", "link.txt")

	_, _, err := SourceSnapshot(root)
	if err == nil || !strings.Contains(err.Error(), "symlinks are not admitted") {
		t.Fatalf("SourceSnapshot() symlink error = %v", err)
	}
}

func TestArtifactSnapshotRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "artifact-target.txt", "target")
	artifactDir := filepath.Join(root, "artifacts", "package")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "artifact-target.txt"), filepath.Join(artifactDir, "package.tgz")); err != nil {
		t.Fatal(err)
	}

	_, err := ArtifactSnapshot(root)
	if err == nil || !strings.Contains(err.Error(), "symlinks are not admitted") {
		t.Fatalf("ArtifactSnapshot() symlink error = %v", err)
	}
}

func TestArtifactSnapshotIgnoresFilesOutsideOwnedOutputRoots(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "artifacts/package/package.tgz", "package")
	before, err := ArtifactEvidenceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "artifacts/.DS_Store", "ambient metadata")
	afterAmbient, err := ArtifactEvidenceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if before != afterAmbient {
		t.Fatalf("ambient artifact metadata changed owned evidence: before=%+v after=%+v", before, afterAmbient)
	}
	writeFixture(t, root, "artifacts/package/package.tgz", "changed package")
	afterOwnedChange, err := ArtifactEvidenceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.SnapshotDigest == afterOwnedChange.SnapshotDigest {
		t.Fatal("owned artifact content change did not change snapshot digest")
	}
}

func TestSnapshotDigestBindsNormalizedMode(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "source.txt", "source")
	first, err := digestPaths(root, []string{"source.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "source.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := digestPaths(root, []string{"source.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("digestPaths() did not bind normalized file mode")
	}
}

func TestSnapshotDigestRejectsNonRegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "not-a-file"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := digestPaths(root, []string{"not-a-file"})
	if err == nil || !strings.Contains(err.Error(), "non-regular files are not admitted") {
		t.Fatalf("digestPaths() non-regular file error = %v", err)
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func writeFixture(t *testing.T, root string, relativePath string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
