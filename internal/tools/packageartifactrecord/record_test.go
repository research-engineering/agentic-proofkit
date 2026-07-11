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
		Argv:                   CanonicalCommandArgv(),
		ArtifactSnapshotDigest: artifactEvidence.SnapshotDigest,
		CommandID:              CommandID,
		EnvironmentDigest:      strings.Repeat("a", 64),
		ExecutionArgv:          CanonicalExecutionArgv(),
		ExitCode:               0,
		FinishedAt:             "2026-07-11T10:00:01Z",
		SchemaVersion:          SchemaVersion,
		SourceRevision:         revision,
		SourceSnapshotDigest:   sourceDigest,
		StartedAt:              "2026-07-11T10:00:00Z",
		Status:                 "passed",
		ToolchainDigest:        strings.Repeat("b", 64),
	}
	if err := ValidateCurrent(root, record); err != nil {
		t.Fatalf("ValidateCurrent() valid record error = %v", err)
	}
	legacyRecord := record
	legacyRecord.SchemaVersion = 1
	if err := ValidateCurrent(root, legacyRecord); err == nil {
		t.Fatal("ValidateCurrent() accepted legacy pre-clean-materialization record")
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

func TestPrepareCandidateArtifactOutputsRemovesOnlyCandidateOwnedOutputs(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"artifacts/package/package.tgz",
		"artifacts/pypi/package.whl",
	} {
		writeFixture(t, root, path, "generated")
	}
	writeFixture(t, root, "artifacts/release/release-manifest.json", `{"artifactKind":"proofkit.release-manifest.v1","channels":[{"status":"candidate"},{"status":"planned"}],"schemaVersion":1}`)
	retainedPath := "artifacts/proofkit/retained.json"
	writeFixture(t, root, retainedPath, "retained")

	if err := PrepareCandidateArtifactOutputs(root); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"artifacts/package", "artifacts/pypi", "artifacts/release"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); !os.IsNotExist(err) {
			t.Fatalf("owned output root %s still exists: %v", path, err)
		}
	}
	if content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(retainedPath))); err != nil || string(content) != "retained" {
		t.Fatalf("non-owned proof artifact changed: content=%q err=%v", content, err)
	}
}

func TestPrepareCandidateArtifactOutputsRejectsProviderEvidenceBeforeMutation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "artifacts/package/package.tgz", "candidate")
	writeFixture(t, root, "artifacts/registry/npm-registry.json", "provider")

	err := PrepareCandidateArtifactOutputs(root)
	if err == nil || !strings.Contains(err.Error(), "rejects ambient provider evidence") {
		t.Fatalf("PrepareCandidateArtifactOutputs() error = %v", err)
	}
	if content, readErr := os.ReadFile(filepath.Join(root, "artifacts/package/package.tgz")); readErr != nil || string(content) != "candidate" {
		t.Fatalf("candidate output changed before provider-evidence rejection: content=%q err=%v", content, readErr)
	}
}

func TestPrepareCandidateArtifactOutputsRejectsUnownedReleaseStateBeforeMutation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "artifacts/package/package.tgz", "candidate")
	writeFixture(t, root, "artifacts/release/unowned.json", "unowned")

	err := PrepareCandidateArtifactOutputs(root)
	if err == nil || !strings.Contains(err.Error(), "rejects unowned release state") {
		t.Fatalf("PrepareCandidateArtifactOutputs() error = %v", err)
	}
	if content, readErr := os.ReadFile(filepath.Join(root, "artifacts/package/package.tgz")); readErr != nil || string(content) != "candidate" {
		t.Fatalf("candidate output changed before unowned-state rejection: content=%q err=%v", content, readErr)
	}
}

func TestPrepareCandidateArtifactOutputsRejectsProviderDerivedReleaseManifestBeforeMutation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "artifacts/package/package.tgz", "candidate")
	writeFixture(t, root, "artifacts/release/release-manifest.json", `{"artifactKind":"proofkit.release-manifest.v1","channels":[{"publicationMode":"published_by_workflow","status":"published"}],"schemaVersion":1}`)

	err := PrepareCandidateArtifactOutputs(root)
	if err == nil || !strings.Contains(err.Error(), "rejects provider-derived release manifest") {
		t.Fatalf("PrepareCandidateArtifactOutputs() error = %v", err)
	}
	if content, readErr := os.ReadFile(filepath.Join(root, "artifacts/package/package.tgz")); readErr != nil || string(content) != "candidate" {
		t.Fatalf("candidate output changed before provider-manifest rejection: content=%q err=%v", content, readErr)
	}
}

func TestPrepareCandidateArtifactOutputsDoesNotFollowArtifactSymlink(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	externalPath := filepath.Join(external, "sentinel.txt")
	if err := os.WriteFile(externalPath, []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "artifacts")); err != nil {
		t.Fatal(err)
	}

	err := PrepareCandidateArtifactOutputs(root)
	if err == nil || !strings.Contains(err.Error(), "traverses a symlink") {
		t.Fatalf("PrepareCandidateArtifactOutputs() error = %v", err)
	}
	if content, readErr := os.ReadFile(externalPath); readErr != nil || string(content) != "retained" {
		t.Fatalf("external sentinel changed through artifact symlink: content=%q err=%v", content, readErr)
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

func TestSnapshotDigestRejectsIntermediateSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	writeFixture(t, external, "package.tgz", "external")
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "artifacts", "package")); err != nil {
		t.Fatal(err)
	}

	_, err := digestPaths(root, []string{"artifacts/package/package.tgz"})
	if err == nil || !strings.Contains(err.Error(), "traverses a symlink") {
		t.Fatalf("digestPaths() intermediate symlink error = %v", err)
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
