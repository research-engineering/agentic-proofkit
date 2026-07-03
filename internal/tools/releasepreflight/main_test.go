package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareNPMExisting(t *testing.T) {
	expected := npmCandidate{Name: "agentic-proofkit", Version: "1.2.3", Shasum: "sha", Integrity: "integrity"}
	actual := npmView{Name: "agentic-proofkit", Version: "1.2.3"}
	actual.Dist.Shasum = "sha"
	actual.Dist.Integrity = "integrity"
	if err := compareNPMExisting(expected, actual); err != nil {
		t.Fatalf("compareNPMExisting() error = %v", err)
	}

	actual.Dist.Shasum = "other"
	if err := compareNPMExisting(expected, actual); err == nil || !strings.Contains(err.Error(), "shasum mismatch") {
		t.Fatalf("compareNPMExisting() error = %v, want shasum mismatch", err)
	}

	expected.Shasum = ""
	if err := compareNPMExisting(expected, actual); err == nil || !strings.Contains(err.Error(), "must include") {
		t.Fatalf("compareNPMExisting() error = %v, want missing candidate metadata", err)
	}
}

func TestCompareNPMCandidateArtifactsBindsDownloadedBytes(t *testing.T) {
	dir := t.TempDir()
	content := []byte("candidate npm artifact")
	filename := "agentic-proofkit-1.2.3.tgz"
	if err := os.WriteFile(filepath.Join(dir, filename), content, 0o600); err != nil {
		t.Fatalf("write candidate artifact: %v", err)
	}
	candidates := []npmCandidate{{
		Name:      "agentic-proofkit",
		Version:   "1.2.3",
		Filename:  filename,
		Shasum:    sha1Hex(content),
		Integrity: sha512Integrity(content),
	}}
	if err := compareNPMCandidateArtifacts(candidates, dir); err != nil {
		t.Fatalf("compareNPMCandidateArtifacts() error = %v", err)
	}

	candidates[0].Integrity = sha512Integrity([]byte("other"))
	if err := compareNPMCandidateArtifacts(candidates, dir); err == nil || !strings.Contains(err.Error(), "integrity mismatch") {
		t.Fatalf("compareNPMCandidateArtifacts() error = %v, want integrity mismatch", err)
	}
}

func TestRunNPMExistingRejectsAmbiguousExpectedJSON(t *testing.T) {
	actualFile := filepath.Join(t.TempDir(), "npm-view.json")
	if err := os.WriteFile(actualFile, []byte(`{"name":"agentic-proofkit","version":"1.2.3","dist":{"shasum":"sha","integrity":"integrity"}}`), 0o600); err != nil {
		t.Fatalf("write npm view: %v", err)
	}
	err := run([]string{
		"npm-existing",
		"--expected-json", `{"name":"agentic-proofkit","name":"other","version":"1.2.3","filename":"agentic-proofkit.tgz","shasum":"sha","integrity":"integrity"}`,
		"--actual-file", actualFile,
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("run(npm-existing) error=%v, want duplicate-key rejection", err)
	}
}

func TestComparePyPIExisting(t *testing.T) {
	candidates := pythonPackageSet{Packages: []wheelRecord{{Filename: "agentic_proofkit-1.2.3-py3-none-any.whl", Sha256: "sha"}}}
	registry := pypiResponse{URLs: []pypiFile{{Filename: "agentic_proofkit-1.2.3-py3-none-any.whl"}}}
	registry.URLs[0].Digests.SHA256 = "sha"
	if err := comparePyPIExisting(candidates, registry); err != nil {
		t.Fatalf("comparePyPIExisting() error = %v", err)
	}

	t.Run("mismatch", func(t *testing.T) {
		mutated := registry
		mutated.URLs[0].Digests.SHA256 = "other"
		if err := comparePyPIExisting(candidates, mutated); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
			t.Fatalf("comparePyPIExisting() error = %v, want sha256 mismatch", err)
		}
	})
	t.Run("extra file", func(t *testing.T) {
		mutated := registry
		mutated.URLs = append(mutated.URLs, pypiFile{Filename: "agentic_proofkit-1.2.3.tar.gz"})
		if err := comparePyPIExisting(candidates, mutated); err == nil || !strings.Contains(err.Error(), "file set mismatch") {
			t.Fatalf("comparePyPIExisting() error = %v, want file set mismatch", err)
		}
	})
	t.Run("duplicate candidate", func(t *testing.T) {
		mutated := candidates
		mutated.Packages = append(mutated.Packages, mutated.Packages[0])
		if err := comparePyPIExisting(mutated, registry); err == nil || !strings.Contains(err.Error(), "duplicate filename") {
			t.Fatalf("comparePyPIExisting() error = %v, want duplicate filename", err)
		}
	})
	t.Run("empty candidate", func(t *testing.T) {
		if err := comparePyPIExisting(pythonPackageSet{}, registry); err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("comparePyPIExisting() error = %v, want empty candidate rejection", err)
		}
	})
}

func TestComparePyPICandidateArtifactsBindsDownloadedBytes(t *testing.T) {
	dir := t.TempDir()
	content := []byte("candidate pypi wheel")
	filename := "agentic_proofkit-1.2.3-py3-none-any.whl"
	if err := os.WriteFile(filepath.Join(dir, filename), content, 0o600); err != nil {
		t.Fatalf("write candidate wheel: %v", err)
	}
	candidates := pythonPackageSet{Packages: []wheelRecord{{
		Filename: filename,
		Sha256:   sha256Hex(content),
	}}}
	if err := comparePyPICandidateArtifacts(candidates, dir); err != nil {
		t.Fatalf("comparePyPICandidateArtifacts() error = %v", err)
	}

	candidates.Packages[0].Sha256 = sha256Hex([]byte("other"))
	if err := comparePyPICandidateArtifacts(candidates, dir); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("comparePyPICandidateArtifacts() error = %v, want sha256 mismatch", err)
	}
}

func TestValidateGitHubReleaseMetadata(t *testing.T) {
	release := githubRelease{TagName: "v1.2.3", Name: "v1.2.3", Body: "notes\n", IsDraft: boolPtr(false), IsPrerelease: boolPtr(false)}
	if err := validateGitHubReleaseMetadata(release, "v1.2.3", "notes\n"); err != nil {
		t.Fatalf("validateGitHubReleaseMetadata() error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*githubRelease)
		want   string
	}{
		{name: "tag drift", mutate: func(value *githubRelease) { value.TagName = "v1.2.4" }, want: "tagName"},
		{name: "title drift", mutate: func(value *githubRelease) { value.Name = "Release 1.2.3" }, want: "name"},
		{name: "missing draft evidence", mutate: func(value *githubRelease) { value.IsDraft = nil }, want: "isDraft"},
		{name: "missing prerelease evidence", mutate: func(value *githubRelease) { value.IsPrerelease = nil }, want: "isPrerelease"},
		{name: "draft", mutate: func(value *githubRelease) { value.IsDraft = boolPtr(true) }, want: "draft"},
		{name: "prerelease", mutate: func(value *githubRelease) { value.IsPrerelease = boolPtr(true) }, want: "prerelease"},
		{name: "body drift", mutate: func(value *githubRelease) { value.Body = "other\n" }, want: "body mismatch"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			mutated := release
			item.mutate(&mutated)
			if err := validateGitHubReleaseMetadata(mutated, "v1.2.3", "notes\n"); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("validateGitHubReleaseMetadata() error = %v, want %q", err, item.want)
			}
		})
	}
}

func sha1Hex(content []byte) string {
	sum := sha1.Sum(content)
	return hex.EncodeToString(sum[:])
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestCompareGitHubReleaseAssets(t *testing.T) {
	expected := []string{"checksums.sha256", "release-manifest.json"}
	assets := []githubAsset{{Name: "checksums.sha256"}, {Name: "release-manifest.json"}}
	if err := compareGitHubReleaseAssets(expected, assets); err != nil {
		t.Fatalf("compareGitHubReleaseAssets() error = %v", err)
	}

	cases := []struct {
		name   string
		want   []string
		assets []githubAsset
		error  string
	}{
		{name: "missing", assets: []githubAsset{{Name: "checksums.sha256"}}, error: "asset set mismatch"},
		{name: "extra", assets: []githubAsset{{Name: "checksums.sha256"}, {Name: "release-manifest.json"}, {Name: "unexpected.txt"}}, error: "asset set mismatch"},
		{name: "duplicate actual", assets: []githubAsset{{Name: "checksums.sha256"}, {Name: "checksums.sha256"}}, error: "duplicate asset"},
		{name: "duplicate expected", want: []string{"checksums.sha256", "checksums.sha256"}, assets: assets, error: "duplicate value"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			want := expected
			if item.want != nil {
				want = item.want
			}
			if err := compareGitHubReleaseAssets(want, item.assets); err == nil || !strings.Contains(err.Error(), item.error) {
				t.Fatalf("compareGitHubReleaseAssets() error = %v, want %q", err, item.error)
			}
		})
	}
}

func TestValidateGitHubSignedTag(t *testing.T) {
	ref := githubTagRef{
		Ref: "refs/tags/v1.2.3",
		Object: githubTagRefObject{
			SHA:  "tag-sha",
			Type: "tag",
		},
	}
	tag := githubTagObject{
		SHA: "tag-sha",
		Tag: "v1.2.3",
		Object: githubTagTarget{
			SHA:  "commit-sha",
			Type: "commit",
		},
		Verification: githubTagVerification{Verified: true},
	}
	if err := validateGitHubSignedTag(ref, tag, "v1.2.3", "commit-sha"); err != nil {
		t.Fatalf("validateGitHubSignedTag() error = %v", err)
	}

	cases := []struct {
		name      string
		mutateRef func(*githubTagRef)
		mutateTag func(*githubTagObject)
		want      string
	}{
		{
			name:      "wrong ref",
			mutateRef: func(value *githubTagRef) { value.Ref = "refs/tags/v1.2.4" },
			want:      "ref refs/tags/v1.2.4",
		},
		{
			name:      "lightweight tag",
			mutateRef: func(value *githubTagRef) { value.Object.Type = "commit" },
			want:      "annotated tag",
		},
		{
			name:      "tag object drift",
			mutateTag: func(value *githubTagObject) { value.SHA = "other-tag-sha" },
			want:      "tag object sha",
		},
		{
			name:      "missing tag object sha",
			mutateTag: func(value *githubTagObject) { value.SHA = "" },
			want:      "tag object sha is missing",
		},
		{
			name:      "tag name drift",
			mutateTag: func(value *githubTagObject) { value.Tag = "v1.2.4" },
			want:      "tag v1.2.4",
		},
		{
			name:      "commit drift",
			mutateTag: func(value *githubTagObject) { value.Object.SHA = "other-commit" },
			want:      "tag target commit",
		},
		{
			name:      "unsigned",
			mutateTag: func(value *githubTagObject) { value.Verification = githubTagVerification{Reason: "unsigned"} },
			want:      "verified signed tag",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			mutatedRef := ref
			mutatedTag := tag
			if item.mutateRef != nil {
				item.mutateRef(&mutatedRef)
			}
			if item.mutateTag != nil {
				item.mutateTag(&mutatedTag)
			}
			err := validateGitHubSignedTag(mutatedRef, mutatedTag, "v1.2.3", "commit-sha")
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("validateGitHubSignedTag() error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestRunGitHubReleaseUsesFiles(t *testing.T) {
	dir := t.TempDir()
	releaseFile := filepath.Join(dir, "release.json")
	notesFile := filepath.Join(dir, "notes.md")
	assetsFile := filepath.Join(dir, "assets.txt")
	if err := os.WriteFile(releaseFile, []byte(`{"tagName":"v1.2.3","name":"v1.2.3","body":"notes\n","isDraft":false,"isPrerelease":false,"assets":[{"name":"checksums.sha256"}]}`), 0o600); err != nil {
		t.Fatalf("write release file: %v", err)
	}
	if err := os.WriteFile(notesFile, []byte("notes\n"), 0o600); err != nil {
		t.Fatalf("write notes file: %v", err)
	}
	if err := os.WriteFile(assetsFile, []byte("checksums.sha256\n"), 0o600); err != nil {
		t.Fatalf("write assets file: %v", err)
	}

	err := run([]string{"github-release", "--release-file", releaseFile, "--tag", "v1.2.3", "--notes-file", notesFile, "--asset-names-file", assetsFile})
	if err != nil {
		t.Fatalf("run(github-release) error = %v", err)
	}
}

func TestRunGitHubReleaseRejectsMissingReleaseStateEvidence(t *testing.T) {
	dir := t.TempDir()
	releaseFile := filepath.Join(dir, "release.json")
	notesFile := filepath.Join(dir, "notes.md")
	assetsFile := filepath.Join(dir, "assets.txt")
	if err := os.WriteFile(releaseFile, []byte(`{"tagName":"v1.2.3","name":"v1.2.3","body":"notes\n","assets":[{"name":"checksums.sha256"}]}`), 0o600); err != nil {
		t.Fatalf("write release file: %v", err)
	}
	if err := os.WriteFile(notesFile, []byte("notes\n"), 0o600); err != nil {
		t.Fatalf("write notes file: %v", err)
	}
	if err := os.WriteFile(assetsFile, []byte("checksums.sha256\n"), 0o600); err != nil {
		t.Fatalf("write assets file: %v", err)
	}

	err := run([]string{"github-release", "--release-file", releaseFile, "--tag", "v1.2.3", "--notes-file", notesFile, "--asset-names-file", assetsFile})
	if err == nil || !strings.Contains(err.Error(), "isDraft must be present") || !strings.Contains(err.Error(), "isPrerelease must be present") {
		t.Fatalf("run(github-release) error = %v, want missing release-state evidence rejection", err)
	}
}

func TestRunGitHubTagUsesFiles(t *testing.T) {
	dir := t.TempDir()
	refFile := filepath.Join(dir, "ref.json")
	tagFile := filepath.Join(dir, "tag.json")
	if err := os.WriteFile(refFile, []byte(`{"ref":"refs/tags/v1.2.3","object":{"sha":"tag-sha","type":"tag"}}`), 0o600); err != nil {
		t.Fatalf("write ref file: %v", err)
	}
	if err := os.WriteFile(tagFile, []byte(`{"sha":"tag-sha","tag":"v1.2.3","object":{"sha":"commit-sha","type":"commit"},"verification":{"verified":true}}`), 0o600); err != nil {
		t.Fatalf("write tag file: %v", err)
	}

	err := run([]string{"github-tag", "--ref-file", refFile, "--tag-file", tagFile, "--tag", "v1.2.3", "--commit", "commit-sha"})
	if err != nil {
		t.Fatalf("run(github-tag) error = %v", err)
	}
}

func TestRunGitHubTagRejectsAmbiguousJSON(t *testing.T) {
	dir := t.TempDir()
	refFile := filepath.Join(dir, "ref.json")
	tagFile := filepath.Join(dir, "tag.json")
	if err := os.WriteFile(refFile, []byte(`{"ref":"refs/tags/v1.2.3","object":{"sha":"tag-sha","type":"tag"}}`), 0o600); err != nil {
		t.Fatalf("write ref file: %v", err)
	}
	if err := os.WriteFile(tagFile, []byte(`{"sha":"tag-sha","tag":"v1.2.3","tag":"v1.2.4","object":{"sha":"commit-sha","type":"commit"},"verification":{"verified":true}}`), 0o600); err != nil {
		t.Fatalf("write tag file: %v", err)
	}

	err := run([]string{"github-tag", "--ref-file", refFile, "--tag-file", tagFile, "--tag", "v1.2.3", "--commit", "commit-sha"})
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("run(github-tag) error = %v, want duplicate-key rejection", err)
	}
}

func TestReadJSONRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(path, []byte(`{"tagName":"v1.2.3","tagName":"v1.2.4"}`), 0o600); err != nil {
		t.Fatalf("write duplicate-key JSON: %v", err)
	}

	var release githubRelease
	err := readJSON(path, &release)
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("readJSON() error = %v, want duplicate-key rejection", err)
	}
}

func TestParseFlagsRejectsUnsupportedAndDuplicateFlags(t *testing.T) {
	if _, err := parseFlags([]string{"--release-file", "release.json", "--unexpected", "value"}, "release-file"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("parseFlags() error = %v, want unsupported flag rejection", err)
	}
	if _, err := parseFlags([]string{"--release-file", "one.json", "--release-file", "two.json"}, "release-file"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("parseFlags() error = %v, want duplicate flag rejection", err)
	}
}

func boolPtr(value bool) *bool {
	return &value
}
