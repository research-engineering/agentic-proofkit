package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/tools/retainedevidence"
)

const maxReleaseJSONBytes = 8 << 20

type npmCandidate struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	Shasum    string `json:"shasum"`
	Integrity string `json:"integrity"`
}

type npmView struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Shasum    string `json:"shasum"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
}

type pythonPackageSet struct {
	Packages []wheelRecord `json:"packages"`
}

type wheelRecord struct {
	Filename string `json:"filename"`
	Sha256   string `json:"sha256"`
}

type pypiResponse struct {
	URLs []pypiFile `json:"urls"`
}

type pypiFile struct {
	Digests struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
	Filename string `json:"filename"`
}

type githubRelease struct {
	Assets       []githubAsset `json:"assets"`
	Body         string        `json:"body"`
	IsDraft      *bool         `json:"isDraft"`
	IsPrerelease *bool         `json:"isPrerelease"`
	Name         string        `json:"name"`
	TagName      string        `json:"tagName"`
}

type githubAsset struct {
	Name string `json:"name"`
}

type githubTagRef struct {
	Object githubTagRefObject `json:"object"`
	Ref    string             `json:"ref"`
}

type githubTagRefObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

type githubTagObject struct {
	Object       githubTagTarget       `json:"object"`
	SHA          string                `json:"sha"`
	Tag          string                `json:"tag"`
	Verification githubTagVerification `json:"verification"`
}

type githubTagTarget struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

type githubTagVerification struct {
	Reason   string `json:"reason"`
	Verified bool   `json:"verified"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: releasepreflight <npm-existing|npm-candidate-artifacts|pypi-existing|pypi-candidate-artifacts|github-tag|github-metadata|github-release|retained-evidence>")
	}
	switch args[0] {
	case "npm-existing":
		options, err := parseFlags(args[1:], "expected-json", "actual-file")
		if err != nil {
			return err
		}
		expected, err := admission.DecodeTypedJSON[npmCandidate](bytes.NewReader([]byte(options["expected-json"])), maxReleaseJSONBytes)
		if err != nil {
			return fmt.Errorf("decode npm expected metadata: %w", err)
		}
		var actual npmView
		if err := readJSON(options["actual-file"], &actual); err != nil {
			return err
		}
		return compareNPMExisting(expected, actual)
	case "npm-candidate-artifacts":
		options, err := parseFlags(args[1:], "metadata-file", "directory")
		if err != nil {
			return err
		}
		var candidates []npmCandidate
		if err := readJSON(options["metadata-file"], &candidates); err != nil {
			return err
		}
		return compareNPMCandidateArtifacts(candidates, options["directory"])
	case "pypi-existing":
		options, err := parseFlags(args[1:], "candidate-file", "registry-file")
		if err != nil {
			return err
		}
		var candidates pythonPackageSet
		if err := readJSON(options["candidate-file"], &candidates); err != nil {
			return err
		}
		var registry pypiResponse
		if err := readJSON(options["registry-file"], &registry); err != nil {
			return err
		}
		return comparePyPIExisting(candidates, registry)
	case "pypi-candidate-artifacts":
		options, err := parseFlags(args[1:], "candidate-file", "directory")
		if err != nil {
			return err
		}
		var candidates pythonPackageSet
		if err := readJSON(options["candidate-file"], &candidates); err != nil {
			return err
		}
		return comparePyPICandidateArtifacts(candidates, options["directory"])
	case "github-metadata", "github-release":
		required := []string{"release-file", "tag", "notes-file"}
		if args[0] == "github-release" {
			required = append(required, "asset-names-file")
		}
		options, err := parseFlags(args[1:], required...)
		if err != nil {
			return err
		}
		var release githubRelease
		if err := readJSON(options["release-file"], &release); err != nil {
			return err
		}
		notes, err := os.ReadFile(options["notes-file"])
		if err != nil {
			return fmt.Errorf("read release notes: %w", err)
		}
		if err := validateGitHubReleaseMetadata(release, options["tag"], string(notes)); err != nil {
			return err
		}
		if args[0] == "github-metadata" {
			return nil
		}
		expectedAssets, err := readLineSet(options["asset-names-file"])
		if err != nil {
			return err
		}
		return compareGitHubReleaseAssets(expectedAssets, release.Assets)
	case "github-tag":
		options, err := parseFlags(args[1:], "ref-file", "tag-file", "tag", "commit")
		if err != nil {
			return err
		}
		var ref githubTagRef
		if err := readJSON(options["ref-file"], &ref); err != nil {
			return err
		}
		var tag githubTagObject
		if err := readJSON(options["tag-file"], &tag); err != nil {
			return err
		}
		return validateGitHubSignedTag(ref, tag, options["tag"], options["commit"])
	case "retained-evidence":
		options, err := parseFlags(args[1:], "artifact-root")
		if err != nil {
			return err
		}
		return retainedevidence.Write(options["artifact-root"])
	default:
		return fmt.Errorf("unknown releasepreflight command %s", args[0])
	}
}

func compareNPMExisting(expected npmCandidate, actual npmView) error {
	if expected.Name == "" || expected.Version == "" || expected.Shasum == "" || expected.Integrity == "" {
		return fmt.Errorf("candidate npm metadata must include name, version, shasum, and integrity")
	}
	failures := []string{}
	if actual.Name != expected.Name {
		failures = append(failures, fmt.Sprintf("name %s !== %s", actual.Name, expected.Name))
	}
	if actual.Version != expected.Version {
		failures = append(failures, fmt.Sprintf("version %s !== %s", actual.Version, expected.Version))
	}
	if actual.Dist.Shasum != expected.Shasum {
		failures = append(failures, "shasum mismatch")
	}
	if actual.Dist.Integrity != expected.Integrity {
		failures = append(failures, "integrity mismatch")
	}
	if len(failures) > 0 {
		return fmt.Errorf("published %s@%s does not match candidate: %s", expected.Name, expected.Version, strings.Join(failures, "; "))
	}
	return nil
}

func compareNPMCandidateArtifacts(candidates []npmCandidate, directory string) error {
	if len(candidates) == 0 {
		return fmt.Errorf("candidate npm package metadata must not be empty")
	}
	expected := map[string]npmCandidate{}
	for _, item := range candidates {
		if item.Name == "" || item.Version == "" || item.Filename == "" || item.Shasum == "" || item.Integrity == "" {
			return fmt.Errorf("candidate npm metadata must include name, version, filename, shasum, and integrity")
		}
		if filepath.Base(item.Filename) != item.Filename {
			return fmt.Errorf("candidate npm filename must be a basename: %s", item.Filename)
		}
		if _, exists := expected[item.Filename]; exists {
			return fmt.Errorf("candidate npm metadata contains duplicate filename %s", item.Filename)
		}
		expected[item.Filename] = item
	}
	actualFiles, err := fileBasenames(directory, "*.tgz")
	if err != nil {
		return err
	}
	if err := compareStringSet(keys(expected), actualFiles, "candidate npm artifact file set"); err != nil {
		return err
	}
	failures := []string{}
	for filename, item := range expected {
		path := filepath.Join(directory, filename)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read candidate npm artifact %s: %w", filename, err)
		}
		sha1Sum := sha1.Sum(content)
		if actual := hex.EncodeToString(sha1Sum[:]); actual != item.Shasum {
			failures = append(failures, filename+" shasum mismatch")
		}
		sha512Sum := sha512Integrity(content)
		if sha512Sum != item.Integrity {
			failures = append(failures, filename+" integrity mismatch")
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		return fmt.Errorf("candidate npm artifact bytes do not match metadata: %s", strings.Join(failures, "; "))
	}
	return nil
}

func comparePyPIExisting(candidates pythonPackageSet, registry pypiResponse) error {
	if len(candidates.Packages) == 0 {
		return fmt.Errorf("candidate pypi package set must not be empty")
	}
	expected := map[string]string{}
	for _, item := range candidates.Packages {
		if item.Filename == "" || item.Sha256 == "" {
			return fmt.Errorf("candidate pypi package entries must include filename and sha256")
		}
		if _, exists := expected[item.Filename]; exists {
			return fmt.Errorf("candidate pypi release contains duplicate filename %s", item.Filename)
		}
		expected[item.Filename] = item.Sha256
	}
	actual := map[string]string{}
	for _, item := range registry.URLs {
		if _, exists := actual[item.Filename]; exists {
			return fmt.Errorf("pypi release contains duplicate filename %s", item.Filename)
		}
		actual[item.Filename] = item.Digests.SHA256
	}
	if err := compareStringSet(keys(expected), keys(actual), "pypi release file set"); err != nil {
		return err
	}
	mismatches := []string{}
	for filename, sha256 := range expected {
		if actual[filename] != sha256 {
			mismatches = append(mismatches, filename)
		}
	}
	sort.Strings(mismatches)
	if len(mismatches) > 0 {
		return fmt.Errorf("pypi release sha256 mismatch: %s", strings.Join(mismatches, ", "))
	}
	return nil
}

func comparePyPICandidateArtifacts(candidates pythonPackageSet, directory string) error {
	if len(candidates.Packages) == 0 {
		return fmt.Errorf("candidate pypi package set must not be empty")
	}
	expected := map[string]string{}
	for _, item := range candidates.Packages {
		if item.Filename == "" || item.Sha256 == "" {
			return fmt.Errorf("candidate pypi package entries must include filename and sha256")
		}
		if filepath.Base(item.Filename) != item.Filename {
			return fmt.Errorf("candidate pypi filename must be a basename: %s", item.Filename)
		}
		if _, exists := expected[item.Filename]; exists {
			return fmt.Errorf("candidate pypi release contains duplicate filename %s", item.Filename)
		}
		expected[item.Filename] = item.Sha256
	}
	actualFiles, err := fileBasenames(directory, "*.whl")
	if err != nil {
		return err
	}
	if err := compareStringSet(keys(expected), actualFiles, "candidate pypi artifact file set"); err != nil {
		return err
	}
	mismatches := []string{}
	for filename, expectedSHA := range expected {
		content, err := os.ReadFile(filepath.Join(directory, filename))
		if err != nil {
			return fmt.Errorf("read candidate pypi artifact %s: %w", filename, err)
		}
		sum := sha256.Sum256(content)
		if actual := hex.EncodeToString(sum[:]); actual != expectedSHA {
			mismatches = append(mismatches, filename)
		}
	}
	sort.Strings(mismatches)
	if len(mismatches) > 0 {
		return fmt.Errorf("candidate pypi artifact sha256 mismatch: %s", strings.Join(mismatches, ", "))
	}
	return nil
}

func validateGitHubReleaseMetadata(release githubRelease, expectedTag string, expectedBody string) error {
	failures := []string{}
	if release.TagName != expectedTag {
		failures = append(failures, fmt.Sprintf("tagName %s !== %s", release.TagName, expectedTag))
	}
	if release.Name != expectedTag {
		failures = append(failures, fmt.Sprintf("name %s !== %s", release.Name, expectedTag))
	}
	if release.IsDraft == nil {
		failures = append(failures, "isDraft must be present")
	} else if *release.IsDraft {
		failures = append(failures, "release is draft")
	}
	if release.IsPrerelease == nil {
		failures = append(failures, "isPrerelease must be present")
	} else if *release.IsPrerelease {
		failures = append(failures, "release is prerelease")
	}
	if normalizeNewlines(release.Body) != normalizeNewlines(expectedBody) {
		failures = append(failures, "release notes body mismatch")
	}
	if len(failures) > 0 {
		return fmt.Errorf("github release metadata does not match candidate: %s", strings.Join(failures, "; "))
	}
	return nil
}

func compareGitHubReleaseAssets(expectedNames []string, assets []githubAsset) error {
	actualNames := make([]string, 0, len(assets))
	seen := map[string]struct{}{}
	for _, asset := range assets {
		if asset.Name == "" {
			return fmt.Errorf("github release asset name must be non-empty")
		}
		if _, exists := seen[asset.Name]; exists {
			return fmt.Errorf("github release contains duplicate asset %s", asset.Name)
		}
		seen[asset.Name] = struct{}{}
		actualNames = append(actualNames, asset.Name)
	}
	return compareStringSet(expectedNames, actualNames, "github release asset set")
}

func validateGitHubSignedTag(ref githubTagRef, tag githubTagObject, expectedTag string, expectedCommit string) error {
	failures := []string{}
	expectedRef := "refs/tags/" + expectedTag
	if ref.Ref != expectedRef {
		failures = append(failures, fmt.Sprintf("ref %s !== %s", ref.Ref, expectedRef))
	}
	if ref.Object.Type != "tag" {
		failures = append(failures, "release tag must be an annotated tag object")
	}
	if ref.Object.SHA == "" {
		failures = append(failures, "release tag ref object sha is missing")
	}
	if tag.SHA == "" {
		failures = append(failures, "release tag object sha is missing")
	}
	if tag.SHA != ref.Object.SHA {
		failures = append(failures, fmt.Sprintf("tag object sha %s !== ref object sha %s", tag.SHA, ref.Object.SHA))
	}
	if tag.Tag != expectedTag {
		failures = append(failures, fmt.Sprintf("tag %s !== %s", tag.Tag, expectedTag))
	}
	if tag.Object.Type != "commit" {
		failures = append(failures, "release tag must point at a commit")
	}
	if tag.Object.SHA != expectedCommit {
		failures = append(failures, fmt.Sprintf("tag target commit %s !== %s", tag.Object.SHA, expectedCommit))
	}
	if !tag.Verification.Verified {
		reason := tag.Verification.Reason
		if reason == "" {
			reason = "unknown"
		}
		failures = append(failures, "release tag must be GitHub-verified signed tag: "+reason)
	}
	if len(failures) > 0 {
		return fmt.Errorf("github tag source does not satisfy release policy: %s", strings.Join(failures, "; "))
	}
	return nil
}

func compareStringSet(expected []string, actual []string, label string) error {
	if value, ok := duplicateString(expected); ok {
		return fmt.Errorf("%s expected set contains duplicate value %s", label, value)
	}
	if value, ok := duplicateString(actual); ok {
		return fmt.Errorf("%s actual set contains duplicate value %s", label, value)
	}
	expected = sortedUnique(expected)
	actual = sortedUnique(actual)
	if len(expected) != len(actual) {
		return fmt.Errorf("%s mismatch: actual=%v expected=%v", label, actual, expected)
	}
	for index := range expected {
		if expected[index] != actual[index] {
			return fmt.Errorf("%s mismatch: actual=%v expected=%v", label, actual, expected)
		}
	}
	return nil
}

func duplicateString(values []string) (string, bool) {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			return value, true
		}
		seen[value] = struct{}{}
	}
	return "", false
}

func sortedUnique(values []string) []string {
	values = append([]string{}, values...)
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func keys[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func fileBasenames(directory string, pattern string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(directory, pattern))
	if err != nil {
		return nil, fmt.Errorf("scan %s artifacts: %w", pattern, err)
	}
	result := make([]string, 0, len(matches))
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat candidate artifact %s: %w", path, err)
		}
		if info.IsDir() {
			continue
		}
		result = append(result, filepath.Base(path))
	}
	sort.Strings(result)
	return result, nil
}

func sha512Integrity(content []byte) string {
	hash := sha512Sum(content)
	return "sha512-" + base64.StdEncoding.EncodeToString(hash)
}

func sha512Sum(content []byte) []byte {
	hash := sha512.New()
	_, _ = hash.Write(content)
	return hash.Sum(nil)
}

func normalizeNewlines(value string) string {
	return strings.ReplaceAll(value, "\r\n", "\n")
}

func readLineSet(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	lines := []string{}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return sortedUnique(lines), nil
}

func readJSON(path string, out any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), maxReleaseJSONBytes)
	if err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", path, err)
	}
	if err := json.Unmarshal(normalized, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func parseFlags(args []string, required ...string) (map[string]string, error) {
	admitted := map[string]struct{}{}
	for _, key := range required {
		admitted[key] = struct{}{}
	}
	options := map[string]string{}
	for index := 0; index < len(args); index++ {
		key := strings.TrimPrefix(args[index], "--")
		if key == args[index] || key == "" {
			return nil, fmt.Errorf("expected --flag, got %s", args[index])
		}
		if _, ok := admitted[key]; !ok {
			return nil, fmt.Errorf("unsupported --%s", key)
		}
		if _, exists := options[key]; exists {
			return nil, fmt.Errorf("duplicate --%s", key)
		}
		index++
		if index >= len(args) {
			return nil, fmt.Errorf("missing value for --%s", key)
		}
		options[key] = args[index]
	}
	for _, key := range required {
		if options[key] == "" {
			return nil, fmt.Errorf("missing --%s", key)
		}
	}
	return options, nil
}
