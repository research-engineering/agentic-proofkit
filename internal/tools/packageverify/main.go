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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/jsonreportcliadaptersource"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

const rootPackageName = "@research-engineering/agentic-proofkit"
const rootBinaryName = "agentic-proofkit"
const maxTarEntryBytes = 128 << 20
const maxEmbeddedBinaryBytes = 64 << 20

var (
	packageCoordinatePattern = regexp.MustCompile(`(?:@research-engineering/agentic-proofkit|agentic-proofkit)@v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?`)
	releaseVersionPattern    = regexp.MustCompile(`\bv?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\b`)
	integrityPattern         = regexp.MustCompile(`sha512-[A-Za-z0-9+/=]{32,}`)
	rawReleaseHashPattern    = regexp.MustCompile(`(?i)\b[0-9a-f]{40}\b`)
	sourceRefPattern         = regexp.MustCompile(`(?i)\b(?:commit|source ref|source sha|head sha|headsha|checkout at|tagged commit)\s+[` + "`" + `'\"]?[0-9a-f]{7,40}\b`)
)

var mutableReleaseDocRules = []struct {
	match   func(string) bool
	message string
}{
	{
		match:   packageCoordinatePattern.MatchString,
		message: "shipped markdown must not embed exact package version coordinates",
	},
	{
		match:   releaseVersionPattern.MatchString,
		message: "shipped markdown must not embed exact release version tokens",
	},
	{
		match:   containsGitHubActionsRunURL,
		message: "shipped markdown must not embed provider run URLs",
	},
	{
		match:   containsNPMRegistryTarballURL,
		message: "shipped markdown must not embed registry tarball URLs",
	},
	{
		match:   integrityPattern.MatchString,
		message: "shipped markdown must not embed registry integrity strings",
	},
	{
		match:   rawReleaseHashPattern.MatchString,
		message: "shipped markdown must not embed raw release commit or shasum evidence",
	},
	{
		match:   sourceRefPattern.MatchString,
		message: "shipped markdown must not embed source ref evidence",
	},
}

type tarEntry struct {
	Mode     int64
	Name     string
	Size     int64
	Typeflag byte
}

type rootPackageArtifact struct {
	Content []byte
	Entries []string
	Headers []tarEntry
	Record  packRecord
}

type packRecord struct {
	Filename  string `json:"filename"`
	Integrity string `json:"integrity"`
	Name      string `json:"name"`
	Shasum    string `json:"shasum"`
	Version   string `json:"version"`
}

type requirementBindings struct {
	Requirements []struct {
		SpecPath string `json:"specPath"`
	} `json:"requirements"`
}

type packageManifest struct {
	Bin                  map[string]string `json:"bin"`
	CPU                  []string          `json:"cpu"`
	Description          string            `json:"description"`
	Exports              map[string]string `json:"exports"`
	Files                []string          `json:"files"`
	License              string            `json:"license"`
	Name                 string            `json:"name"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	OS                   []string          `json:"os"`
	PackageManager       string            `json:"packageManager"`
	Private              bool              `json:"private"`
	PublishConfig        publishConfig     `json:"publishConfig"`
	Repository           repository        `json:"repository"`
	Scripts              map[string]string `json:"scripts"`
	SideEffects          bool              `json:"sideEffects"`
	Type                 string            `json:"type"`
	Version              string            `json:"version"`
}

type publishConfig struct {
	Access   string `json:"access"`
	Registry string `json:"registry"`
}

type repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type installedCommandResult struct {
	ExitCode int
	Stderr   []byte
	Stdout   []byte
}

type textPolicySmokeReport struct {
	ReportID   string                 `json:"reportId"`
	ReportKind string                 `json:"reportKind"`
	State      string                 `json:"state"`
	Summary    textPolicySmokeSummary `json:"summary"`
}

type textPolicySmokeSummary struct {
	CheckedTextFileCount int `json:"checkedTextFileCount"`
	FailureCount         int `json:"failureCount"`
	InputFileCount       int `json:"inputFileCount"`
}

type jsonAdapterSourceSmokeReport struct {
	SchemaVersion  int                           `json:"schemaVersion"`
	ArtifactKind   string                        `json:"artifactKind"`
	Format         string                        `json:"format"`
	GeneratorID    string                        `json:"generatorId"`
	Language       string                        `json:"language"`
	Source         string                        `json:"source"`
	SourceFileName string                        `json:"sourceFileName"`
	SourceSha256   string                        `json:"sourceSha256"`
	Summary        jsonAdapterSourceSmokeSummary `json:"summary"`
}

type jsonAdapterSourceSmokeSummary struct {
	ExportedSymbolCount int `json:"exportedSymbolCount"`
	LineCount           int `json:"lineCount"`
}

func main() {
	if err := runVerifier(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func runVerifier() error {
	records, err := readPackRecords(filepath.Join("artifacts", "package", "npm-pack.json"))
	if err != nil {
		return err
	}
	recordByName := map[string]packRecord{}
	for _, record := range records {
		if record.Name == "" || record.Filename == "" || record.Integrity == "" || record.Shasum == "" || record.Version == "" {
			return fmt.Errorf("package record must include name, version, filename, integrity, and shasum")
		}
		if _, exists := recordByName[record.Name]; exists {
			return fmt.Errorf("duplicate package record for %s", record.Name)
		}
		recordByName[record.Name] = record
	}
	rootRecord, ok := recordByName[rootPackageName]
	if !ok {
		return fmt.Errorf("missing root package record %s", rootPackageName)
	}
	rootPackage, err := verifyRootPackage(rootRecord)
	if err != nil {
		return err
	}
	delete(recordByName, rootPackageName)
	if len(recordByName) > 0 {
		extra := make([]string, 0, len(recordByName))
		for name := range recordByName {
			extra = append(extra, name)
		}
		sort.Strings(extra)
		return fmt.Errorf("unexpected package records: %s", strings.Join(extra, ", "))
	}
	if err := verifyRootManifestBoundary(rootPackage); err != nil {
		return err
	}
	if err := verifyNoStalePackageDocs(rootPackage); err != nil {
		return err
	}
	if err := verifySpecReferenceClosure(rootPackage, toSet(rootPackage.Entries)); err != nil {
		return err
	}
	return verifyOutsideConsumer(rootPackage)
}

func verifyRootPackage(record packRecord) (rootPackageArtifact, error) {
	if record.Name != rootPackageName {
		return rootPackageArtifact{}, fmt.Errorf("unexpected root package name: %s", record.Name)
	}
	content, err := os.ReadFile(recordPath(record))
	if err != nil {
		return rootPackageArtifact{}, fmt.Errorf("read package artifact %s: %w", record.Filename, err)
	}
	if err := verifyPackRecordContent(record, content); err != nil {
		return rootPackageArtifact{}, err
	}
	entryHeaders, err := tarEntryHeadersFromBytes(content)
	if err != nil {
		return rootPackageArtifact{}, err
	}
	if err := verifyTarEntryHeaders(entryHeaders); err != nil {
		return rootPackageArtifact{}, err
	}
	entries := tarEntryNames(entryHeaders)
	entrySet := toSet(entries)
	if err := verifyRequiredRootEntries(entrySet); err != nil {
		return rootPackageArtifact{}, err
	}
	for _, entry := range entries {
		if forbiddenRootEntry(entry) {
			return rootPackageArtifact{}, fmt.Errorf("root package contains forbidden entry %s", entry)
		}
		if !allowedRootEntry(entry) {
			return rootPackageArtifact{}, fmt.Errorf("root package contains unexpected entry %s", entry)
		}
	}
	return rootPackageArtifact{Content: content, Entries: entries, Headers: entryHeaders, Record: record}, nil
}

func verifyPackRecordBytes(record packRecord) error {
	content, err := os.ReadFile(recordPath(record))
	if err != nil {
		return fmt.Errorf("read package artifact %s: %w", record.Filename, err)
	}
	return verifyPackRecordContent(record, content)
}

func verifyPackRecordContent(record packRecord, content []byte) error {
	sha1Sum := sha1.Sum(content)
	if actual := hex.EncodeToString(sha1Sum[:]); actual != record.Shasum {
		return fmt.Errorf("package artifact %s shasum mismatch", record.Filename)
	}
	hash := sha512.New()
	_, _ = hash.Write(content)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(hash.Sum(nil))
	if integrity != record.Integrity {
		return fmt.Errorf("package artifact %s integrity mismatch", record.Filename)
	}
	return nil
}

func requiredRootEntries() []string {
	required := []string{
		"package/ADOPTION.md",
		"package/AGENTS.md",
		"package/BACKLOG.md",
		"package/CONTRIBUTING.md",
		"package/LICENSE",
		"package/NON_CLAIMS.md",
		"package/README.md",
		"package/SECURITY.md",
		"package/dist/agentic-proofkit",
		"package/docs/proofkit-contract-map.md",
		"package/docs/release-process.md",
		"package/package.json",
		"package/proofkit/cli-contract.v1.json",
		"package/proofkit/receipt-producer-policy.json",
		"package/proofkit/requirement-bindings.json",
		"package/proofkit/witness-plan.json",
	}
	required = append(required, releaseplatform.PackageTarEntries()...)
	return required
}

func verifyRequiredRootEntries(entrySet map[string]struct{}) error {
	for _, path := range requiredRootEntries() {
		if _, ok := entrySet[path]; !ok {
			return fmt.Errorf("root package missing required entry %s", path)
		}
	}
	return nil
}

func readPackRecords(path string) ([]packRecord, error) {
	records, err := readAdmittedJSON[[]packRecord](path)
	if err != nil {
		return nil, err
	}
	if len(records) != 1 {
		return nil, fmt.Errorf("npm pack must describe exactly the root package, got %d records", len(records))
	}
	return records, nil
}

func recordPath(record packRecord) string {
	return filepath.Join("artifacts", "package", record.Filename)
}

func tarEntryHeadersFromBytes(content []byte) ([]tarEntry, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	return tarEntryHeadersFromGzip(gzipReader)
}

func tarEntryHeadersFromGzip(gzipReader io.Reader) ([]tarEntry, error) {
	tarReader := tar.NewReader(gzipReader)
	entries := []tarEntry{}
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		entries = append(entries, tarEntry{
			Mode:     header.Mode,
			Name:     header.Name,
			Size:     header.Size,
			Typeflag: header.Typeflag,
		})
	}
	return entries, nil
}

func tarEntryNames(entries []tarEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	sort.Strings(names)
	return names
}

func verifyTarEntryHeaders(entries []tarEntry) error {
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if err := verifyTarEntryHeader(entry); err != nil {
			return err
		}
		if _, exists := seen[entry.Name]; exists {
			return fmt.Errorf("root package contains duplicate tar entry %s", entry.Name)
		}
		seen[entry.Name] = struct{}{}
	}
	return nil
}

func verifyTarEntryHeader(entry tarEntry) error {
	if entry.Name == "" || strings.Contains(entry.Name, "\x00") || strings.HasPrefix(entry.Name, "/") || strings.Contains(entry.Name, "\\") {
		return fmt.Errorf("root package contains unsafe tar entry path %q", entry.Name)
	}
	cleaned := filepath.ToSlash(filepath.Clean(entry.Name))
	if cleaned != entry.Name || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return fmt.Errorf("root package contains unsafe tar entry path %q", entry.Name)
	}
	if entry.Typeflag != tar.TypeReg {
		return fmt.Errorf("root package tar entry %s must be a regular file", entry.Name)
	}
	if entry.Size < 0 || entry.Size > maxTarEntryBytes {
		return fmt.Errorf("root package tar entry %s has invalid size %d", entry.Name, entry.Size)
	}
	if rootBinaryEntry(entry.Name) {
		if entry.Size == 0 || entry.Size > maxEmbeddedBinaryBytes {
			return fmt.Errorf("root package binary entry %s has invalid size %d", entry.Name, entry.Size)
		}
		if entry.Mode&0o111 == 0 {
			return fmt.Errorf("root package binary entry %s must be executable", entry.Name)
		}
	}
	return nil
}

func readManifestFromTar(artifact rootPackageArtifact) (packageManifest, error) {
	content, err := readTarFileFromBytes(artifact.Content, "package/package.json")
	if err != nil {
		return packageManifest{}, err
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return packageManifest{}, err
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return packageManifest{}, fmt.Errorf("package manifest must be an object")
	}
	if err := verifyManifestTopLevelKeys(record); err != nil {
		return packageManifest{}, err
	}
	return admission.DecodeTypedJSON[packageManifest](bytes.NewReader(content), int64(len(content)))
}

func verifyManifestTopLevelKeys(record map[string]any) error {
	allowed := map[string]struct{}{
		"bin":            {},
		"cpu":            {},
		"description":    {},
		"exports":        {},
		"files":          {},
		"license":        {},
		"name":           {},
		"os":             {},
		"packageManager": {},
		"private":        {},
		"publishConfig":  {},
		"repository":     {},
		"scripts":        {},
		"sideEffects":    {},
		"type":           {},
		"version":        {},
	}
	unknown := []string{}
	for key := range record {
		if _, ok := allowed[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("package manifest has %d unsupported top-level field(s)", len(unknown))
}

func readTarFileFromBytes(content []byte, target string) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	return readTarFileFromGzip(gzipReader, "package artifact snapshot", target)
}

func readTarFileFromGzip(gzipReader io.Reader, label string, target string) ([]byte, error) {
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if header.Name != target {
			continue
		}
		return io.ReadAll(tarReader)
	}
	return nil, fmt.Errorf("%s missing %s", label, target)
}

func forbiddenRootEntry(path string) bool {
	forbiddenSuffixes := []string{".d.ts", ".ts", ".map"}
	for _, suffix := range forbiddenSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	forbiddenExact := map[string]struct{}{
		"package/bun.lock":                        {},
		"package/dist/cli.js":                     {},
		"package/dist/index.js":                   {},
		"package/proofkit/sdk-cli-parity.v1.json": {},
		"package/tsconfig.json":                   {},
	}
	_, ok := forbiddenExact[path]
	return ok
}

func allowedRootEntry(path string) bool {
	allowedExact := map[string]struct{}{
		"package/ADOPTION.md":                                               {},
		"package/AGENTS.md":                                                 {},
		"package/BACKLOG.md":                                                {},
		"package/CONTRIBUTING.md":                                           {},
		"package/LICENSE":                                                   {},
		"package/NON_CLAIMS.md":                                             {},
		"package/README.md":                                                 {},
		"package/SECURITY.md":                                               {},
		"package/dist/agentic-proofkit":                                     {},
		"package/docs/proofkit-contract-map.md":                             {},
		"package/docs/release-process.md":                                   {},
		"package/package.json":                                              {},
		"package/proofkit/cli-contract.v1.json":                             {},
		"package/proofkit/receipt-producer-policy.json":                     {},
		"package/proofkit/requirement-bindings.json":                        {},
		"package/proofkit/witness-plan.json":                                {},
		"package/docs/specs/proofkit-consumer-infra-retirement/overview.md": {},
		"package/docs/specs/proofkit-consumer-infra-retirement/requirements.v1.json": {},
		"package/docs/specs/proofkit-package-boundary/overview.md":                   {},
		"package/docs/specs/proofkit-package-boundary/requirements.v1.json":          {},
		"package/docs/specs/proofkit-receipt-authority/overview.md":                  {},
		"package/docs/specs/proofkit-receipt-authority/requirements.v1.json":         {},
		"package/docs/specs/proofkit-spec-proof-core/overview.md":                    {},
		"package/docs/specs/proofkit-spec-proof-core/requirements.v1.json":           {},
		"package/docs/specs/proofkit-supply-chain-quality/overview.md":               {},
		"package/docs/specs/proofkit-supply-chain-quality/requirements.v1.json":      {},
	}
	if _, ok := allowedExact[path]; ok {
		return true
	}
	if embeddedPlatformBinaryEntry(path) {
		return true
	}
	return false
}

func embeddedPlatformBinaryEntry(path string) bool {
	for _, entry := range releaseplatform.PackageTarEntries() {
		if path == entry {
			return true
		}
	}
	return false
}

func rootBinaryEntry(path string) bool {
	return path == "package/dist/agentic-proofkit" || embeddedPlatformBinaryEntry(path)
}

func verifyRootManifestBoundary(artifact rootPackageArtifact) error {
	manifest, err := readManifestFromTar(artifact)
	if err != nil {
		return err
	}
	if manifest.Name != rootPackageName {
		return fmt.Errorf("root package name mismatch: %s", manifest.Name)
	}
	if manifest.Private {
		return fmt.Errorf("root package must not be private")
	}
	if manifest.Version != artifact.Record.Version {
		return fmt.Errorf("root package version mismatch: manifest=%s pack=%s", manifest.Version, artifact.Record.Version)
	}
	if manifest.License != "MIT" {
		return fmt.Errorf("root package license must be MIT, got %s", manifest.License)
	}
	if manifest.PackageManager != "npm@11.18.0" {
		return fmt.Errorf("root package packageManager must be npm@11.18.0, got %s", manifest.PackageManager)
	}
	if manifest.Type != "module" {
		return fmt.Errorf("root package type must be module, got %s", manifest.Type)
	}
	if manifest.SideEffects {
		return fmt.Errorf("root package sideEffects must be false")
	}
	if manifest.Repository.Type != "git" || manifest.Repository.URL != "git+https://github.com/research-engineering/agentic-proofkit.git" {
		return fmt.Errorf("root package repository must be git+https://github.com/research-engineering/agentic-proofkit.git")
	}
	if manifest.PublishConfig.Access != "public" || manifest.PublishConfig.Registry != "https://registry.npmjs.org" {
		return fmt.Errorf("root package publishConfig must target public npm registry")
	}
	if err := verifyNoLifecycleScripts(manifest.Scripts); err != nil {
		return err
	}
	if len(manifest.Bin) != 1 || manifest.Bin[rootBinaryName] != "dist/agentic-proofkit" {
		return fmt.Errorf("root package bin must expose dist/agentic-proofkit only")
	}
	if len(manifest.Exports) != 1 || manifest.Exports["./package.json"] != "./package.json" {
		return fmt.Errorf("package exports must deny root and deep imports while allowing ./package.json")
	}
	if !sameStrings(manifest.OS, releaseplatform.NPMOSValues()) {
		return fmt.Errorf("root package os must be %v, got %v", releaseplatform.NPMOSValues(), manifest.OS)
	}
	if !sameStrings(manifest.CPU, releaseplatform.NPMCPUValues()) {
		return fmt.Errorf("root package cpu must be %v, got %v", releaseplatform.NPMCPUValues(), manifest.CPU)
	}
	expectedFiles := []string{
		"ADOPTION.md",
		"AGENTS.md",
		"BACKLOG.md",
		"CONTRIBUTING.md",
		"LICENSE",
		"NON_CLAIMS.md",
		"README.md",
		"SECURITY.md",
		"dist/**",
		"docs/proofkit-contract-map.md",
		"docs/release-process.md",
		"docs/specs/**/*",
		"proofkit/*.json",
	}
	if !sameStrings(manifest.Files, expectedFiles) {
		return fmt.Errorf("root package files allowlist mismatch: %v", manifest.Files)
	}
	if len(manifest.OptionalDependencies) != 0 {
		return fmt.Errorf("root package must not declare optional platform dependencies")
	}
	return nil
}

func verifyNoLifecycleScripts(scripts map[string]string) error {
	lifecycleScripts := map[string]struct{}{
		"preinstall":     {},
		"install":        {},
		"postinstall":    {},
		"prepack":        {},
		"postpack":       {},
		"prepare":        {},
		"prepublish":     {},
		"prepublishOnly": {},
	}
	for name := range scripts {
		if _, ok := lifecycleScripts[name]; ok {
			return fmt.Errorf("root package must not declare lifecycle script %s", name)
		}
	}
	return nil
}

func sameStrings(actual []string, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func verifyNoStalePackageDocs(artifact rootPackageArtifact) error {
	previousPrivateNamespace := "W25" + "X80"
	previousPersonalNamespace := "ipe" + "rev"
	previousPersonalNamespaceLong := "ipe" + "reverziev"
	legacyConsumerPackageScope := "@" + "a" + "fc"
	staleTerms := map[string]string{
		"runtime JavaScript":          "package docs must describe Go binaries, not runtime JavaScript",
		"declaration files":           "package docs must not claim declaration files",
		"exported APIs":               "package docs must not route consumers to a package-root SDK",
		"supported root API":          "package docs must not claim a supported root API",
		"public/root API":             "package docs must not claim a public root API",
		"optional package":            "package docs must describe embedded platform binaries, not optional platform packages",
		"optional packages":           "package docs must describe embedded platform binaries, not optional platform packages",
		"platform optional":           "package docs must describe embedded platform binaries, not optional platform packages",
		"platform package":            "package docs must describe embedded platform binaries, not optional platform packages",
		"platform packages":           "package docs must describe embedded platform binaries, not optional platform packages",
		previousPrivateNamespace:      "package docs must not route public consumers to a previous private namespace",
		previousPersonalNamespace:     "package docs must not route public consumers to a personal account namespace",
		previousPersonalNamespaceLong: "package docs must not route public consumers to a personal account namespace",
		legacyConsumerPackageScope:    "package docs must not retain consumer-specific package names",
	}
	textEntries, err := readTarTextEntriesFromBytes(artifact.Content)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(textEntries))
	for path := range textEntries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		text := textEntries[path]
		for term, message := range staleTerms {
			if containsStaleTerm(text, term) {
				return fmt.Errorf("%s contains stale package-boundary term %q: %s", path, term, message)
			}
		}
		if strings.HasSuffix(path, ".md") {
			for _, rule := range mutableReleaseDocRules {
				if rule.match(text) {
					return fmt.Errorf("%s contains mutable package-public release fact: %s", path, rule.message)
				}
			}
		}
	}
	return nil
}

func containsStaleTerm(text string, term string) bool {
	offset := 0
	for {
		index := strings.Index(text[offset:], term)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(term)
		if staleTermBoundary(text, start-1) && staleTermBoundary(text, end) {
			return true
		}
		offset = start + len(term)
		if offset >= len(text) {
			return false
		}
	}
}

func containsGitHubActionsRunURL(text string) bool {
	return strings.Contains(text, "https://github.com/research-engineering/agentic-proofkit/actions/runs/")
}

func containsNPMRegistryTarballURL(text string) bool {
	return strings.Contains(text, "https://registry.npmjs.org/@research-engineering/agentic-proofkit/-/") ||
		strings.Contains(text, "https://registry.npmjs.org/agentic-proofkit/-/")
}

func staleTermBoundary(text string, index int) bool {
	if index < 0 || index >= len(text) {
		return true
	}
	character := text[index]
	return !((character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		character == '-')
}

func readTarTextEntriesFromBytes(content []byte) (map[string]string, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	return readTarTextEntriesFromGzip(gzipReader)
}

func readTarTextEntriesFromGzip(gzipReader io.Reader) (map[string]string, error) {
	tarReader := tar.NewReader(gzipReader)
	entries := map[string]string{}
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if !packageTextEntry(header.Name) {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("package text entry %s must be a regular file", header.Name)
		}
		if header.Size < 0 || header.Size > maxTarEntryBytes {
			return nil, fmt.Errorf("package text entry %s has invalid size %d", header.Name, header.Size)
		}
		content, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, err
		}
		entries[header.Name] = string(content)
	}
	return entries, nil
}

func packageTextEntry(path string) bool {
	switch path {
	case "package/ADOPTION.md",
		"package/AGENTS.md",
		"package/BACKLOG.md",
		"package/CONTRIBUTING.md",
		"package/NON_CLAIMS.md",
		"package/README.md",
		"package/SECURITY.md":
		return true
	}
	if strings.HasPrefix(path, "package/docs/") {
		return strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".json")
	}
	if strings.HasPrefix(path, "package/proofkit/") {
		return strings.HasSuffix(path, ".json")
	}
	return false
}

func verifySpecReferenceClosure(artifact rootPackageArtifact, entries map[string]struct{}) error {
	content, err := readTarFileFromBytes(artifact.Content, "package/proofkit/requirement-bindings.json")
	if err != nil {
		return err
	}
	bindings, err := decodeRequirementBindings(content)
	if err != nil {
		return err
	}
	for _, requirement := range bindings.Requirements {
		if requirement.SpecPath == "" {
			return fmt.Errorf("requirement binding has empty specPath")
		}
		packagePath := "package/" + filepath.ToSlash(requirement.SpecPath)
		if _, ok := entries[packagePath]; !ok {
			return fmt.Errorf("root package missing specPath reference %s", requirement.SpecPath)
		}
	}
	return nil
}

func decodeRequirementBindings(content []byte) (requirementBindings, error) {
	return admission.DecodeTypedJSON[requirementBindings](bytes.NewReader(content), int64(len(content)))
}

func readAdmittedJSON[T any](path string) (T, error) {
	var out T
	file, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer file.Close()
	value, err := admission.DecodeTypedJSON[T](file, 16<<20)
	if err != nil {
		return out, fmt.Errorf("decode %s: %w", path, err)
	}
	return value, nil
}

func verifyOutsideConsumer(artifact rootPackageArtifact) error {
	return verifyExactTarballConsumer(artifact)
}

func verifyExactTarballConsumer(artifact rootPackageArtifact) error {
	consumer, err := os.MkdirTemp("", "proofkit-consumer-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(consumer)
	tarballPath := filepath.Join(consumer, artifact.Record.Filename)
	if err := os.WriteFile(tarballPath, artifact.Content, 0o644); err != nil {
		return fmt.Errorf("write snapshot package tarball: %w", err)
	}
	packageJSON := fmt.Sprintf(
		`{"private":true,"type":"module","dependencies":{"%s":"file:%s"}}`+"\n",
		rootPackageName,
		tarballPath,
	)
	if err := os.WriteFile(filepath.Join(consumer, "package.json"), []byte(packageJSON), 0o644); err != nil {
		return err
	}
	if output, err := run(consumer, "npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"); err != nil {
		return fmt.Errorf("outside consumer install failed: %w\n%s", err, output)
	}
	binPath := filepath.Join(consumer, "node_modules", ".bin", "agentic-proofkit")
	if runtime.GOOS == "windows" {
		binPath += ".cmd"
	}
	output, err := run(consumer, binPath, "--help")
	if err != nil {
		return fmt.Errorf("outside consumer binary smoke failed: %w\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("CLI/JSON is the public cross-language contract")) {
		return fmt.Errorf("outside consumer binary smoke did not expose CLI contract")
	}
	if err := verifyInstalledJSONABI(consumer, binPath); err != nil {
		return err
	}
	if err := verifyOutsideConsumerImports(consumer); err != nil {
		return err
	}
	return nil
}

func run(dir string, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Dir = dir
	return command.CombinedOutput()
}

func verifyInstalledJSONABI(consumer string, binPath string) error {
	if err := os.WriteFile(filepath.Join(consumer, "unlisted-poison.md"), []byte("bad trailing \n"), 0o644); err != nil {
		return fmt.Errorf("write unlisted poison file: %w", err)
	}
	success, err := runWithInput(consumer, binPath, packageSmokeSuccessInput(), "text-policy", "--input", "-")
	if err != nil {
		return fmt.Errorf("outside consumer JSON success smoke failed to run: %w", err)
	}
	if err := verifyTextPolicySmokeReport(success, "proofkit.package-smoke.success", "passed", 0, textPolicySmokeSummary{
		CheckedTextFileCount: 1,
		FailureCount:         0,
		InputFileCount:       1,
	}); err != nil {
		return fmt.Errorf("outside consumer JSON success smoke failed: %w", err)
	}
	failed, err := runWithInput(consumer, binPath, packageSmokeFailureInput(), "text-policy", "--input", "-")
	if err != nil {
		return fmt.Errorf("outside consumer JSON failure smoke failed to run: %w", err)
	}
	if err := verifyTextPolicySmokeReport(failed, "proofkit.package-smoke.failure", "failed", 1, textPolicySmokeSummary{
		CheckedTextFileCount: 1,
		FailureCount:         1,
		InputFileCount:       1,
	}); err != nil {
		return fmt.Errorf("outside consumer JSON failure smoke failed: %w", err)
	}
	if err := verifyJSONAdapterSourceSmoke(consumer, binPath); err != nil {
		return err
	}
	return nil
}

func verifyJSONAdapterSourceSmoke(consumer string, binPath string) error {
	command := exec.Command(binPath, "json-report-cli-adapter-source", "--language", "typescript")
	command.Dir = consumer
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("outside consumer JSON adapter source smoke failed to run: %w; stderr=%s", err, stderr.String())
	}
	return verifyJSONAdapterSourceSmokeReport(installedCommandResult{
		ExitCode: 0,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
	}, jsonreportcliadaptersource.TypeScriptSource())
}

func verifyJSONAdapterSourceSmokeReport(result installedCommandResult, expectedSource string) error {
	if result.ExitCode != 0 {
		return fmt.Errorf("exit code %d, want 0; stdout=%s stderr=%s", result.ExitCode, result.Stdout, result.Stderr)
	}
	if len(result.Stderr) != 0 {
		return fmt.Errorf("stderr must be empty for json adapter source smoke, got %q", string(result.Stderr))
	}
	report, err := admission.DecodeTypedJSON[jsonAdapterSourceSmokeReport](bytes.NewReader(result.Stdout), 8<<20)
	if err != nil {
		return fmt.Errorf("json adapter source smoke stdout must be one JSON report: %w; stdout=%s", err, result.Stdout)
	}
	if report.SchemaVersion != 1 {
		return fmt.Errorf("schemaVersion=%d, want 1", report.SchemaVersion)
	}
	if report.ArtifactKind != "proofkit.json-report-cli-adapter-source" {
		return fmt.Errorf("artifactKind=%s, want proofkit.json-report-cli-adapter-source", report.ArtifactKind)
	}
	if report.Language != "typescript" {
		return fmt.Errorf("language=%s, want typescript", report.Language)
	}
	if report.Format != "json" {
		return fmt.Errorf("format=%s, want json", report.Format)
	}
	if report.SourceFileName != "proofkit-json-report-cli-adapter.ts" {
		return fmt.Errorf("sourceFileName=%s, want proofkit-json-report-cli-adapter.ts", report.SourceFileName)
	}
	if report.GeneratorID != "proofkit.json-report-cli-adapter-source.typescript.v1" {
		return fmt.Errorf("generatorId=%s, want proofkit.json-report-cli-adapter-source.typescript.v1", report.GeneratorID)
	}
	if report.Source != expectedSource {
		return fmt.Errorf("json adapter source does not match current owner source")
	}
	if report.SourceSha256 != digest.SHA256TextRef(report.Source) {
		return fmt.Errorf("json adapter source hash mismatch")
	}
	if report.Summary.ExportedSymbolCount < 20 {
		return fmt.Errorf("summary.exportedSymbolCount=%d, want at least 20", report.Summary.ExportedSymbolCount)
	}
	if report.Summary.LineCount < 500 {
		return fmt.Errorf("summary.lineCount=%d, want at least 500", report.Summary.LineCount)
	}
	for _, token := range []string{
		"function readProofkitBoundedTextFile",
		"export function runProofkitNoInputJsonCommand",
		"options.inputMode === \"none\"",
		"stable JSON value must not contain unsafe integer numbers",
		"openSync(filePath, \"r\")",
	} {
		if !strings.Contains(report.Source, token) {
			return fmt.Errorf("json adapter source missing required token %q", token)
		}
	}
	for _, token := range []string{
		"readFileSync(filePath, \"utf8\")",
		"JSON.parse(text)",
	} {
		if strings.Contains(report.Source, token) {
			return fmt.Errorf("json adapter source contains forbidden stale token %q", token)
		}
	}
	return nil
}

func runWithInput(dir string, name string, input []byte, args ...string) (installedCommandResult, error) {
	command := exec.Command(name, args...)
	command.Dir = dir
	command.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return installedCommandResult{}, err
		}
		exitCode = exitErr.ExitCode()
	}
	return installedCommandResult{ExitCode: exitCode, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

func verifyTextPolicySmokeReport(result installedCommandResult, reportID string, state string, exitCode int, summary textPolicySmokeSummary) error {
	if result.ExitCode != exitCode {
		return fmt.Errorf("exit code %d, want %d; stdout=%s stderr=%s", result.ExitCode, exitCode, result.Stdout, result.Stderr)
	}
	if len(result.Stderr) != 0 {
		return fmt.Errorf("stderr must be empty for report-producing text-policy smoke, got %q", string(result.Stderr))
	}
	report, err := admission.DecodeTypedJSON[textPolicySmokeReport](bytes.NewReader(result.Stdout), 1<<20)
	if err != nil {
		return fmt.Errorf("stdout must be one JSON report: %w; stdout=%s", err, result.Stdout)
	}
	if report.ReportKind != "proofkit.text-policy" {
		return fmt.Errorf("reportKind=%s, want proofkit.text-policy", report.ReportKind)
	}
	if report.ReportID != reportID {
		return fmt.Errorf("reportId=%s, want %s", report.ReportID, reportID)
	}
	if report.State != state {
		return fmt.Errorf("state=%s, want %s", report.State, state)
	}
	if report.Summary.InputFileCount != summary.InputFileCount {
		return fmt.Errorf("summary.inputFileCount=%d, want %d", report.Summary.InputFileCount, summary.InputFileCount)
	}
	if report.Summary.CheckedTextFileCount != summary.CheckedTextFileCount {
		return fmt.Errorf("summary.checkedTextFileCount=%d, want %d", report.Summary.CheckedTextFileCount, summary.CheckedTextFileCount)
	}
	if report.Summary.FailureCount != summary.FailureCount {
		return fmt.Errorf("summary.failureCount=%d, want %d", report.Summary.FailureCount, summary.FailureCount)
	}
	return nil
}

func packageSmokeSuccessInput() []byte {
	return []byte(`{"schemaVersion":1,"reportId":"proofkit.package-smoke.success","nonClaims":["Package smoke input does not claim repository discovery."],"policy":{"allowTab":true,"asciiOnly":true,"binarySuffixes":[".png"],"rejectTrailingWhitespace":true,"requireFinalNewline":true},"files":[{"contentBase64":"b2sK","path":"docs/ok.md","state":"present"}]}` + "\n")
}

func packageSmokeFailureInput() []byte {
	return []byte(`{"schemaVersion":1,"reportId":"proofkit.package-smoke.failure","nonClaims":["Package smoke input does not claim repository discovery."],"policy":{"allowTab":true,"asciiOnly":true,"binarySuffixes":[".png"],"rejectTrailingWhitespace":true,"requireFinalNewline":true},"files":[{"contentBase64":"bm8tbmV3bGluZQ==","path":"docs/bad.md","state":"present"}]}` + "\n")
}

func verifyOutsideConsumerImports(consumer string) error {
	payload, err := json.Marshal(struct {
		DeniedSpecifiers     []string `json:"deniedSpecifiers"`
		ExpectedManifestName string   `json:"expectedManifestName"`
		ManifestSpecifier    string   `json:"manifestSpecifier"`
	}{
		DeniedSpecifiers: []string{
			rootPackageName,
			rootPackageName + "/dist/agentic-proofkit",
			rootPackageName + "/dist/command-descriptors.json",
			rootPackageName + "/internal/app/command_descriptors",
			rootPackageName + "/proofkit/cli-contract.v1.json",
			rootPackageName + "/proofkit/command-descriptors.v1.json",
			rootPackageName + "/internal/tools/packageverify",
		},
		ExpectedManifestName: rootPackageName,
		ManifestSpecifier:    rootPackageName + "/package.json",
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(consumer, "proofkit-import-boundary.json"), payload, 0o600); err != nil {
		return fmt.Errorf("write outside consumer import boundary payload: %w", err)
	}
	script := `
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const require = createRequire(import.meta.url);
const payload = JSON.parse(readFileSync("proofkit-import-boundary.json", "utf8"));
const manifest = require(payload.manifestSpecifier);
if (manifest.name !== payload.expectedManifestName) {
  throw new Error("package.json export did not resolve package manifest");
}
for (const specifier of payload.deniedSpecifiers) {
  let failed = false;
  try {
    await import(specifier);
  } catch {
    failed = true;
  }
  if (!failed) {
    throw new Error("module import unexpectedly succeeded: " + specifier);
  }
}
console.log("module import boundary ok");
`
	output, err := run(consumer, "node", "--input-type=module", "--eval", script)
	if err != nil {
		return fmt.Errorf("outside consumer module boundary proof failed: %w\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("module import boundary ok")) {
		return fmt.Errorf("outside consumer module boundary proof did not confirm denial")
	}
	return nil
}

func toSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
