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
	"maps"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/jsonreportcliadaptersource"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

const rootPackageName = "@research-engineering/agentic-proofkit"
const rootBinaryName = "agentic-proofkit"
const installedNPMExecCommandPrefix = "npm exec --offline -- agentic-proofkit "
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
	DevDependencies      map[string]string `json:"devDependencies"`
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
		writeVerificationFailure(os.Stderr, err)
		os.Exit(1)
	}
}

func writeVerificationFailure(writer io.Writer, err error) {
	_, _ = fmt.Fprintln(writer, admit.RedactStructuralText(err.Error()))
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
	if err := verifyPackedOwnerRecordsMatchSource(rootPackage); err != nil {
		return err
	}
	if err := verifyNoStalePackageDocs(rootPackage); err != nil {
		return err
	}
	if err := verifySpecReferenceClosure(rootPackage, toSet(rootPackage.Entries)); err != nil {
		return err
	}
	if err := verifyPackagePublicReferenceClosure(rootPackage, toSet(rootPackage.Entries)); err != nil {
		return err
	}
	return verifyOutsideConsumer(rootPackage)
}

func verifyPackedOwnerRecordsMatchSource(artifact rootPackageArtifact) error {
	for _, entry := range artifact.Entries {
		if !sourceOwnedPackageEntry(entry) {
			continue
		}
		packed, err := readTarFileFromBytes(artifact.Content, entry)
		if err != nil {
			return err
		}
		sourcePath := strings.TrimPrefix(entry, "package/")
		source, err := os.ReadFile(filepath.FromSlash(sourcePath))
		if err != nil {
			return fmt.Errorf("read source owner for packed entry %s: %w", entry, err)
		}
		if !bytes.Equal(packed, source) {
			return fmt.Errorf("packed owner record %s does not match source owner %s", entry, sourcePath)
		}
	}
	return nil
}

func sourceOwnedPackageEntry(entry string) bool {
	switch entry {
	case "package/LICENSE", "package/package.json":
		return true
	default:
		return packageTextEntry(entry)
	}
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
		"package/LICENSE",
		"package/NON_CLAIMS.md",
		"package/README.md",
		"package/SECURITY.md",
		"package/dist/agentic-proofkit",
		"package/docs/proofkit-contract-map.md",
		"package/docs/release-process.md",
		"package/package.json",
		"package/proofkit/cli-contract.v2.json",
		"package/proofkit/command-families.v1.json",
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
		"bin":             {},
		"cpu":             {},
		"description":     {},
		"devDependencies": {},
		"exports":         {},
		"files":           {},
		"license":         {},
		"name":            {},
		"os":              {},
		"packageManager":  {},
		"private":         {},
		"publishConfig":   {},
		"repository":      {},
		"scripts":         {},
		"sideEffects":     {},
		"type":            {},
		"version":         {},
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
		"package/ADOPTION.md":                                                        {},
		"package/LICENSE":                                                            {},
		"package/NON_CLAIMS.md":                                                      {},
		"package/README.md":                                                          {},
		"package/SECURITY.md":                                                        {},
		"package/dist/agentic-proofkit":                                              {},
		"package/docs/proofkit-contract-map.md":                                      {},
		"package/docs/release-process.md":                                            {},
		"package/package.json":                                                       {},
		"package/proofkit/cli-contract.v2.json":                                      {},
		"package/proofkit/command-families.v1.json":                                  {},
		"package/proofkit/receipt-producer-policy.json":                              {},
		"package/proofkit/requirement-bindings.json":                                 {},
		"package/proofkit/witness-plan.json":                                         {},
		"package/docs/specs/proofkit-agent-workflow/overview.md":                     {},
		"package/docs/specs/proofkit-agent-workflow/requirements.v1.json":            {},
		"package/docs/specs/proofkit-consumer-infra-retirement/overview.md":          {},
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
	expectedDevDependencies := map[string]string{"@playwright/test": "1.62.0", "axe-core": "4.12.1", "typescript": "7.0.2"}
	if !maps.Equal(manifest.DevDependencies, expectedDevDependencies) {
		return fmt.Errorf("root package devDependencies must equal the source-only browser proof toolchain")
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
		decoded, err := unicodepolicy.DecodeUTF8(content)
		if err != nil {
			return nil, fmt.Errorf("package text entry is not valid UTF-8")
		}
		entries[header.Name] = decoded
	}
	return entries, nil
}

func packageTextEntry(path string) bool {
	switch path {
	case "package/ADOPTION.md",
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

var markdownInlineDestinationPattern = regexp.MustCompile(`\[[^\]\r\n]*\]\(\s*(?:<([^>\r\n]+)>|([^)\s\r\n]+))(?:\s+(?:"[^"\r\n]*"|'[^'\r\n]*'|\([^)\r\n]*\)))?\s*\)`)
var markdownReferenceDestinationPattern = regexp.MustCompile(`(?m)^[ \t]{0,3}\[[^\]\r\n]+\]:[ \t]*(?:<([^>\r\n]+)>|([^ \t\r\n]+))`)
var markdownCodeSpanPattern = regexp.MustCompile("`([^`]+)`")
var readmePublicNavigationPattern = regexp.MustCompile(
	`(?s)The full machine-readable command inventory remains\s+` +
		"`([^`\r\n]+)`" +
		`; the human route map is\s+` +
		"`([^`\r\n]+)`" +
		`\.`,
)

func verifyPackagePublicReferenceClosure(artifact rootPackageArtifact, entries map[string]struct{}) error {
	textEntries, err := readTarTextEntriesFromBytes(artifact.Content)
	if err != nil {
		return err
	}
	for entry, content := range textEntries {
		if strings.HasSuffix(entry, ".md") {
			if err := verifyMarkdownDestinations(entry, content, entries); err != nil {
				return err
			}
		}
	}
	knownMachineEntries := map[string]struct{}{
		"package/proofkit/cli-contract.v2.json":         {},
		"package/proofkit/command-families.v1.json":     {},
		"package/proofkit/receipt-producer-policy.json": {},
		"package/proofkit/requirement-bindings.json":    {},
		"package/proofkit/witness-plan.json":            {},
	}
	for entry, content := range textEntries {
		if !strings.HasSuffix(entry, ".json") {
			continue
		}
		if strings.HasPrefix(entry, "package/docs/specs/") && strings.HasSuffix(entry, "/requirements.v1.json") {
			if err := verifyRequirementSourceReferences(entry, content, entries); err != nil {
				return err
			}
			continue
		}
		if _, known := knownMachineEntries[entry]; !known {
			return fmt.Errorf("package contains unclassified machine projection %s", entry)
		}
	}
	if readme, ok := textEntries["package/README.md"]; ok {
		if err := verifyREADMEInstallPolicy(readme); err != nil {
			return err
		}
		if err := verifyREADMEPublicNavigation(readme, entries); err != nil {
			return err
		}
		if err := verifyREADMEOwnerTable(readme, entries); err != nil {
			return err
		}
	}
	if err := verifyRequirementBindingReferences(textEntries["package/proofkit/requirement-bindings.json"], entries); err != nil {
		return err
	}
	if err := verifyWitnessPlanReferences(textEntries["package/proofkit/witness-plan.json"]); err != nil {
		return err
	}
	if err := verifyCommandFamilyReferenceInventory(textEntries["package/proofkit/command-families.v1.json"]); err != nil {
		return err
	}
	if err := verifyReceiptPolicyReferences(textEntries["package/proofkit/receipt-producer-policy.json"], entries); err != nil {
		return err
	}
	return verifyCLIContractSourceClassifications(textEntries["package/proofkit/cli-contract.v2.json"], entries)
}

const readmePreOneExactPinPolicy = "Pre-1.0 releases may contain owner-declared breaking changes, so npm consumers\nmust retain the exact saved version instead of replacing it with a version\nrange."

func verifyREADMEInstallPolicy(content string) error {
	if strings.Count(content, readmePreOneExactPinPolicy) != 1 {
		return fmt.Errorf("package README must state the exact pre-1.0 npm pin policy once")
	}
	return nil
}

func verifyMarkdownDestinations(entry, content string, entries map[string]struct{}) error {
	matches := append(
		markdownInlineDestinationPattern.FindAllStringSubmatch(content, -1),
		markdownReferenceDestinationPattern.FindAllStringSubmatch(content, -1)...,
	)
	for _, match := range matches {
		destination := firstNonEmptyCapture(match[1:])
		if destination == "" || strings.HasPrefix(destination, "#") || strings.Contains(destination, "://") || strings.HasPrefix(destination, "mailto:") {
			continue
		}
		destination = strings.SplitN(destination, "#", 2)[0]
		destination = strings.SplitN(destination, "?", 2)[0]
		resolved := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(entry), destination))
		if !safePackageEntryReference(resolved) {
			return fmt.Errorf("%s contains unsafe Markdown destination %s", entry, destination)
		}
		if _, ok := entries[resolved]; !ok {
			return fmt.Errorf("%s contains dangling package-public Markdown destination %s", entry, destination)
		}
	}
	return nil
}

func verifyRequirementSourceReferences(entry, content string, entries map[string]struct{}) error {
	value, err := decodePackageJSONObject(content, entry)
	if err != nil {
		return err
	}
	if err := verifyClosedReferenceInventory(entry, value, map[string]string{
		"/specPackagePath":                       "package_public_directory",
		"/overviewPath":                          "package_public",
		"/requirementsPath":                      "package_public",
		"/requirements/*/proofBindingRefs":       "package_public",
		"/requirements/*/nonClaimRefs":           "non_claim_identifier",
		"/requirements/*/lifecycle/evidenceRefs": "package_public_or_evidence_identifier",
	}); err != nil {
		return err
	}
	specPackagePath := stringField(value, "specPackagePath")
	if err := requireShippedRootPrefix(entry+" specPackagePath", specPackagePath, entries); err != nil {
		return err
	}
	for _, field := range []string{"overviewPath", "requirementsPath"} {
		if err := requireShippedRootReference(entry+" "+field, stringField(value, field), entries); err != nil {
			return err
		}
	}
	requirements, ok := value["requirements"].([]any)
	if !ok {
		return fmt.Errorf("package %s requirements must be an array", entry)
	}
	for _, raw := range requirements {
		requirement, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("package %s requirement must be an object", entry)
		}
		for _, reference := range stringArrayField(requirement, "proofBindingRefs") {
			if err := requireShippedRootReference(entry+" proofBindingRef", reference, entries); err != nil {
				return err
			}
		}
		for _, reference := range stringArrayField(requirement, "nonClaimRefs") {
			if !strings.HasPrefix(reference, "NC-") {
				return fmt.Errorf("package %s nonClaimRef must be an NC-* identifier", entry)
			}
		}
		lifecycle, _ := requirement["lifecycle"].(map[string]any)
		for _, reference := range stringArrayField(lifecycle, "evidenceRefs") {
			if looksLikeRepositoryPath(reference) {
				if err := requireShippedRootReference(entry+" lifecycle evidenceRef", reference, entries); err != nil {
					return err
				}
			} else if reference == "" {
				return fmt.Errorf("package %s lifecycle evidenceRef must be non-empty", entry)
			}
		}
	}
	return nil
}

func firstNonEmptyCapture(captures []string) string {
	for _, capture := range captures {
		if capture != "" {
			return strings.TrimSpace(capture)
		}
	}
	return ""
}

func verifyREADMEPublicNavigation(content string, entries map[string]struct{}) error {
	match := readmePublicNavigationPattern.FindStringSubmatch(content)
	if len(match) != 3 {
		return fmt.Errorf("package README public command navigation is missing")
	}
	for _, reference := range match[1:] {
		if err := requireShippedRootReference("package README public command navigation", reference, entries); err != nil {
			return err
		}
	}
	return nil
}

func verifyREADMEOwnerTable(content string, entries map[string]struct{}) error {
	inTable := false
	for _, line := range strings.Split(content, "\n") {
		if line == "| Need | Owner |" {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "|---") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 4 {
			return fmt.Errorf("package README owner table must contain exactly two cells")
		}
		for _, match := range markdownCodeSpanPattern.FindAllStringSubmatch(cells[2], -1) {
			reference := strings.TrimSpace(match[1])
			if !looksLikeRepositoryPath(reference) {
				continue
			}
			if err := requireShippedRootReference("package README owner table", reference, entries); err != nil {
				return err
			}
		}
	}
	if !inTable {
		return fmt.Errorf("package README owner table is missing")
	}
	return nil
}

func verifyRequirementBindingReferences(content string, entries map[string]struct{}) error {
	value, err := decodePackageJSONObject(content, "requirement bindings")
	if err != nil {
		return err
	}
	if err := verifyClosedReferenceInventory("requirement bindings", value, map[string]string{
		"/requirements/*/specPath":                "package_public",
		"/bindings/*/witnessPath":                 "source_checkout",
		"/bindings/*/witnessSelectors":            "source_checkout_selector_set",
		"/bindings/*/witnessSelectors/*/selector": "source_checkout_test_selector",
	}); err != nil {
		return err
	}
	requirements, ok := value["requirements"].([]any)
	if !ok {
		return fmt.Errorf("package requirement bindings requirements must be an array")
	}
	for _, raw := range requirements {
		record, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("package requirement binding requirement must be an object")
		}
		specPath, ok := record["specPath"].(string)
		if !ok || specPath == "" {
			return fmt.Errorf("package requirement binding specPath must be a string")
		}
		if err := requireShippedRootReference("package requirement binding specPath", specPath, entries); err != nil {
			return err
		}
	}
	bindings, _ := value["bindings"].([]any)
	for _, raw := range bindings {
		record, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("package requirement binding witness must be an object")
		}
		witnessPath, ok := record["witnessPath"].(string)
		if !ok || witnessPath == "" {
			return fmt.Errorf("package requirement binding witnessPath must be a string")
		}
		if err := requireSourceCheckoutReference("package requirement binding witnessPath", witnessPath); err != nil {
			return err
		}
		selectors, _ := record["witnessSelectors"].([]any)
		for _, rawSelector := range selectors {
			selector, ok := rawSelector.(map[string]any)
			if !ok {
				return fmt.Errorf("package requirement binding witnessSelector must be an object")
			}
			if value, _ := selector["selector"].(string); value == "" {
				return fmt.Errorf("package requirement binding witness selector must be non-empty")
			}
			if value, _ := selector["command"].(string); value == "" {
				return fmt.Errorf("package requirement binding witness command must be non-empty")
			}
		}
	}
	return nil
}

func verifyWitnessPlanReferences(content string) error {
	value, err := decodePackageJSONObject(content, "witness plan")
	if err != nil {
		return err
	}
	if err := verifyClosedReferenceInventory("witness plan", value, map[string]string{
		"/commands/*/cwd":                      "source_checkout",
		"/commands/*/expectedArtifacts/*/path": "generated_output",
		"/policies/*/inputSelectors":           "source_checkout_or_generated_input",
		"/policies/*/outputSelectors":          "generated_output",
		"/policies/*/cacheAdmissionRefs":       "policy_identifier",
	}); err != nil {
		return err
	}
	commands, ok := value["commands"].([]any)
	if !ok {
		return fmt.Errorf("package witness plan commands must be an array")
	}
	for _, raw := range commands {
		command, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("package witness plan command must be an object")
		}
		cwd, _ := command["cwd"].(string)
		if cwd != "." {
			return fmt.Errorf("package witness plan command cwd must be source checkout root")
		}
		artifacts, _ := command["expectedArtifacts"].([]any)
		for _, rawArtifact := range artifacts {
			artifact, ok := rawArtifact.(map[string]any)
			if !ok {
				return fmt.Errorf("package witness plan expectedArtifact must be an object")
			}
			if err := requireGeneratedOutputReference("package witness plan expectedArtifact", stringField(artifact, "path")); err != nil {
				return err
			}
		}
	}
	policies, ok := value["policies"].([]any)
	if !ok {
		return fmt.Errorf("package witness plan policies must be an array")
	}
	for _, raw := range policies {
		policy, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("package witness plan policy must be an object")
		}
		for _, reference := range stringArrayField(policy, "inputSelectors") {
			if strings.HasPrefix(reference, "artifacts/") {
				if err := requireGeneratedOutputReference("package witness plan generated inputSelector", reference); err != nil {
					return err
				}
				continue
			}
			if err := requireSourceCheckoutReference("package witness plan source inputSelector", reference); err != nil {
				return err
			}
		}
		for _, reference := range stringArrayField(policy, "outputSelectors") {
			if err := requireGeneratedOutputReference("package witness plan outputSelector", reference); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyCommandFamilyReferenceInventory(content string) error {
	value, err := decodePackageJSONObject(content, "command family catalog")
	if err != nil {
		return err
	}
	if err := verifyClosedReferenceInventory("command family catalog", value, map[string]string{}); err != nil {
		return err
	}
	families, ok := value["families"].([]any)
	if !ok {
		return fmt.Errorf("package command family catalog families must be an array")
	}
	for _, raw := range families {
		family, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("package command family must be an object")
		}
		for _, command := range stringArrayField(family, "commands") {
			if looksLikeRepositoryPath(command) {
				return fmt.Errorf("package command family command must be a command identifier, got route %s", command)
			}
		}
	}
	return nil
}

func verifyReceiptPolicyReferences(content string, entries map[string]struct{}) error {
	value, err := decodePackageJSONObject(content, "receipt producer policy")
	if err != nil {
		return err
	}
	if err := verifyClosedReferenceInventory("receipt producer policy", value, map[string]string{
		"/producers/*/evidenceRefs": "package_public_or_source_checkout",
	}); err != nil {
		return err
	}
	producers, ok := value["producers"].([]any)
	if !ok {
		return fmt.Errorf("package receipt producer policy producers must be an array")
	}
	for _, raw := range producers {
		record, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("package receipt producer must be an object")
		}
		refs, ok := record["evidenceRefs"].([]any)
		if !ok {
			return fmt.Errorf("package receipt producer evidenceRefs must be an array")
		}
		for _, rawRef := range refs {
			reference, ok := rawRef.(string)
			if !ok {
				return fmt.Errorf("package receipt producer evidenceRef must be a string")
			}
			if record["producerId"] == "github.actions.package" && reference == ".github/workflows/ci.yml" {
				if err := requireSourceCheckoutReference("package receipt producer source evidenceRef", reference); err != nil {
					return err
				}
				continue
			}
			if err := requireShippedRootReference("package receipt producer evidenceRef", reference, entries); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyCLIContractSourceClassifications(content string, entries map[string]struct{}) error {
	value, err := decodePackageJSONObject(content, "CLI contract")
	if err != nil {
		return err
	}
	if err := verifyClosedReferenceInventory("CLI contract", value, map[string]string{
		"/processContract/helpGrammar/helpCatalogFormsSource":           "package_public",
		"/commands/*/inputContract/fields/availableInputs/item/ref":     "runtime_field",
		"/commands/*/inputContract/fields/knownChangedPaths":            "runtime_field",
		"/commands/*/inputContract/fields/observedReports/item/ref":     "runtime_field",
		"/commands/*/inputContract/nativeAdmissionWitnessSelector":      "source_checkout_selector",
		"/commands/*/inputContract/nativeAdmissionWitnessSelector/path": "source_checkout",
		"/commands/*/inputContract/nativeSource/path":                   "source_checkout",
		"/commands/*/inputContract/nativeSources/*/path":                "source_checkout",
		"/commands/*/inputContract/ownerRequirementRefs":                "requirement_identifier",
		"/commands/*/inputContract/rootDefinitionRef":                   "schema_identifier",
		"/commands/*/outputContract/nativeOutputWitnessSelector":        "source_checkout_selector",
		"/commands/*/outputContract/nativeOutputWitnessSelector/path":   "source_checkout",
		"/commands/*/outputContract/nativeSource/path":                  "source_checkout",
		"/commands/*/outputContract/nativeSources/*/path":               "source_checkout",
		"/commands/*/outputContract/ownerRequirementRefs":               "requirement_identifier",
		"/commands/*/outputContract/qualityFindingFields/evidenceRefs":  "runtime_field",
		"/commands/*/outputContract/records/dependencyRef":              "runtime_field",
		"/commands/*/outputContract/rootDefinitionRef":                  "schema_identifier",
		"/contractDefinitions/*/definitionRefs":                         "schema_identifier",
	}); err != nil {
		return err
	}
	if processContract, _ := value["processContract"].(map[string]any); processContract != nil {
		helpGrammar, _ := processContract["helpGrammar"].(map[string]any)
		if helpGrammar == nil {
			return fmt.Errorf("package CLI contract processContract.helpGrammar must be an object")
		}
		if err := requireShippedRootReference(
			"package CLI contract helpCatalogFormsSource",
			stringField(helpGrammar, "helpCatalogFormsSource"),
			entries,
		); err != nil {
			return err
		}
	}
	commands, ok := value["commands"].([]any)
	if !ok {
		return fmt.Errorf("package CLI contract commands must be an array")
	}
	for _, rawCommand := range commands {
		command, ok := rawCommand.(map[string]any)
		if !ok {
			return fmt.Errorf("package CLI contract command must be an object")
		}
		for _, contractKey := range []string{"inputContract", "outputContract"} {
			contract, _ := command[contractKey].(map[string]any)
			if contract == nil {
				continue
			}
			_, hasSource := contract["nativeSource"]
			_, hasSources := contract["nativeSources"]
			if hasSource == hasSources {
				return fmt.Errorf("package CLI contract %s must declare exactly one of nativeSource or nativeSources", contractKey)
			}
			for _, sourceKey := range []string{"nativeSource", "nativeAdmissionWitnessSelector", "nativeOutputWitnessSelector"} {
				source, _ := contract[sourceKey].(map[string]any)
				if source == nil {
					continue
				}
				reference, _ := source["path"].(string)
				if reference == "" {
					return fmt.Errorf("package CLI contract %s.%s path must be non-empty", contractKey, sourceKey)
				}
				if source["evidenceClass"] != "source_checkout" {
					return fmt.Errorf("package CLI contract source-only %s.%s must declare evidenceClass=source_checkout", contractKey, sourceKey)
				}
				if err := requireSourceCheckoutReference("package CLI contract source path", reference); err != nil {
					return err
				}
			}
			if rawSources, ok := contract["nativeSources"].([]any); ok {
				for index, rawSource := range rawSources {
					source, ok := rawSource.(map[string]any)
					if !ok {
						return fmt.Errorf("package CLI contract %s.nativeSources[%d] must be an object", contractKey, index)
					}
					reference, _ := source["path"].(string)
					if reference == "" {
						return fmt.Errorf("package CLI contract %s.nativeSources[%d] path must be non-empty", contractKey, index)
					}
					if source["evidenceClass"] != "source_checkout" {
						return fmt.Errorf("package CLI contract source-only %s.nativeSources[%d] must declare evidenceClass=source_checkout", contractKey, index)
					}
					if err := requireSourceCheckoutReference("package CLI contract source path", reference); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func verifyClosedReferenceInventory(label string, value any, classifications map[string]string) error {
	var walk func(any, []string) error
	walk = func(current any, route []string) error {
		switch typed := current.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				fieldRoute := append(append([]string{}, route...), key)
				if referenceBearingField(key) {
					pointer := "/" + strings.Join(fieldRoute, "/")
					if _, admitted := classifications[pointer]; !admitted {
						return fmt.Errorf("package %s contains unclassified reference-bearing field %s", label, pointer)
					}
				}
				if err := walk(typed[key], fieldRoute); err != nil {
					return err
				}
			}
		case []any:
			for _, item := range typed {
				if err := walk(item, append(append([]string{}, route...), "*")); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value, nil)
}

func referenceBearingField(key string) bool {
	if key == "helpCatalogFormsSource" {
		return true
	}
	lower := strings.ToLower(key)
	if lower == "cwd" {
		return true
	}
	for _, suffix := range []string{"path", "paths", "ref", "refs", "selector", "selectors"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func requireSourceCheckoutReference(context, reference string) error {
	static, err := safeRepositoryReference(reference)
	if err != nil {
		return fmt.Errorf("%s contains unsafe source-checkout route %s: %w", context, reference, err)
	}
	root, err := findRepositoryRoot()
	if err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	current := root
	if static == "." {
		return nil
	}
	for _, component := range strings.Split(static, "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("%s contains dangling source-checkout route %s", context, reference)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s source-checkout route traverses symlink %s", context, reference)
		}
	}
	return nil
}

func requireGeneratedOutputReference(context, reference string) error {
	static, err := safeRepositoryReference(reference)
	if err != nil {
		return fmt.Errorf("%s contains unsafe generated-output route %s: %w", context, reference, err)
	}
	if static != "artifacts" && !strings.HasPrefix(static, "artifacts/") &&
		static != "dist" && !strings.HasPrefix(static, "dist/") {
		return fmt.Errorf("%s must classify an artifacts/ or dist/ generated-output route, got %s", context, reference)
	}
	return nil
}

func safeRepositoryReference(reference string) (string, error) {
	if reference == "" || strings.HasPrefix(reference, "/") || strings.Contains(reference, `\`) {
		return "", fmt.Errorf("route must be non-empty repository-relative POSIX syntax")
	}
	clean := pathpkg.Clean(reference)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("route escapes repository root")
	}
	static := clean
	if index := strings.IndexAny(static, "*?["); index >= 0 {
		static = strings.TrimSuffix(static[:index], "/")
		if static == "" {
			return "", fmt.Errorf("glob must have an existing static prefix")
		}
	}
	return static, nil
}

func findRepositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	for {
		if info, err := os.Stat(filepath.Join(current, "go.mod")); err == nil && info.Mode().IsRegular() {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("repository root containing go.mod not found")
		}
		current = parent
	}
}

func stringField(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

func stringArrayField(record map[string]any, key string) []string {
	values, _ := record[key].([]any)
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value, ok := raw.(string)
		if !ok {
			return []string{""}
		}
		result = append(result, value)
	}
	return result
}

func decodePackageJSONObject(content, label string) (map[string]any, error) {
	if content == "" {
		return nil, fmt.Errorf("package %s is missing", label)
	}
	value, err := admission.DecodeJSON(strings.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("decode package %s: %w", label, err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("package %s must be an object", label)
	}
	return record, nil
}

func requireShippedRootReference(context, reference string, entries map[string]struct{}) error {
	if !looksLikeRepositoryPath(reference) || strings.HasPrefix(reference, "/") {
		return fmt.Errorf("%s contains unsafe route %s", context, reference)
	}
	target := pathpkg.Clean("package/" + reference)
	if !safePackageEntryReference(target) {
		return fmt.Errorf("%s contains unsafe route %s", context, reference)
	}
	if _, ok := entries[target]; !ok {
		return fmt.Errorf("%s contains dangling package-public route %s", context, reference)
	}
	return nil
}

func requireShippedRootPrefix(context, reference string, entries map[string]struct{}) error {
	if !looksLikeRepositoryPath(reference) || strings.HasPrefix(reference, "/") {
		return fmt.Errorf("%s contains unsafe route %s", context, reference)
	}
	target := pathpkg.Clean("package/" + reference)
	if !safePackageEntryReference(target) {
		return fmt.Errorf("%s contains unsafe route %s", context, reference)
	}
	prefix := strings.TrimSuffix(target, "/") + "/"
	for entry := range entries {
		if strings.HasPrefix(entry, prefix) {
			return nil
		}
	}
	return fmt.Errorf("%s contains dangling package-public route %s", context, reference)
}

func safePackageEntryReference(reference string) bool {
	return reference != "package" &&
		strings.HasPrefix(reference, "package/") &&
		!strings.Contains(reference, `\`) &&
		!strings.Contains(reference, "../")
}

func looksLikeRepositoryPath(reference string) bool {
	return strings.Contains(reference, "/") || strings.Contains(pathpkg.Base(reference), ".")
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
	return withExactTarballConsumer(artifact, func(consumer string) error {
		if err := verifyInstalledOnboardingTrace(consumer, runInstalledWithInput); err != nil {
			return err
		}
		if err := verifyInstalledJSONABI(consumer); err != nil {
			return err
		}
		return verifyOutsideConsumerImports(consumer)
	})
}

func withExactTarballConsumer(artifact rootPackageArtifact, verify func(string) error) error {
	consumer, err := os.MkdirTemp("", "proofkit-consumer-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(consumer)
	tarballPath := filepath.Join(consumer, artifact.Record.Filename)
	if err := os.WriteFile(tarballPath, artifact.Content, 0o644); err != nil {
		return fmt.Errorf("write snapshot package tarball: %w", err)
	}
	packageJSON, err := json.Marshal(map[string]any{
		"private": true,
		"type":    "module",
		"dependencies": map[string]string{
			rootPackageName: "file:" + tarballPath,
		},
	})
	if err != nil {
		return fmt.Errorf("encode outside consumer package manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "package.json"), append(packageJSON, '\n'), 0o644); err != nil {
		return err
	}
	if output, err := run(consumer, "npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"); err != nil {
		return fmt.Errorf("outside consumer install failed: %w\n%s", err, output)
	}
	return verify(consumer)
}

func run(dir string, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Dir = dir
	return command.CombinedOutput()
}

type installedCommandOperation func(string, []byte, ...string) (installedCommandResult, error)

type installedHelpRoute struct {
	ID   string
	Argv []string
}

func verifyInstalledOnboardingTrace(consumer string, execute installedCommandOperation) error {
	rootHelp, err := execute(consumer, nil, "help")
	if err != nil {
		return fmt.Errorf("outside consumer root help failed to run: %w", err)
	}
	if err := requireInstalledTextSuccess(rootHelp, "root help"); err != nil {
		return err
	}
	familyArgv, err := installedRootHelpFamilyArgv(rootHelp.Stdout)
	if err != nil {
		return err
	}
	if !bytes.Contains(rootHelp.Stdout, []byte("CLI/JSON is the public cross-language contract")) {
		return fmt.Errorf("outside consumer root help did not expose the family discovery and CLI contract routes")
	}
	families, err := execute(consumer, nil, familyArgv...)
	if err != nil {
		return fmt.Errorf("outside consumer family help failed to run: %w", err)
	}
	if err := requireInstalledTextSuccess(families, "family help"); err != nil {
		return err
	}
	familyRoutes, err := parseInstalledFamilyRoutes(string(families.Stdout))
	if err != nil {
		return err
	}
	var stackHelp installedCommandResult
	var requirementSourceHelp installedCommandResult
	stackHelpFound := false
	requirementSourceHelpFound := false
	for _, familyRoute := range familyRoutes {
		family, err := execute(consumer, nil, familyRoute.Argv...)
		if err != nil {
			return fmt.Errorf("outside consumer family %s failed to run: %w", familyRoute.ID, err)
		}
		if err := requireInstalledTextSuccess(family, "family "+familyRoute.ID); err != nil {
			return err
		}
		leafRoutes, err := parseInstalledLeafHelpRoutes(string(family.Stdout))
		if err != nil {
			return fmt.Errorf("outside consumer family %s: %w", familyRoute.ID, err)
		}
		for _, leafRoute := range leafRoutes {
			leafHelp, err := execute(consumer, nil, leafRoute.Argv...)
			if err != nil {
				return fmt.Errorf("outside consumer %s help failed to run: %w", leafRoute.ID, err)
			}
			if err := requireInstalledTextSuccess(leafHelp, leafRoute.ID+" help"); err != nil {
				return err
			}
			if err := requireInstalledInvocationSyntax(leafHelp.Stdout, leafRoute.ID); err != nil {
				return err
			}
			switch leafRoute.ID {
			case "stack-preset":
				if stackHelpFound {
					return fmt.Errorf("outside consumer family navigation exposed stack-preset more than once")
				}
				stackHelp = leafHelp
				stackHelpFound = true
			case "requirement-source-admission":
				if requirementSourceHelpFound {
					return fmt.Errorf("outside consumer family navigation exposed requirement-source-admission more than once")
				}
				requirementSourceHelp = leafHelp
				requirementSourceHelpFound = true
			}
		}
	}
	if !stackHelpFound {
		return fmt.Errorf("outside consumer family navigation did not expose stack-preset")
	}
	if !requirementSourceHelpFound {
		return fmt.Errorf("outside consumer family navigation did not expose requirement-source-admission")
	}
	presetRoutes, err := parseInstalledPresetRoutes(string(stackHelp.Stdout))
	if err != nil {
		return err
	}
	contractPath := filepath.Join(consumer, "node_modules", "@research-engineering", "agentic-proofkit", "proofkit", "cli-contract.v2.json")
	contractContent, err := os.ReadFile(contractPath)
	if err != nil {
		return fmt.Errorf("read installed CLI contract: %w", err)
	}
	contractPresetIDs, err := installedContractPresetIDs(contractContent)
	if err != nil {
		return err
	}
	helpPresetIDs := make([]string, 0, len(presetRoutes))
	for _, route := range presetRoutes {
		helpPresetIDs = append(helpPresetIDs, route.ID)
	}
	if !sameStrings(helpPresetIDs, contractPresetIDs) {
		return fmt.Errorf("installed stack-preset help ids=%v contract ids=%v", helpPresetIDs, contractPresetIDs)
	}
	var firstSelfContinuation []string
	for _, presetRoute := range presetRoutes {
		result, err := execute(consumer, nil, presetRoute.Argv...)
		if err != nil {
			return fmt.Errorf("outside consumer stack preset %s failed to run: %w", presetRoute.ID, err)
		}
		if err := requirePassedJSON(result, "stack preset "+presetRoute.ID); err != nil {
			return err
		}
		continuations, err := installedPresetContinuationArgv(result, presetRoute.ID)
		if err != nil {
			return err
		}
		if firstSelfContinuation == nil {
			firstSelfContinuation = append([]string{}, continuations[0]...)
		}
	}
	if len(firstSelfContinuation) == 0 {
		return fmt.Errorf("outside consumer stack presets exposed no executable self-continuation")
	}
	continuation, err := execute(consumer, nil, firstSelfContinuation...)
	if err != nil {
		return fmt.Errorf("outside consumer stack preset self-continuation failed to run: %w", err)
	}
	if err := requirePassedJSON(continuation, "stack preset self-continuation"); err != nil {
		return err
	}
	readmeRelativePath, err := installedREADMEPath(requirementSourceHelp.Stdout)
	if err != nil {
		return err
	}
	readmePath := filepath.Join(consumer, filepath.FromSlash(readmeRelativePath))
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		return fmt.Errorf("read installed README: %w", err)
	}
	argv, input, err := installedREADMEFirstInput(readme)
	if err != nil {
		return err
	}
	result, err := execute(consumer, input, argv...)
	if err != nil {
		return fmt.Errorf("outside consumer README first-input command failed to run: %w", err)
	}
	return requirePassedJSON(result, "README first-input command")
}

func installedRootHelpFamilyArgv(content []byte) ([]string, error) {
	const routeFragment = "agentic-proofkit help families"
	decoded, err := unicodepolicy.DecodeUTF8(content)
	if err != nil {
		return nil, fmt.Errorf("installed README is not valid UTF-8")
	}
	var command string
	matchCount := 0
	for _, line := range strings.Split(decoded, "\n") {
		if !strings.Contains(line, routeFragment) {
			continue
		}
		command = strings.TrimLeft(line, " \t")
		matchCount++
	}
	if matchCount != 1 {
		return nil, fmt.Errorf("outside consumer root help must expose exactly one family discovery route")
	}
	if !strings.HasPrefix(command, installedNPMExecCommandPrefix) {
		return nil, fmt.Errorf("outside consumer root help family route must use npm exec --offline")
	}
	argv, err := parseLiteralShellWords(strings.TrimPrefix(command, installedNPMExecCommandPrefix))
	if err != nil {
		return nil, fmt.Errorf("outside consumer root help family route must use bounded literal shell words: %w", err)
	}
	if len(argv) != 2 || argv[0] != "help" || argv[1] != "families" {
		return nil, fmt.Errorf("outside consumer root help family route must resolve to help families")
	}
	return argv, nil
}

func parseInstalledFamilyRoutes(help string) ([]installedHelpRoute, error) {
	ids, err := parseInstalledFamilyIDs(help)
	if err != nil {
		return nil, err
	}
	routeByID := map[string][]string{}
	for _, line := range strings.Split(help, "\n") {
		if !strings.Contains(line, "agentic-proofkit help family ") {
			continue
		}
		argv, err := installedNPMExecArgv(line, "family discovery")
		if err != nil {
			return nil, err
		}
		if len(argv) != 3 || argv[0] != "help" || argv[1] != "family" || argv[2] == "" {
			return nil, fmt.Errorf("outside consumer family discovery route must resolve to help family <family-id>")
		}
		if _, exists := routeByID[argv[2]]; exists {
			return nil, fmt.Errorf("outside consumer family discovery route %q is duplicated", argv[2])
		}
		routeByID[argv[2]] = argv
	}
	if len(routeByID) != len(ids) {
		return nil, fmt.Errorf("outside consumer family discovery routes=%d family ids=%d", len(routeByID), len(ids))
	}
	routes := make([]installedHelpRoute, 0, len(ids))
	for _, id := range ids {
		argv, ok := routeByID[id]
		if !ok {
			return nil, fmt.Errorf("outside consumer family %q has no copyable discovery route", id)
		}
		routes = append(routes, installedHelpRoute{ID: id, Argv: argv})
	}
	return routes, nil
}

func parseInstalledLeafHelpRoutes(help string) ([]installedHelpRoute, error) {
	commandIDs := []string{}
	seenCommandIDs := map[string]struct{}{}
	inCommands := false
	for _, line := range strings.Split(help, "\n") {
		if line == "Commands:" {
			inCommands = true
			continue
		}
		if !inCommands || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "    ") {
			continue
		}
		commandID := strings.TrimSpace(line)
		if commandID == "" || strings.ContainsAny(commandID, " \t") {
			return nil, fmt.Errorf("command family has an invalid command id %q", commandID)
		}
		if _, exists := seenCommandIDs[commandID]; exists {
			return nil, fmt.Errorf("command family has duplicate command id %q", commandID)
		}
		seenCommandIDs[commandID] = struct{}{}
		commandIDs = append(commandIDs, commandID)
	}
	if len(commandIDs) == 0 {
		return nil, fmt.Errorf("command family exposed no command ids")
	}

	routeByID := map[string][]string{}
	for _, line := range strings.Split(help, "\n") {
		if !strings.Contains(line, "agentic-proofkit help ") {
			continue
		}
		argv, err := installedNPMExecArgv(line, "leaf help")
		if err != nil {
			return nil, err
		}
		if len(argv) != 2 || argv[0] != "help" || argv[1] == "" {
			return nil, fmt.Errorf("outside consumer leaf help route must resolve to help <command>")
		}
		if _, exists := routeByID[argv[1]]; exists {
			return nil, fmt.Errorf("outside consumer command %q has duplicate copyable help routes", argv[1])
		}
		routeByID[argv[1]] = argv
	}
	if len(routeByID) != len(commandIDs) {
		return nil, fmt.Errorf("outside consumer leaf help routes=%d command ids=%d", len(routeByID), len(commandIDs))
	}
	routes := make([]installedHelpRoute, 0, len(commandIDs))
	for _, commandID := range commandIDs {
		argv, ok := routeByID[commandID]
		if !ok {
			return nil, fmt.Errorf("outside consumer command %q has no copyable help route", commandID)
		}
		routes = append(routes, installedHelpRoute{ID: commandID, Argv: argv})
	}
	return routes, nil
}

func requireInstalledInvocationSyntax(content []byte, command string) error {
	decoded, err := unicodepolicy.DecodeUTF8(content)
	if err != nil {
		return fmt.Errorf("installed README is not valid UTF-8")
	}
	lines := strings.Split(decoded, "\n")
	var usage string
	var installed string
	usageCount := 0
	installedCount := 0
	usageIndex := -1
	installedIndex := -1
	for index, line := range lines {
		if line == "Usage:" {
			usageCount++
			if index+1 >= len(lines) {
				return fmt.Errorf("outside consumer command %q has no usage line", command)
			}
			usage = strings.TrimLeft(lines[index+1], " \t")
			usageIndex = index
		}
		if line == "Installed invocation:" {
			installedCount++
			if index+1 >= len(lines) {
				return fmt.Errorf("outside consumer command %q has no installed invocation line", command)
			}
			installed = strings.TrimLeft(lines[index+1], " \t")
			installedIndex = index
		}
	}
	commandPrefix := "agentic-proofkit " + command
	if usageCount != 1 || installedCount != 1 ||
		installedIndex != usageIndex+3 ||
		(usage != commandPrefix && !strings.HasPrefix(usage, commandPrefix+" ")) {
		return fmt.Errorf("outside consumer command %q must expose one exact bare usage and installed invocation", command)
	}
	if installed != "npm exec --offline -- "+usage {
		return fmt.Errorf("outside consumer command %q installed invocation must prefix its exact usage with npm exec --offline", command)
	}
	return nil
}

func parseInstalledPresetRoutes(help string) ([]installedHelpRoute, error) {
	ids, err := parseInstalledPresetIDs(help)
	if err != nil {
		return nil, err
	}
	routeByID := map[string][]string{}
	for _, line := range strings.Split(help, "\n") {
		if !strings.Contains(line, "agentic-proofkit stack-preset --preset ") {
			continue
		}
		if strings.Contains(line, "<") {
			continue
		}
		argv, err := installedNPMExecArgv(line, "stack preset")
		if err != nil {
			return nil, err
		}
		if len(argv) != 3 || argv[0] != "stack-preset" || argv[1] != "--preset" || argv[2] == "" {
			return nil, fmt.Errorf("outside consumer stack-preset route must resolve to stack-preset --preset <id>")
		}
		if _, exists := routeByID[argv[2]]; exists {
			return nil, fmt.Errorf("outside consumer stack-preset route %q is duplicated", argv[2])
		}
		routeByID[argv[2]] = argv
	}
	if len(routeByID) != len(ids) {
		return nil, fmt.Errorf("outside consumer stack-preset routes=%d preset ids=%d", len(routeByID), len(ids))
	}
	routes := make([]installedHelpRoute, 0, len(ids))
	for _, id := range ids {
		argv, ok := routeByID[id]
		if !ok {
			return nil, fmt.Errorf("outside consumer preset %q has no copyable execution route", id)
		}
		routes = append(routes, installedHelpRoute{ID: id, Argv: argv})
	}
	return routes, nil
}

func installedREADMEPath(content []byte) (string, error) {
	const prefix = "Path: "
	const expected = "node_modules/@research-engineering/agentic-proofkit/README.md"
	var discovered string
	matchCount := 0
	decoded, err := unicodepolicy.DecodeUTF8(content)
	if err != nil {
		return "", fmt.Errorf("installed README is not valid UTF-8")
	}
	for _, line := range strings.Split(decoded, "\n") {
		line = strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		discovered = strings.TrimPrefix(line, prefix)
		matchCount++
	}
	if matchCount != 1 || discovered != expected {
		return "", fmt.Errorf("outside consumer requirement-source-admission help must expose the exact installed README path")
	}
	return discovered, nil
}

func installedNPMExecArgv(line string, label string) ([]string, error) {
	command := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(command, installedNPMExecCommandPrefix) {
		return nil, fmt.Errorf("outside consumer %s route must use npm exec --offline", label)
	}
	argv, err := parseLiteralShellWords(strings.TrimPrefix(command, installedNPMExecCommandPrefix))
	if err != nil {
		return nil, fmt.Errorf("outside consumer %s route must use bounded literal shell words: %w", label, err)
	}
	return argv, nil
}

func installedPresetContinuationArgv(result installedCommandResult, presetID string) ([][]string, error) {
	value, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), 8<<20)
	if err != nil {
		return nil, fmt.Errorf("outside consumer stack preset %s stdout must be one JSON value: %w", presetID, err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("outside consumer stack preset %s output must be an object", presetID)
	}
	diagnostics, ok := record["diagnostics"].([]any)
	if !ok {
		return nil, fmt.Errorf("outside consumer stack preset %s output must expose diagnostics", presetID)
	}
	var presetValue map[string]any
	presetDiagnosticCount := 0
	for _, rawDiagnostic := range diagnostics {
		diagnostic, ok := rawDiagnostic.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("outside consumer stack preset %s diagnostics must contain objects", presetID)
		}
		if diagnostic["key"] != "preset" {
			continue
		}
		presetDiagnosticCount++
		presetValue, ok = diagnostic["value"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("outside consumer stack preset %s preset diagnostic must contain an object value", presetID)
		}
	}
	if presetDiagnosticCount != 1 {
		return nil, fmt.Errorf("outside consumer stack preset %s must expose exactly one preset diagnostic", presetID)
	}
	rawCommands, ok := presetValue["suggestedCommands"].([]any)
	if !ok || len(rawCommands) == 0 {
		return nil, fmt.Errorf("outside consumer stack preset %s must expose non-empty suggestedCommands", presetID)
	}
	continuations := make([][]string, 0, len(rawCommands))
	firstCommand := ""
	for index, rawCommand := range rawCommands {
		command, ok := rawCommand.(string)
		if !ok || command == "" {
			return nil, fmt.Errorf("outside consumer stack preset %s suggestedCommands[%d] must be a non-empty string", presetID, index)
		}
		if command != strings.TrimSpace(command) || !strings.HasPrefix(command, installedNPMExecCommandPrefix) {
			return nil, fmt.Errorf("outside consumer stack preset %s suggestedCommands[%d] must use the exact npm exec --offline prefix", presetID, index)
		}
		argv, err := parseLiteralShellWords(strings.TrimPrefix(command, installedNPMExecCommandPrefix))
		if err != nil {
			return nil, fmt.Errorf("outside consumer stack preset %s suggestedCommands[%d] must use bounded literal shell words: %w", presetID, index, err)
		}
		if len(argv) == 0 {
			return nil, fmt.Errorf("outside consumer stack preset %s suggestedCommands[%d] has no Proofkit argv", presetID, index)
		}
		if index == 0 {
			firstCommand = command
		}
		continuations = append(continuations, argv)
	}
	expectedSelfContinuation := installedNPMExecCommandPrefix + "stack-preset --preset " + presetID
	if firstCommand != expectedSelfContinuation {
		return nil, fmt.Errorf("outside consumer stack preset %s first suggested command must be its exact self-continuation", presetID)
	}
	return continuations, nil
}

func requireInstalledTextSuccess(result installedCommandResult, label string) error {
	if result.ExitCode != 0 || len(result.Stderr) != 0 || len(result.Stdout) == 0 {
		return fmt.Errorf("outside consumer %s exit=%d stdout=%q stderr=%q", label, result.ExitCode, result.Stdout, result.Stderr)
	}
	return nil
}

func requirePassedJSON(result installedCommandResult, label string) error {
	if result.ExitCode != 0 || len(result.Stderr) != 0 {
		return fmt.Errorf("outside consumer %s exit=%d stdout=%q stderr=%q", label, result.ExitCode, result.Stdout, result.Stderr)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), 8<<20)
	if err != nil {
		return fmt.Errorf("outside consumer %s stdout must be one JSON value: %w", label, err)
	}
	record, ok := value.(map[string]any)
	if !ok || record["state"] != "passed" {
		return fmt.Errorf("outside consumer %s state is not passed", label)
	}
	return nil
}

func parseInstalledFamilyIDs(help string) ([]string, error) {
	ids := []string{}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(help, "\n") {
		if !strings.HasPrefix(line, "  ") || !strings.Contains(line, "\t") {
			continue
		}
		id := strings.TrimSpace(strings.SplitN(strings.TrimSpace(line), "\t", 2)[0])
		if id != "" {
			if _, exists := seen[id]; exists {
				return nil, fmt.Errorf("outside consumer family help duplicated family id %q", id)
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("outside consumer family help exposed no family ids")
	}
	return ids, nil
}

func parseInstalledPresetIDs(help string) ([]string, error) {
	const prefix = "agentic-proofkit stack-preset --preset <"
	start := strings.Index(help, prefix)
	if start < 0 {
		return nil, fmt.Errorf("outside consumer stack-preset help omitted preset vocabulary")
	}
	start += len(prefix)
	end := strings.Index(help[start:], ">")
	if end < 0 {
		return nil, fmt.Errorf("outside consumer stack-preset help has an unclosed preset vocabulary")
	}
	ids := strings.Split(help[start:start+end], "|")
	if len(ids) == 0 || !sort.StringsAreSorted(ids) {
		return nil, fmt.Errorf("outside consumer stack-preset help ids must be non-empty and sorted")
	}
	return ids, nil
}

func installedContractPresetIDs(content []byte) ([]string, error) {
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("decode installed CLI contract: %w", err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("installed CLI contract must be an object")
	}
	commands, ok := record["commands"].([]any)
	if !ok {
		return nil, fmt.Errorf("installed CLI contract commands must be an array")
	}
	for _, raw := range commands {
		command, _ := raw.(map[string]any)
		if command["command"] != "stack-preset" {
			continue
		}
		output, _ := command["outputContract"].(map[string]any)
		choices, _ := output["flagChoices"].(map[string]any)
		rawIDs, _ := choices["--preset"].([]any)
		ids := make([]string, 0, len(rawIDs))
		for _, rawID := range rawIDs {
			id, ok := rawID.(string)
			if !ok || id == "" {
				return nil, fmt.Errorf("installed CLI contract stack-preset choices must be non-empty strings")
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 || !sort.StringsAreSorted(ids) {
			return nil, fmt.Errorf("installed CLI contract stack-preset choices must be non-empty and sorted")
		}
		return ids, nil
	}
	return nil, fmt.Errorf("installed CLI contract omitted stack-preset")
}

func installedREADMEFirstInput(content []byte) ([]string, []byte, error) {
	text, err := unicodepolicy.DecodeUTF8(content)
	if err != nil {
		return nil, nil, fmt.Errorf("installed README is not valid UTF-8")
	}
	const startMarker = "<!-- proofkit:first-valid-input:start -->"
	const endMarker = "<!-- proofkit:first-valid-input:end -->"
	if strings.Count(text, startMarker) != 1 || strings.Count(text, endMarker) != 1 {
		return nil, nil, fmt.Errorf("installed README first-input markers must occur exactly once")
	}
	start := strings.Index(text, startMarker) + len(startMarker)
	end := strings.Index(text, endMarker)
	if start >= end {
		return nil, nil, fmt.Errorf("installed README first-input marker order is invalid")
	}
	block := text[start:end]
	fenceLines := regexp.MustCompile("(?m)^[ \\t]*(?:`{3,}|~{3,})[^\\r\\n]*$").FindAllString(block, -1)
	if len(fenceLines) != 4 {
		return nil, nil, fmt.Errorf("installed README first-input block must contain one bash command and one JSON value")
	}
	for _, line := range fenceLines {
		if strings.Contains(line, "~") {
			return nil, nil, fmt.Errorf("installed README first-input block must contain one bash command and one JSON value")
		}
	}
	match := regexp.MustCompile("(?s)^\\s*```bash[ \\t]*\\r?\\n([^\\r\\n]+)\\r?\\n```[ \\t]*\\r?\\n\\s*```json[ \\t]*\\r?\\n(.*?)\\r?\\n```[ \\t]*\\s*$").FindStringSubmatch(block)
	if len(match) != 3 {
		return nil, nil, fmt.Errorf("installed README first-input block must contain one bash command and one JSON value")
	}
	command := strings.TrimLeft(match[1], " \t")
	if !strings.HasPrefix(command, installedNPMExecCommandPrefix) {
		return nil, nil, fmt.Errorf("installed README first-input command must use npm exec --offline")
	}
	argv, err := parseLiteralShellWords(strings.TrimPrefix(command, installedNPMExecCommandPrefix))
	if err != nil {
		return nil, nil, fmt.Errorf("installed README first-input command must use bounded literal shell words: %w", err)
	}
	if len(argv) == 0 {
		return nil, nil, fmt.Errorf("installed README first-input command has no Proofkit argv")
	}
	input := []byte(match[2] + "\n")
	if _, err := admission.DecodeJSON(bytes.NewReader(input), int64(len(input))); err != nil {
		return nil, nil, fmt.Errorf("installed README first-input JSON is invalid: %w", err)
	}
	return argv, input, nil
}

func parseLiteralShellWords(command string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote byte
	wordStarted := false

	backslashRunEnd := func(index int) int {
		end := index
		for end < len(command) && command[end] == '\\' {
			end++
		}
		return end
	}
	writeBackslashes := func(count int) {
		for range count {
			word.WriteByte('\\')
		}
	}
	flush := func() {
		if !wordStarted {
			return
		}
		words = append(words, word.String())
		word.Reset()
		wordStarted = false
	}
	for index := 0; index < len(command); index++ {
		character := command[index]
		if character == 0 {
			return nil, fmt.Errorf("NUL is not allowed")
		}
		if character == '\r' || character == '\n' {
			return nil, fmt.Errorf("line breaks are not allowed")
		}
		switch quote {
		case '\'':
			if character == '\'' {
				quote = 0
			} else {
				word.WriteByte(character)
			}
			continue
		case '"':
			switch character {
			case '"':
				quote = 0
			case '$', '`':
				return nil, fmt.Errorf("shell expansion is not allowed")
			case '!':
				return nil, fmt.Errorf("history expansion is not allowed")
			case '\\':
				end := backslashRunEnd(index)
				count := end - index
				if end == len(command) {
					return nil, fmt.Errorf("trailing escape in double-quoted word")
				}
				next := command[end]
				if next == 0 {
					return nil, fmt.Errorf("NUL is not allowed")
				}
				if next == '\r' || next == '\n' {
					return nil, fmt.Errorf("line continuation is not allowed")
				}
				if next == '!' {
					writeBackslashes((count + 1) / 2)
					word.WriteByte(next)
					index = end
					continue
				}
				writeBackslashes(count / 2)
				if count%2 != 0 && strings.ContainsRune("\"\\$`", rune(next)) {
					word.WriteByte(next)
					index = end
				} else {
					if count%2 != 0 {
						word.WriteByte('\\')
					}
					index = end - 1
				}
			default:
				word.WriteByte(character)
			}
			continue
		}

		switch character {
		case ' ', '\t':
			flush()
		case '\'', '"':
			quote = character
			wordStarted = true
		case '\\':
			end := backslashRunEnd(index)
			count := end - index
			if end == len(command) {
				if count%2 != 0 {
					return nil, fmt.Errorf("trailing escape")
				}
				writeBackslashes(count / 2)
				wordStarted = true
				index = end - 1
				continue
			}
			next := command[end]
			if next == 0 {
				return nil, fmt.Errorf("NUL is not allowed")
			}
			if next == '\r' || next == '\n' {
				return nil, fmt.Errorf("line continuation is not allowed")
			}
			writeBackslashes(count / 2)
			if next == '!' || count%2 != 0 {
				word.WriteByte(next)
				index = end
			} else {
				index = end - 1
			}
			wordStarted = true
		default:
			if strings.ContainsRune(";&|<>()$`*?[]{}~#!", rune(character)) {
				return nil, fmt.Errorf("shell operators and expansion syntax are not allowed")
			}
			word.WriteByte(character)
			wordStarted = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted word")
	}
	flush()
	return words, nil
}

func verifyInstalledJSONABI(consumer string) error {
	if err := os.WriteFile(filepath.Join(consumer, "unlisted-poison.md"), []byte("bad trailing \n"), 0o644); err != nil {
		return fmt.Errorf("write unlisted poison file: %w", err)
	}
	success, err := runInstalledWithInput(consumer, packageSmokeSuccessInput(), "text-policy", "--input", "-")
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
	compactSuccess, err := runInstalledWithInput(consumer, packageSmokeSuccessInput(), "--json-layout", "compact", "text-policy", "--input", "-")
	if err != nil {
		return fmt.Errorf("outside consumer compact JSON success smoke failed to run: %w", err)
	}
	if err := verifyTextPolicySmokeReport(compactSuccess, "proofkit.package-smoke.success", "passed", 0, textPolicySmokeSummary{CheckedTextFileCount: 1, FailureCount: 0, InputFileCount: 1}); err != nil {
		return fmt.Errorf("outside consumer compact JSON success smoke failed: %w", err)
	}
	failed, err := runInstalledWithInput(consumer, packageSmokeFailureInput(), "text-policy", "--input", "-")
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
	compactFailed, err := runInstalledWithInput(consumer, packageSmokeFailureInput(), "--json-layout", "compact", "text-policy", "--input", "-")
	if err != nil {
		return fmt.Errorf("outside consumer compact JSON failure smoke failed to run: %w", err)
	}
	if err := verifyTextPolicySmokeReport(compactFailed, "proofkit.package-smoke.failure", "failed", 1, textPolicySmokeSummary{CheckedTextFileCount: 1, FailureCount: 1, InputFileCount: 1}); err != nil {
		return fmt.Errorf("outside consumer compact JSON failure smoke failed: %w", err)
	}
	if err := verifyJSONAdapterSourceSmoke(consumer); err != nil {
		return err
	}
	if err := workflowsmoke.Verify(func(input []byte, args ...string) (workflowsmoke.Result, error) {
		result, err := runInstalledWithInput(consumer, input, args...)
		return workflowsmoke.Result{ExitCode: result.ExitCode, Stdout: result.Stdout, Stderr: result.Stderr}, err
	}); err != nil {
		return fmt.Errorf("outside consumer agent-workflow smoke failed: %w", err)
	}
	return nil
}

func verifyJSONAdapterSourceSmoke(consumer string) error {
	result, err := runInstalledWithInput(consumer, nil, "json-report-cli-adapter-source", "--language", "typescript")
	if err != nil {
		return fmt.Errorf("outside consumer JSON adapter source smoke failed to run: %w", err)
	}
	return verifyJSONAdapterSourceSmokeReport(result, jsonreportcliadaptersource.TypeScriptSource())
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
	if report.GeneratorID != "proofkit.json-report-cli-adapter-source.typescript.v2" {
		return fmt.Errorf("generatorId=%s, want proofkit.json-report-cli-adapter-source.typescript.v2", report.GeneratorID)
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

func runInstalledWithInput(dir string, input []byte, args ...string) (installedCommandResult, error) {
	npmArgs := append([]string{"exec", "--offline", "--", "agentic-proofkit"}, args...)
	return runWithInput(dir, "npm", input, npmArgs...)
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
			rootPackageName + "/proofkit/cli-contract.v2.json",
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
const payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(readFileSync("proofkit-import-boundary.json")));
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
