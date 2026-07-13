package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasepublisher"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/trustedpublisher"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const (
	artifactKind      = "proofkit.release-manifest.v1"
	pythonPackageName = "agentic-proofkit"
	schemaVersion     = 1
	npmRegistry       = releasechannel.NPMRegistryURL
)

type packageJSON struct {
	Description    string         `json:"description"`
	License        string         `json:"license"`
	Name           string         `json:"name"`
	PackageManager string         `json:"packageManager"`
	Repository     repositoryJSON `json:"repository"`
	Version        string         `json:"version"`
}

type repositoryJSON struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type packRecord struct {
	Filename     string `json:"filename"`
	Integrity    string `json:"integrity"`
	Name         string `json:"name"`
	Shasum       string `json:"shasum"`
	UnpackedSize int64  `json:"unpackedSize,omitempty"`
	Version      string `json:"version"`
}

type pythonPackageSet struct {
	ArtifactKind   string              `json:"artifactKind"`
	PackageName    string              `json:"packageName"`
	PackageVersion string              `json:"packageVersion"`
	Packages       []pythonWheelRecord `json:"packages"`
	SchemaVersion  int                 `json:"schemaVersion"`
}

type pypiRegistrySet struct {
	ArtifactKind       string              `json:"artifactKind"`
	AuthorityChannel   string              `json:"authorityChannel"`
	AuthorityValidator string              `json:"authorityValidator"`
	NonClaims          []string            `json:"nonClaims"`
	PackageName        string              `json:"packageName"`
	PackageVersion     string              `json:"packageVersion"`
	Packages           []pythonWheelRecord `json:"packages"`
	Registry           string              `json:"registry"`
	SchemaVersion      int                 `json:"schemaVersion"`
	Source             string              `json:"source"`
}

type pythonWheelRecord struct {
	AbiTag         string `json:"abiTag"`
	BinarySha256   string `json:"binarySha256"`
	Filename       string `json:"filename"`
	Name           string `json:"name"`
	PackageType    string `json:"packageType,omitempty"`
	PlatformSuffix string `json:"platformSuffix"`
	PlatformTag    string `json:"platformTag"`
	PythonTag      string `json:"pythonTag"`
	Sha256         string `json:"sha256"`
	URL            string `json:"url,omitempty"`
	Version        string `json:"version"`
	WheelTag       string `json:"wheelTag"`
}

type releaseManifest struct {
	ArtifactKind            string                   `json:"artifactKind"`
	SchemaVersion           int                      `json:"schemaVersion"`
	Package                 packageIdentity          `json:"package"`
	Source                  sourceIdentity           `json:"source"`
	Workflow                workflowIdentity         `json:"workflow"`
	Toolchain               toolchainIdentity        `json:"toolchain"`
	Channels                []channelEvidence        `json:"channels"`
	LocalPackEvidence       []packageEvidence        `json:"localPackEvidence"`
	RegistryInstallEvidence *registryInstallEvidence `json:"registryInstallEvidence,omitempty"`
	NonClaims               []string                 `json:"nonClaims"`
}

type packageIdentity struct {
	Description    string `json:"description"`
	License        string `json:"license"`
	Name           string `json:"name"`
	PackageManager string `json:"packageManager"`
	RepositoryURL  string `json:"repositoryUrl"`
	Version        string `json:"version"`
}

type sourceIdentity struct {
	CanonicalKind string `json:"canonicalKind"`
	GoModule      string `json:"goModule"`
	GitCommit     string `json:"gitCommit,omitempty"`
	GitRef        string `json:"gitRef,omitempty"`
}

type workflowIdentity struct {
	EventName  string `json:"eventName,omitempty"`
	Name       string `json:"name,omitempty"`
	RunnerOS   string `json:"runnerOS,omitempty"`
	RunnerArch string `json:"runnerArch,omitempty"`
}

type toolchainIdentity struct {
	Go   string `json:"go"`
	Node string `json:"node,omitempty"`
	Npm  string `json:"npm,omitempty"`
}

type channelEvidence struct {
	AuthorityChannel     string                     `json:"authorityChannel"`
	AuthorityValidator   string                     `json:"authorityValidator"`
	Kind                 string                     `json:"kind"`
	PublicationMode      string                     `json:"publicationMode,omitempty"`
	PublisherEnvironment string                     `json:"publisherEnvironment,omitempty"`
	TrustedPublisher     *trustedpublisher.Identity `json:"trustedPublisher,omitempty"`
	Role                 string                     `json:"role"`
	Status               string                     `json:"status"`
	Registry             string                     `json:"registry,omitempty"`
	Assets               []assetEvidence            `json:"assets,omitempty"`
	Packages             []packageEvidence          `json:"packages,omitempty"`
	NonClaims            []string                   `json:"nonClaims,omitempty"`
}

type packageEvidence struct {
	AbiTag         string `json:"abiTag,omitempty"`
	BinarySha256   string `json:"binarySha256,omitempty"`
	Filename       string `json:"filename,omitempty"`
	Integrity      string `json:"integrity,omitempty"`
	Name           string `json:"name"`
	PackageType    string `json:"packageType,omitempty"`
	PlatformSuffix string `json:"platformSuffix,omitempty"`
	PlatformTag    string `json:"platformTag,omitempty"`
	PythonTag      string `json:"pythonTag,omitempty"`
	Shasum         string `json:"shasum,omitempty"`
	Sha256         string `json:"sha256,omitempty"`
	URL            string `json:"url,omitempty"`
	Version        string `json:"version"`
	WheelTag       string `json:"wheelTag,omitempty"`
}

type assetEvidence struct {
	Filename string `json:"filename"`
	Sha256   string `json:"sha256"`
}

type registryInstallEvidence struct {
	Kind                       string `json:"kind"`
	AuditSignaturesSha256      string `json:"auditSignaturesSha256,omitempty"`
	AdapterSourceReportSha256  string `json:"adapterSourceReportSha256,omitempty"`
	FailedReportSha256         string `json:"failedReportSha256,omitempty"`
	HelpOutputSha256           string `json:"helpOutputSha256,omitempty"`
	PackageLockSha256          string `json:"packageLockSha256,omitempty"`
	PublishedArtifactSetSha256 string `json:"publishedArtifactSetSha256,omitempty"`
	SuccessReportSha256        string `json:"successReportSha256,omitempty"`
}

type trustedPublisherSet struct {
	NPM  *trustedpublisher.Identity
	PyPI *trustedpublisher.Identity
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	manifest, err := readPackageJSON("package.json")
	if err != nil {
		return err
	}
	changeRecord, err := releasechange.Read(releasechange.RecordPath)
	if err != nil {
		return err
	}
	if err := releasechange.RequireVersion(changeRecord, manifest.Version); err != nil {
		return err
	}
	localRecords, err := readPackRecords(filepath.Join("artifacts", "package", "npm-pack.json"))
	if err != nil {
		return err
	}
	sortPackRecords(localRecords)
	pythonPackages, err := optionalPythonPackageSet(filepath.Join("artifacts", "pypi", "python-packages.json"))
	if err != nil {
		return err
	}
	assets, checksums, sbomSubjectChecksums, err := releaseAssets(localRecords, pythonPackages)
	if err != nil {
		return err
	}
	registryRecords, err := optionalPackRecords(filepath.Join("artifacts", "registry", "npm-pack.json"))
	if err != nil {
		return err
	}
	if len(registryRecords) > 0 {
		sortPackRecords(registryRecords)
	}
	pypiRegistry, err := optionalPyPIRegistrySet(filepath.Join("artifacts", "pypi-registry", "pypi-release.json"))
	if err != nil {
		return err
	}
	npmPublicationMode, err := optionalPublicationMode(filepath.Join("artifacts", "registry", "npm-publication-mode.txt"), "npm")
	if err != nil {
		return err
	}
	pypiPublicationMode, err := optionalPublicationMode(filepath.Join("artifacts", "pypi-registry", "pypi-publication-mode.txt"), "pypi")
	if err != nil {
		return err
	}
	if err := requirePublicationMode(npmPublicationMode, "npm", len(registryRecords) > 0); err != nil {
		return err
	}
	if err := requirePublicationMode(pypiPublicationMode, "pypi", pypiRegistry != nil); err != nil {
		return err
	}
	if err := requirePackRecordsMatchPackage(manifest, localRecords, "local npm package evidence"); err != nil {
		return err
	}
	if err := requireRegistryRecordsMatchLocal(registryRecords, localRecords); err != nil {
		return err
	}
	if err := requirePythonPackagesMatchPackage(manifest, pythonPackages, "local Python package evidence"); err != nil {
		return err
	}
	if err := requirePyPIRegistryMatchesLocal(pypiRegistry, pythonPackages, manifest); err != nil {
		return err
	}
	trustedPublishers, err := trustedPublisherSetFromEnv(manifest, npmPublicationMode, pypiPublicationMode, os.Getenv)
	if err != nil {
		return err
	}
	moduleName, err := goModule()
	if err != nil {
		return err
	}
	goVersion, err := commandOutput("go", "version")
	if err != nil {
		return err
	}
	releaseDir := filepath.Join("artifacts", "release")
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "checksums.sha256"), []byte(strings.Join(checksums, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "sbom-subjects.sha256"), []byte(strings.Join(sbomSubjectChecksums, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	release := releaseManifest{
		ArtifactKind:  artifactKind,
		SchemaVersion: schemaVersion,
		Package: packageIdentity{
			Description:    manifest.Description,
			License:        manifest.License,
			Name:           manifest.Name,
			PackageManager: manifest.PackageManager,
			RepositoryURL:  manifest.Repository.URL,
			Version:        manifest.Version,
		},
		Source: sourceIdentity{
			CanonicalKind: "go-source",
			GoModule:      moduleName,
			GitCommit:     os.Getenv("GITHUB_SHA"),
			GitRef:        os.Getenv("GITHUB_REF_NAME"),
		},
		Workflow: workflowIdentity{
			EventName:  os.Getenv("GITHUB_EVENT_NAME"),
			Name:       os.Getenv("GITHUB_WORKFLOW"),
			RunnerOS:   os.Getenv("RUNNER_OS"),
			RunnerArch: os.Getenv("RUNNER_ARCH"),
		},
		Toolchain: toolchainIdentity{
			Go:   goVersion,
			Node: optionalCommandOutput("node", "--version"),
			Npm:  optionalCommandOutput("npm", "--version"),
		},
		Channels:          releaseChannels(localRecords, registryRecords, npmPublicationMode, pythonPackages, pypiRegistry, pypiPublicationMode, assets, trustedPublishers),
		LocalPackEvidence: packageEvidenceSet(localRecords, assetShaByFilename(assets)),
		NonClaims: []string{
			"GitHub Release assets are archive evidence, not package-manager dependency authority.",
			"PyPI distribution is not registry authority until the PyPI channel has its own admitted post-publish evidence.",
			"Native witness execution, consumer adoption, consumer proof freshness, merge policy, and rollout policy remain consumer-owned.",
		},
	}
	installEvidence, err := optionalRegistryInstallEvidence(filepath.Join("artifacts", "registry"))
	if err != nil {
		return err
	}
	release.RegistryInstallEvidence = installEvidence
	if err := writeJSON(filepath.Join(releaseDir, "release-manifest.json"), release); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "release-notes.md"), []byte(releasechange.RenderMarkdown(changeRecord, manifest.Name, pythonPackageName, pypiRegistry != nil)), 0o644); err != nil {
		return err
	}
	metadataChecksums, err := checksumLines([]string{
		filepath.Join(releaseDir, "release-manifest.json"),
		filepath.Join(releaseDir, "release-notes.md"),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(releaseDir, "metadata-checksums.sha256"), []byte(strings.Join(metadataChecksums, "\n")+"\n"), 0o644)
}

func readPackageJSON(path string) (packageJSON, error) {
	manifest, err := readAdmittedJSON[packageJSON](path)
	if err != nil {
		return packageJSON{}, err
	}
	if manifest.Name == "" || manifest.Version == "" || manifest.License == "" || manifest.Repository.URL == "" {
		return packageJSON{}, fmt.Errorf("package.json must include name, version, license, and repository.url")
	}
	return manifest, nil
}

func readPackRecords(path string) ([]packRecord, error) {
	records, err := readAdmittedJSON[[]packRecord](path)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s must contain at least one package record", path)
	}
	for _, record := range records {
		if record.Name == "" || record.Version == "" || record.Filename == "" || record.Integrity == "" || record.Shasum == "" {
			return nil, fmt.Errorf("%s contains incomplete package record", path)
		}
	}
	return records, nil
}

func optionalPackRecords(path string) ([]packRecord, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return readPackRecords(path)
}

func optionalPublicationMode(path string, label string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	mode := strings.TrimSpace(string(content))
	mode, err = trustedpublisher.AdmitPublicationMode(mode, fmt.Sprintf("%s publication mode", label))
	if err != nil {
		return "", err
	}
	return mode, nil
}

func requirePublicationMode(mode string, label string, registryEvidencePresent bool) error {
	if registryEvidencePresent && mode == "" {
		return fmt.Errorf("%s publication mode is required when registry evidence exists", label)
	}
	if !registryEvidencePresent && mode != "" {
		return fmt.Errorf("%s publication mode requires registry evidence", label)
	}
	return nil
}

func trustedPublisherSetFromEnv(manifest packageJSON, npmPublicationMode string, pypiPublicationMode string, getenv func(string) string) (trustedPublisherSet, error) {
	repository, err := trustedpublisher.RepositorySlugFromGitHubURL(manifest.Repository.URL)
	if err != nil {
		return trustedPublisherSet{}, err
	}
	out := trustedPublisherSet{}
	npmRequiresIdentity, err := publicationModeRequiresIdentity(npmPublicationMode, "npm")
	if err != nil {
		return trustedPublisherSet{}, err
	}
	if npmRequiresIdentity {
		identity, err := releasepublisher.FromEnvForAuthorityChannel(string(releasechannel.RegistryRelease), manifest.Name, manifest.Version, repository, getenv)
		if err != nil {
			return trustedPublisherSet{}, err
		}
		out.NPM = &identity
	}
	pypiRequiresIdentity, err := publicationModeRequiresIdentity(pypiPublicationMode, "pypi")
	if err != nil {
		return trustedPublisherSet{}, err
	}
	if pypiRequiresIdentity {
		identity, err := releasepublisher.FromEnvForAuthorityChannel(string(releasechannel.PyPIRegistryRelease), pythonPackageName, manifest.Version, repository, getenv)
		if err != nil {
			return trustedPublisherSet{}, err
		}
		out.PyPI = &identity
	}
	return out, nil
}

func publicationModeRequiresIdentity(mode string, label string) (bool, error) {
	if mode == "" {
		return false, nil
	}
	return trustedpublisher.PublicationModeRequiresIdentity(mode, fmt.Sprintf("%s publication mode", label))
}

func requirePackRecordsMatchPackage(manifest packageJSON, records []packRecord, label string) error {
	for _, record := range records {
		if record.Name != manifest.Name || record.Version != manifest.Version {
			return fmt.Errorf("%s record %s must match package.json identity %s@%s", label, record.Filename, manifest.Name, manifest.Version)
		}
	}
	return nil
}

func requireRegistryRecordsMatchLocal(registryRecords []packRecord, localRecords []packRecord) error {
	if len(registryRecords) == 0 {
		return nil
	}
	if len(registryRecords) != len(localRecords) {
		return fmt.Errorf("npm registry evidence package count must match local package evidence")
	}
	localByFilename := map[string]packRecord{}
	for _, record := range localRecords {
		localByFilename[record.Filename] = record
	}
	for _, registryRecord := range registryRecords {
		localRecord, ok := localByFilename[registryRecord.Filename]
		if !ok {
			return fmt.Errorf("npm registry evidence contains package %s absent from local package evidence", registryRecord.Filename)
		}
		if registryRecord.Name != localRecord.Name ||
			registryRecord.Version != localRecord.Version ||
			registryRecord.Integrity != localRecord.Integrity ||
			registryRecord.Shasum != localRecord.Shasum {
			return fmt.Errorf("npm registry evidence for %s does not match local package identity and bytes", registryRecord.Filename)
		}
	}
	return nil
}

func optionalPythonPackageSet(path string) (*pythonPackageSet, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out, err := readAdmittedJSON[pythonPackageSet](path)
	if err != nil {
		return nil, err
	}
	if out.ArtifactKind != "proofkit.python-package-set.v1" || out.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s has unexpected artifact kind or schema version", path)
	}
	if out.PackageName == "" || out.PackageVersion == "" || len(out.Packages) == 0 {
		return nil, fmt.Errorf("%s must include package identity and packages", path)
	}
	sort.Slice(out.Packages, func(left int, right int) bool {
		return out.Packages[left].Filename < out.Packages[right].Filename
	})
	return &out, nil
}

func requirePythonPackagesMatchPackage(manifest packageJSON, packageSet *pythonPackageSet, label string) error {
	if packageSet == nil {
		return nil
	}
	if packageSet.PackageName != pythonPackageName || packageSet.PackageVersion != manifest.Version {
		return fmt.Errorf("%s must match Python package identity %s@%s", label, pythonPackageName, manifest.Version)
	}
	for _, record := range packageSet.Packages {
		if record.Name != pythonPackageName || record.Version != manifest.Version {
			return fmt.Errorf("%s wheel %s must match Python package identity %s@%s", label, record.Filename, pythonPackageName, manifest.Version)
		}
	}
	return nil
}

func optionalPyPIRegistrySet(path string) (*pypiRegistrySet, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out, err := readAdmittedJSON[pypiRegistrySet](path)
	if err != nil {
		return nil, err
	}
	if out.ArtifactKind != "proofkit.pypi-registry-artifact-set.v1" || out.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s has unexpected artifact kind or schema version", path)
	}
	if out.Registry == "" || out.PackageName == "" || out.PackageVersion == "" || len(out.Packages) == 0 {
		return nil, fmt.Errorf("%s must include registry, package identity, and packages", path)
	}
	definition := releasechannel.Must(releasechannel.PyPIRegistryRelease)
	if out.AuthorityChannel != string(definition.ID) || out.AuthorityValidator != definition.AuthorityValidator {
		return nil, fmt.Errorf("%s must carry canonical %s authority metadata", path, definition.ID)
	}
	if out.Registry != definition.RegistryURL {
		return nil, fmt.Errorf("%s must carry canonical %s registry URL", path, definition.ID)
	}
	if out.Source != releasechannel.PyPIRegistryEvidenceSource {
		return nil, fmt.Errorf("%s must carry %s source", path, releasechannel.PyPIRegistryEvidenceSource)
	}
	for _, record := range out.Packages {
		if err := validatePyPIRegistryPackageEvidence(path, record); err != nil {
			return nil, err
		}
	}
	sort.Slice(out.Packages, func(left int, right int) bool {
		return out.Packages[left].Filename < out.Packages[right].Filename
	})
	return &out, nil
}

func validatePyPIRegistryPackageEvidence(path string, record pythonWheelRecord) error {
	if record.Filename == "" ||
		record.Name == "" ||
		record.Version == "" ||
		record.PackageType == "" ||
		record.PythonTag == "" ||
		record.AbiTag == "" ||
		record.PlatformTag == "" ||
		record.PlatformSuffix == "" ||
		record.WheelTag == "" ||
		record.Sha256 == "" ||
		record.BinarySha256 == "" ||
		record.URL == "" {
		return fmt.Errorf("%s packages must carry complete post-publish PyPI wheel evidence", path)
	}
	if record.PackageType != "bdist_wheel" {
		return fmt.Errorf("%s package %s must be a PyPI wheel", path, record.Filename)
	}
	return nil
}

func requirePyPIRegistryMatchesLocal(registry *pypiRegistrySet, local *pythonPackageSet, manifest packageJSON) error {
	if registry == nil {
		return nil
	}
	if local == nil {
		return fmt.Errorf("PyPI registry evidence requires local Python package evidence")
	}
	if registry.PackageName != pythonPackageName || registry.PackageVersion != manifest.Version {
		return fmt.Errorf("PyPI registry evidence must match Python package identity %s@%s", pythonPackageName, manifest.Version)
	}
	if len(registry.Packages) != len(local.Packages) {
		return fmt.Errorf("PyPI registry evidence package count must match local Python package evidence")
	}
	localByFilename := map[string]pythonWheelRecord{}
	for _, record := range local.Packages {
		localByFilename[record.Filename] = record
	}
	for _, registryRecord := range registry.Packages {
		localRecord, ok := localByFilename[registryRecord.Filename]
		if !ok {
			return fmt.Errorf("PyPI registry evidence contains wheel %s absent from local Python package evidence", registryRecord.Filename)
		}
		if registryRecord.Name != localRecord.Name ||
			registryRecord.Version != localRecord.Version ||
			registryRecord.Sha256 != localRecord.Sha256 ||
			registryRecord.BinarySha256 != localRecord.BinarySha256 ||
			registryRecord.PythonTag != localRecord.PythonTag ||
			registryRecord.AbiTag != localRecord.AbiTag ||
			registryRecord.PlatformTag != localRecord.PlatformTag ||
			registryRecord.PlatformSuffix != localRecord.PlatformSuffix ||
			registryRecord.WheelTag != localRecord.WheelTag {
			return fmt.Errorf("PyPI registry evidence for %s does not match local wheel identity and bytes", registryRecord.Filename)
		}
	}
	return nil
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

func sortPackRecords(records []packRecord) {
	sort.Slice(records, func(left int, right int) bool {
		if records[left].Name == records[right].Name {
			return records[left].Filename < records[right].Filename
		}
		return records[left].Name < records[right].Name
	})
}

func releaseAssets(localRecords []packRecord, pythonPackages *pythonPackageSet) ([]assetEvidence, []string, []string, error) {
	paths := expectedPackageArtifactPaths(localRecords, pythonPackages)
	if len(paths) == 0 {
		return nil, nil, nil, fmt.Errorf("release assets require at least one package artifact")
	}
	packagePaths, err := optionalGlob(filepath.Join("artifacts", "package", "*.tgz"))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := requireExactPathSet(packagePaths, expectedPackageArtifactPaths(localRecords, nil), "release package artifact"); err != nil {
		return nil, nil, nil, err
	}
	pythonWheelPaths, err := optionalGlob(filepath.Join("artifacts", "pypi", "*.whl"))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := requireExactPathSet(pythonWheelPaths, expectedPythonWheelPaths(pythonPackages), "release Python wheel artifact"); err != nil {
		return nil, nil, nil, err
	}
	sbomSubjectPaths := append([]string{}, paths...)
	paths = append(paths, filepath.Join("artifacts", "release", "sbom.cdx.json"))
	sort.Strings(paths)
	sort.Strings(sbomSubjectPaths)
	assets := make([]assetEvidence, 0, len(paths))
	checksums := make([]string, 0, len(paths))
	sbomSubjectChecksums := make([]string, 0, len(sbomSubjectPaths))
	for _, path := range paths {
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, nil, nil, err
		}
		filename := filepath.Base(path)
		assets = append(assets, assetEvidence{Filename: filename, Sha256: sum})
		checksums = append(checksums, fmt.Sprintf("%s  %s", sum, filename))
	}
	for _, path := range sbomSubjectPaths {
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, nil, nil, err
		}
		sbomSubjectChecksums = append(sbomSubjectChecksums, fmt.Sprintf("%s  %s", sum, filepath.Base(path)))
	}
	return assets, checksums, sbomSubjectChecksums, nil
}

func checksumLines(paths []string) ([]string, error) {
	sort.Strings(paths)
	lines := make([]string, 0, len(paths))
	for _, path := range paths {
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fmt.Sprintf("%s  %s", sum, filepath.Base(path)))
	}
	return lines, nil
}

func optionalGlob(pattern string) ([]string, error) {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func expectedPackageArtifactPaths(localRecords []packRecord, pythonPackages *pythonPackageSet) []string {
	paths := make([]string, 0, len(localRecords))
	for _, record := range localRecords {
		paths = append(paths, filepath.Join("artifacts", "package", record.Filename))
	}
	paths = append(paths, expectedPythonWheelPaths(pythonPackages)...)
	sort.Strings(paths)
	return paths
}

func expectedPythonWheelPaths(pythonPackages *pythonPackageSet) []string {
	if pythonPackages == nil {
		return nil
	}
	paths := make([]string, 0, len(pythonPackages.Packages))
	for _, record := range pythonPackages.Packages {
		paths = append(paths, filepath.Join("artifacts", "pypi", record.Filename))
	}
	sort.Strings(paths)
	return paths
}

func requireExactPathSet(actual []string, expected []string, context string) error {
	sort.Strings(actual)
	sort.Strings(expected)
	actualSet := stringSet(actual)
	expectedSet := stringSet(expected)
	missing := []string{}
	for _, path := range expected {
		if _, ok := actualSet[path]; !ok {
			missing = append(missing, path)
		}
	}
	unexpected := []string{}
	for _, path := range actual {
		if _, ok := expectedSet[path]; !ok {
			unexpected = append(unexpected, path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s missing expected file(s): %s", context, strings.Join(missing, ", "))
	}
	if len(unexpected) > 0 {
		return fmt.Errorf("%s has unexpected file(s): %s", context, strings.Join(unexpected, ", "))
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func assetShaByFilename(assets []assetEvidence) map[string]string {
	out := make(map[string]string, len(assets))
	for _, asset := range assets {
		out[asset.Filename] = asset.Sha256
	}
	return out
}

func packageEvidenceSet(records []packRecord, shaByFilename map[string]string) []packageEvidence {
	out := make([]packageEvidence, 0, len(records))
	for _, record := range records {
		out = append(out, packageEvidence{
			Filename:  record.Filename,
			Integrity: record.Integrity,
			Name:      record.Name,
			Shasum:    record.Shasum,
			Sha256:    shaByFilename[record.Filename],
			Version:   record.Version,
		})
	}
	return out
}

func releaseChannels(localRecords []packRecord, registryRecords []packRecord, npmPublicationMode string, pythonPackages *pythonPackageSet, pypiRegistry *pypiRegistrySet, pypiPublicationMode string, assets []assetEvidence, trustedPublishers trustedPublisherSet) []channelEvidence {
	npmStatus := "candidate"
	npmPackages := packageEvidenceSet(localRecords, assetShaByFilename(assets))
	npmNonClaims := []string{
		"Local npm package artifacts are candidate tarball evidence; they do not prove npm registry publication, registry install authority, or consumer adoption.",
	}
	if len(registryRecords) > 0 {
		npmStatus = "published"
		npmPackages = packageEvidenceSet(registryRecords, nil)
		npmNonClaims = []string{
			"npm registry identity does not prove consumer installation, consumer adoption, or rollout.",
		}
		npmRequiresIdentity, _ := publicationModeRequiresIdentity(npmPublicationMode, "npm")
		if !npmRequiresIdentity {
			npmNonClaims = append(npmNonClaims, "npm registry identity proves byte availability, not publisher provenance for this workflow run.")
		}
	}
	pypiChannel := channelBase(releasechannel.PyPIRegistryRelease)
	pypiChannel.Status = "planned"
	pypiChannel.NonClaims = []string{
		"PyPI is not a dependency authority for this version until PyPI package evidence exists.",
	}
	pythonCandidateChannel := channelBase(releasechannel.PythonWheelCandidate)
	pythonCandidateChannel.Status = "not_applicable"
	pythonCandidateChannel.NonClaims = []string{
		"Python wheel candidate channel is absent until local wheel artifacts exist.",
	}
	if pythonPackages != nil {
		pythonCandidateChannel.Status = "candidate"
		pythonCandidateChannel.Packages = pythonPackageEvidenceSet(pythonPackages.Packages)
		pythonCandidateChannel.NonClaims = []string{
			"Python wheels are candidate artifacts until published through an admitted registry release workflow.",
		}
	}
	if pypiRegistry != nil {
		pypiChannel.Status = "published"
		pypiChannel.Registry = pypiRegistry.Registry
		pypiChannel.Packages = pythonPackageEvidenceSet(pypiRegistry.Packages)
		pypiChannel.PublicationMode = pypiPublicationMode
		pypiChannel.PublisherEnvironment = publisherEnvironmentForMode(pypiPublicationMode, "github-actions:environment:pypi")
		pypiChannel.TrustedPublisher = trustedPublisherWhenPublished(pypiChannel.Status, pypiPublicationMode, trustedPublishers.PyPI)
		pypiChannel.NonClaims = []string{
			"PyPI registry identity does not prove consumer installation or consumer rollout.",
		}
		pypiRequiresIdentity, _ := publicationModeRequiresIdentity(pypiPublicationMode, "pypi")
		if !pypiRequiresIdentity {
			pypiChannel.NonClaims = append(pypiChannel.NonClaims, "PyPI registry identity proves byte availability, not publisher provenance for this workflow run.")
		}
	}
	npmChannel := channelBase(releasechannel.RegistryRelease)
	npmChannel.PublicationMode = publicationModeWhenPublished(npmStatus, npmPublicationMode)
	npmChannel.PublisherEnvironment = publisherEnvironmentWhenPublished(npmStatus, npmPublicationMode, "github-actions:environment:npm-production")
	npmChannel.TrustedPublisher = trustedPublisherWhenPublished(npmStatus, npmPublicationMode, trustedPublishers.NPM)
	npmChannel.Status = npmStatus
	npmChannel.Packages = npmPackages
	npmChannel.NonClaims = npmNonClaims
	githubArchiveChannel := channelBase(releasechannel.GitHubReleaseArchive)
	githubArchiveChannel.PublisherEnvironment = "github-actions:contents-write"
	githubArchiveChannel.Status = "candidate"
	githubArchiveChannel.Assets = assets
	githubArchiveChannel.NonClaims = []string{
		"GitHub Release assets are not a package-manager install channel for consumers.",
		"GitHub Release publication facts are owned by post-create github-release.json evidence, not by this candidate manifest.",
	}
	return []channelEvidence{
		npmChannel,
		pythonCandidateChannel,
		pypiChannel,
		githubArchiveChannel,
	}
}

func channelBase(id releasechannel.ID) channelEvidence {
	definition := releasechannel.Must(id)
	return channelEvidence{
		AuthorityChannel:   string(definition.ID),
		AuthorityValidator: definition.AuthorityValidator,
		Kind:               definition.Kind,
		Registry:           definition.RegistryURL,
		Role:               definition.Role,
	}
}

func publicationModeWhenPublished(status string, mode string) string {
	if status != "published" {
		return ""
	}
	return mode
}

func publisherEnvironmentForMode(mode string, environment string) string {
	requiresIdentity, err := publicationModeRequiresIdentity(mode, "release channel")
	if err != nil || !requiresIdentity {
		return ""
	}
	return environment
}

func publisherEnvironmentWhenPublished(status string, mode string, environment string) string {
	if status != "published" {
		return ""
	}
	return publisherEnvironmentForMode(mode, environment)
}

func trustedPublisherWhenPublished(status string, mode string, identity *trustedpublisher.Identity) *trustedpublisher.Identity {
	requiresIdentity, err := publicationModeRequiresIdentity(mode, "release channel")
	if status != "published" || err != nil || !requiresIdentity {
		return nil
	}
	return identity
}

func pythonPackageEvidenceSet(records []pythonWheelRecord) []packageEvidence {
	out := make([]packageEvidence, 0, len(records))
	for _, record := range records {
		out = append(out, packageEvidence{
			AbiTag:         record.AbiTag,
			BinarySha256:   record.BinarySha256,
			Filename:       record.Filename,
			Name:           record.Name,
			PackageType:    record.PackageType,
			PlatformSuffix: record.PlatformSuffix,
			PlatformTag:    record.PlatformTag,
			PythonTag:      record.PythonTag,
			Sha256:         record.Sha256,
			URL:            record.URL,
			Version:        record.Version,
			WheelTag:       record.WheelTag,
		})
	}
	return out
}

func optionalRegistryInstallEvidence(dir string) (*registryInstallEvidence, error) {
	var packageLock, helpOutput, auditSignatures, artifactSet, adapterSourceReport, successReport, failedReport string
	paths := []struct {
		path   string
		target *string
	}{
		{path: filepath.Join(dir, "audit-signatures.txt"), target: &auditSignatures},
		{path: filepath.Join(dir, "published-registry-artifact-set.json"), target: &artifactSet},
		{path: filepath.Join(dir, "root-install-help.txt"), target: &helpOutput},
		{path: filepath.Join(dir, "root-install-json-adapter-source.json"), target: &adapterSourceReport},
		{path: filepath.Join(dir, "root-install-json-failed.json"), target: &failedReport},
		{path: filepath.Join(dir, "root-install-json-success.json"), target: &successReport},
		{path: filepath.Join(dir, "root-install-package-lock.json"), target: &packageLock},
	}
	missing := []string{}
	found := 0
	for _, item := range paths {
		path := item.path
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, filepath.Base(path))
				continue
			}
			return nil, err
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		*item.target = sum
		found++
	}
	if found == 0 {
		return nil, nil
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("registry install evidence is partial; missing file(s): %s", strings.Join(missing, ", "))
	}
	return &registryInstallEvidence{
		Kind:                       "root-only-npm-install",
		AuditSignaturesSha256:      auditSignatures,
		AdapterSourceReportSha256:  adapterSourceReport,
		FailedReportSha256:         failedReport,
		HelpOutputSha256:           helpOutput,
		PackageLockSha256:          packageLock,
		PublishedArtifactSetSha256: artifactSet,
		SuccessReportSha256:        successReport,
	}, nil
}

func writeJSON(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o644)
}

func goModule() (string, error) {
	content, err := os.ReadFile("go.mod")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			moduleName := strings.TrimSpace(strings.TrimPrefix(line, "module "))
			if moduleName == "" {
				return "", fmt.Errorf("go.mod module declaration is empty")
			}
			return moduleName, nil
		}
	}
	return "", fmt.Errorf("go.mod module declaration is required")
}

func commandOutput(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(output)), nil
}

func optionalCommandOutput(name string, args ...string) string {
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
