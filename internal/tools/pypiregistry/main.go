package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

const (
	artifactKind  = "proofkit.pypi-registry-artifact-set.v1"
	packageName   = "agentic-proofkit"
	packageKind   = "proofkit.python-package-set.v1"
	pypiRegistry  = releasechannel.PyPIRegistryURL
	schemaVersion = 1

	pypiRegistryAttemptLimit = 24
	pypiRegistryRetryDelay   = 10 * time.Second
)

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type pythonPackageSet struct {
	ArtifactKind   string        `json:"artifactKind"`
	PackageName    string        `json:"packageName"`
	PackageVersion string        `json:"packageVersion"`
	Packages       []wheelRecord `json:"packages"`
	SchemaVersion  int           `json:"schemaVersion"`
}

type wheelRecord struct {
	AbiTag         string `json:"abiTag"`
	BinarySha256   string `json:"binarySha256"`
	Filename       string `json:"filename"`
	Name           string `json:"name"`
	PlatformSuffix string `json:"platformSuffix"`
	PlatformTag    string `json:"platformTag"`
	PythonTag      string `json:"pythonTag"`
	Sha256         string `json:"sha256"`
	Version        string `json:"version"`
	WheelTag       string `json:"wheelTag"`
}

type pypiResponse struct {
	Info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"info"`
	URLs []pypiFile `json:"urls"`
}

type pypiFile struct {
	Digests struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
	Filename      string `json:"filename"`
	PackageType   string `json:"packagetype"`
	PythonVersion string `json:"python_version"`
	URL           string `json:"url"`
	Yanked        bool   `json:"yanked"`
}

type pypiHTTPStatusError struct {
	StatusCode int
	Status     string
	Body       string
}

func (err pypiHTTPStatusError) Error() string {
	return fmt.Sprintf("pypi returned %s: %s", err.Status, err.Body)
}

type registryArtifactSet struct {
	ArtifactKind       string                  `json:"artifactKind"`
	AuthorityChannel   string                  `json:"authorityChannel"`
	AuthorityValidator string                  `json:"authorityValidator"`
	SchemaVersion      int                     `json:"schemaVersion"`
	Registry           string                  `json:"registry"`
	Source             string                  `json:"source"`
	PackageName        string                  `json:"packageName"`
	PackageVersion     string                  `json:"packageVersion"`
	Packages           []registryWheelEvidence `json:"packages"`
	NonClaims          []string                `json:"nonClaims"`
}

type registryWheelEvidence struct {
	AbiTag         string `json:"abiTag"`
	BinarySha256   string `json:"binarySha256"`
	Filename       string `json:"filename"`
	Name           string `json:"name"`
	PackageType    string `json:"packageType"`
	PlatformSuffix string `json:"platformSuffix"`
	PlatformTag    string `json:"platformTag"`
	PythonTag      string `json:"pythonTag"`
	Sha256         string `json:"sha256"`
	URL            string `json:"url"`
	Version        string `json:"version"`
	WheelTag       string `json:"wheelTag"`
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
	candidates, err := readPythonPackageSet(filepath.Join("artifacts", "pypi", "python-packages.json"))
	if err != nil {
		return err
	}
	if candidates.PackageName != packageName || candidates.PackageVersion != manifest.Version {
		return fmt.Errorf("python package candidates do not match package.json identity")
	}
	if err := requireCandidatePlatformCompleteness(candidates.Packages); err != nil {
		return err
	}
	evidence, err := fetchPyPIRegistryEvidence(candidates, packageName, manifest.Version, pypiRegistryAttemptLimit, pypiRegistryRetryDelay, fetchPyPIRelease)
	if err != nil {
		return err
	}
	output := registryArtifactOutput(manifest.Version, evidence)
	if err := os.MkdirAll(filepath.Join("artifacts", "pypi-registry"), 0o755); err != nil {
		return err
	}
	return writeJSON(filepath.Join("artifacts", "pypi-registry", "pypi-release.json"), output)
}

func registryArtifactOutput(version string, evidence []registryWheelEvidence) registryArtifactSet {
	channel := releasechannel.Must(releasechannel.PyPIRegistryRelease)
	return registryArtifactSet{
		ArtifactKind:       artifactKind,
		AuthorityChannel:   string(channel.ID),
		AuthorityValidator: channel.AuthorityValidator,
		SchemaVersion:      schemaVersion,
		Registry:           pypiRegistry,
		Source:             releasechannel.PyPIRegistryEvidenceSource,
		PackageName:        packageName,
		PackageVersion:     version,
		Packages:           evidence,
		NonClaims: []string{
			"pypi registry identity does not prove consumer installation, consumer rollout, or native execution in every consumer environment.",
			"pypi registry identity does not replace the candidate wheel RECORD and local install smoke proof.",
		},
	}
}

func readPackageJSON(path string) (packageJSON, error) {
	out, err := readAdmittedJSON[packageJSON](path)
	if err != nil {
		return packageJSON{}, err
	}
	if out.Name == "" || out.Version == "" {
		return packageJSON{}, fmt.Errorf("%s must include package name and version", path)
	}
	return out, nil
}

func readPythonPackageSet(path string) (pythonPackageSet, error) {
	out, err := readAdmittedJSON[pythonPackageSet](path)
	if err != nil {
		return pythonPackageSet{}, err
	}
	if out.ArtifactKind != packageKind || out.SchemaVersion != schemaVersion {
		return pythonPackageSet{}, fmt.Errorf("%s has unexpected artifact kind or schema version", path)
	}
	if out.PackageName == "" || out.PackageVersion == "" || len(out.Packages) == 0 {
		return pythonPackageSet{}, fmt.Errorf("%s must include package identity and wheels", path)
	}
	return out, nil
}

func fetchPyPIRegistryEvidence(candidates pythonPackageSet, name string, version string, attempts int, delay time.Duration, fetch func(string, string) (pypiResponse, error)) ([]registryWheelEvidence, error) {
	if attempts < 1 {
		return nil, fmt.Errorf("pypi registry evidence fetch requires at least one attempt")
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		registry, err := fetch(name, version)
		if err == nil {
			evidence, err := compareRegistryFiles(candidates, registry)
			if err == nil {
				return evidence, nil
			}
			if !retryableRegistryEvidenceError(err) {
				return nil, err
			}
			lastErr = err
		} else {
			if !retryablePyPIFetchError(err) {
				return nil, err
			}
			lastErr = err
		}
		if attempt < attempts {
			time.Sleep(delay)
		}
	}
	return nil, fmt.Errorf("fetch complete pypi registry evidence %s@%s: %w", name, version, lastErr)
}

func fetchPyPIRelease(name string, version string) (pypiResponse, error) {
	url := fmt.Sprintf("%s/pypi/%s/%s/json", pypiRegistry, name, version)
	client := http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return pypiResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		return pypiResponse{}, pypiHTTPStatusError{
			StatusCode: response.StatusCode,
			Status:     response.Status,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		return pypiResponse{}, err
	}
	out, err := admission.DecodeTypedJSON[pypiResponse](bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return pypiResponse{}, err
	}
	return out, nil
}

func retryablePyPIFetchError(err error) bool {
	var statusErr pypiHTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == http.StatusNotFound || statusErr.StatusCode >= http.StatusInternalServerError
	}
	return true
}

func retryableRegistryEvidenceError(err error) bool {
	return strings.Contains(err.Error(), "pypi release is missing wheel")
}

func requireCandidatePlatformCompleteness(records []wheelRecord) error {
	bySuffix := map[string]wheelRecord{}
	for _, record := range records {
		if err := validateCandidateWheel(record); err != nil {
			return err
		}
		if _, exists := bySuffix[record.PlatformSuffix]; exists {
			return fmt.Errorf("candidate package set contains duplicate platform suffix %s", record.PlatformSuffix)
		}
		bySuffix[record.PlatformSuffix] = record
	}
	for _, target := range releaseplatform.Targets() {
		record, ok := bySuffix[target.PlatformSuffix]
		if !ok {
			return fmt.Errorf("candidate package set is missing wheel for release platform %s", target.PlatformSuffix)
		}
		if record.PlatformTag != target.PlatformTag || record.WheelTag != target.WheelTag {
			return fmt.Errorf("candidate package set wheel metadata for %s does not match release platform owner", target.PlatformSuffix)
		}
		delete(bySuffix, target.PlatformSuffix)
	}
	if len(bySuffix) > 0 {
		extra := make([]string, 0, len(bySuffix))
		for suffix := range bySuffix {
			extra = append(extra, suffix)
		}
		sort.Strings(extra)
		return fmt.Errorf("candidate package set contains unmanaged release platform suffixes: %s", strings.Join(extra, ", "))
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

func compareRegistryFiles(candidates pythonPackageSet, registry pypiResponse) ([]registryWheelEvidence, error) {
	if registry.Info.Name == "" || registry.Info.Version == "" {
		return nil, fmt.Errorf("pypi response must include release identity")
	}
	if !strings.EqualFold(registry.Info.Name, candidates.PackageName) || registry.Info.Version != candidates.PackageVersion {
		return nil, fmt.Errorf("pypi release identity mismatch")
	}
	filesByName := make(map[string]pypiFile, len(registry.URLs))
	for _, file := range registry.URLs {
		if _, exists := filesByName[file.Filename]; exists {
			return nil, fmt.Errorf("pypi response contains duplicate filename %s", file.Filename)
		}
		filesByName[file.Filename] = file
	}
	expectedFiles := make(map[string]struct{}, len(candidates.Packages))
	for _, candidate := range candidates.Packages {
		if err := validateCandidateWheel(candidate); err != nil {
			return nil, err
		}
		if _, exists := expectedFiles[candidate.Filename]; exists {
			return nil, fmt.Errorf("candidate package set contains duplicate filename %s", candidate.Filename)
		}
		expectedFiles[candidate.Filename] = struct{}{}
	}
	for filename := range filesByName {
		if _, ok := expectedFiles[filename]; !ok {
			return nil, fmt.Errorf("pypi release contains unexpected file %s", filename)
		}
	}
	out := make([]registryWheelEvidence, 0, len(candidates.Packages))
	for _, candidate := range candidates.Packages {
		file, ok := filesByName[candidate.Filename]
		if !ok {
			return nil, fmt.Errorf("pypi release is missing wheel %s", candidate.Filename)
		}
		if file.PackageType != "bdist_wheel" {
			return nil, fmt.Errorf("pypi file %s has package type %s", file.Filename, file.PackageType)
		}
		if file.Yanked {
			return nil, fmt.Errorf("pypi file %s is yanked", file.Filename)
		}
		if file.PythonVersion != candidate.PythonTag {
			return nil, fmt.Errorf("pypi file %s python tag mismatch: %s", file.Filename, file.PythonVersion)
		}
		if file.Digests.SHA256 != candidate.Sha256 {
			return nil, fmt.Errorf("pypi file %s sha256 mismatch", file.Filename)
		}
		out = append(out, registryWheelEvidence{
			AbiTag:         candidate.AbiTag,
			BinarySha256:   candidate.BinarySha256,
			Filename:       candidate.Filename,
			Name:           candidate.Name,
			PackageType:    file.PackageType,
			PlatformSuffix: candidate.PlatformSuffix,
			PlatformTag:    candidate.PlatformTag,
			PythonTag:      candidate.PythonTag,
			Sha256:         candidate.Sha256,
			URL:            file.URL,
			Version:        candidate.Version,
			WheelTag:       candidate.WheelTag,
		})
	}
	sort.Slice(out, func(left int, right int) bool {
		return out[left].Filename < out[right].Filename
	})
	return out, nil
}

func validateCandidateWheel(record wheelRecord) error {
	if record.Filename == "" ||
		record.Name == "" ||
		record.Version == "" ||
		record.PythonTag == "" ||
		record.AbiTag == "" ||
		record.PlatformTag == "" ||
		record.PlatformSuffix == "" ||
		record.WheelTag == "" ||
		record.Sha256 == "" ||
		record.BinarySha256 == "" {
		return fmt.Errorf("candidate package set contains incomplete wheel evidence")
	}
	return nil
}

func writeJSON(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o644)
}
