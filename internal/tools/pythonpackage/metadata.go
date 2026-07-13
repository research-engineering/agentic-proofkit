package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

var pep440VersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+(?:a[0-9]+|b[0-9]+|rc[0-9]+|\.post[0-9]+|\.dev[0-9]+)?$`)

const (
	artifactKind      = "proofkit.python-package-set.v1"
	npmPackageName    = "@research-engineering/agentic-proofkit"
	packageName       = "agentic-proofkit"
	licenseExpression = "MIT"
	pythonTag         = "py3"
	abiTag            = "none"
	licenseFilename   = "LICENSE"
	schemaVersion     = 1
)

type target = releaseplatform.Target

func releaseTargets() []target {
	return releaseplatform.Targets()
}

type packageJSON struct {
	Description string         `json:"description"`
	License     string         `json:"license"`
	Name        string         `json:"name"`
	Repository  repositoryJSON `json:"repository"`
	Version     string         `json:"version"`
}

type repositoryJSON struct {
	URL string `json:"url"`
}

type packageSet struct {
	ArtifactKind   string        `json:"artifactKind"`
	SchemaVersion  int           `json:"schemaVersion"`
	PackageName    string        `json:"packageName"`
	PackageVersion string        `json:"packageVersion"`
	Packages       []wheelRecord `json:"packages"`
	NonClaims      []string      `json:"nonClaims"`
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

func readPackageJSON() (packageJSON, error) {
	manifest, err := readAdmittedJSON[packageJSON]("package.json")
	if err != nil {
		return packageJSON{}, err
	}
	if manifest.Name != npmPackageName {
		return packageJSON{}, fmt.Errorf("package.json name must be %s, got %s", npmPackageName, manifest.Name)
	}
	if err := requireMetadataField("version", manifest.Version); err != nil {
		return packageJSON{}, err
	}
	if !pep440VersionPattern.MatchString(manifest.Version) {
		return packageJSON{}, fmt.Errorf("package.json version must be a PEP 440-compatible wheel version without filename-unsafe separators")
	}
	if err := requireMetadataField("description", manifest.Description); err != nil {
		return packageJSON{}, err
	}
	if err := requireMetadataField("license", manifest.License); err != nil {
		return packageJSON{}, err
	}
	if manifest.License != licenseExpression {
		return packageJSON{}, fmt.Errorf("package.json license must be %s", licenseExpression)
	}
	if err := requireMetadataField("repository.url", manifest.Repository.URL); err != nil {
		return packageJSON{}, err
	}
	return manifest, nil
}

func requireMetadataField(label string, value string) error {
	if value == "" {
		return fmt.Errorf("package.json must include %s", label)
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("package.json %s must be a single-line metadata field without surrounding whitespace", label)
	}
	return nil
}

func readLicenseFile() ([]byte, error) {
	content, err := os.ReadFile(licenseFilename)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", licenseFilename, err)
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("%s must not be empty", licenseFilename)
	}
	return content, nil
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

func distInfoDir(version string) string {
	return "agentic_proofkit-" + version + ".dist-info"
}

func wheelFilename(version string, target target) string {
	return "agentic_proofkit-" + version + "-" + target.WheelTag + ".whl"
}

func currentTarget() (target, error) {
	return releaseplatform.CurrentTarget()
}
