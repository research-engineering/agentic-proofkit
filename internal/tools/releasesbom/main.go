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
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

const (
	bomFormat     = "CycloneDX"
	specVersion   = "1.6"
	sbomPath      = "artifacts/release/sbom.cdx.json"
	toolName      = "agentic-proofkit"
	toolComponent = "pkg:generic/agentic-proofkit"
)

type packageJSON struct {
	License    string         `json:"license"`
	Name       string         `json:"name"`
	Repository repositoryJSON `json:"repository"`
	Version    string         `json:"version"`
}

type repositoryJSON struct {
	URL string `json:"url"`
}

type goModuleRecord struct {
	Path    string          `json:"Path"`
	Version string          `json:"Version"`
	Replace *goModuleRecord `json:"Replace"`
	Main    bool            `json:"Main"`
}

type cyclonedxBOM struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Version      int                   `json:"version"`
	Metadata     cyclonedxMetadata     `json:"metadata"`
	Components   []cyclonedxComponent  `json:"components"`
	Dependencies []cyclonedxDependency `json:"dependencies"`
}

type cyclonedxMetadata struct {
	Component cyclonedxComponent `json:"component"`
	Tools     []cyclonedxTool    `json:"tools"`
}

type cyclonedxTool struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type cyclonedxComponent struct {
	Type       string              `json:"type"`
	BOMRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	PackageURL string              `json:"purl,omitempty"`
	Hashes     []cyclonedxHash     `json:"hashes,omitempty"`
	Licenses   []cyclonedxLicense  `json:"licenses,omitempty"`
	Properties []cyclonedxProperty `json:"properties,omitempty"`
}

type cyclonedxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cyclonedxLicense struct {
	License cyclonedxLicenseID `json:"license"`
}

type cyclonedxLicenseID struct {
	ID string `json:"id"`
}

type cyclonedxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cyclonedxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
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
	components, err := components(manifest)
	if err != nil {
		return err
	}
	sort.Slice(components, func(left int, right int) bool {
		return components[left].BOMRef < components[right].BOMRef
	})
	dependencies := []cyclonedxDependency{{
		Ref:       rootRef(manifest),
		DependsOn: componentRefs(components, rootRef(manifest)),
	}}
	out := cyclonedxBOM{
		BOMFormat:   bomFormat,
		SpecVersion: specVersion,
		Version:     1,
		Metadata: cyclonedxMetadata{
			Component: rootComponent(manifest),
			Tools: []cyclonedxTool{{
				Name:    toolName,
				Vendor:  "agentic-proofkit",
				Version: manifest.Version,
			}},
		},
		Components:   components,
		Dependencies: dependencies,
	}
	if err := os.MkdirAll(filepath.Dir(sbomPath), 0o755); err != nil {
		return err
	}
	content, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(sbomPath, append(content, '\n'), 0o644)
}

func readPackageJSON(path string) (packageJSON, error) {
	file, err := os.Open(path)
	if err != nil {
		return packageJSON{}, err
	}
	defer file.Close()
	manifest, err := admission.DecodeTypedJSON[packageJSON](file, 16<<20)
	if err != nil {
		return packageJSON{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if manifest.Name == "" || manifest.Version == "" || manifest.License == "" {
		return packageJSON{}, fmt.Errorf("%s must include name, version, and license", path)
	}
	return manifest, nil
}

func components(manifest packageJSON) ([]cyclonedxComponent, error) {
	out := []cyclonedxComponent{}
	goModules, err := goModuleComponents()
	if err != nil {
		return nil, err
	}
	out = append(out, goModules...)
	fileComponents, err := releaseFileComponents(manifest)
	if err != nil {
		return nil, err
	}
	out = append(out, fileComponents...)
	return out, nil
}

func goModuleComponents() ([]cyclonedxComponent, error) {
	output, err := exec.Command("go", "list", "-m", "-json", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("go list modules: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	out := []cyclonedxComponent{}
	for {
		var module goModuleRecord
		if err := decoder.Decode(&module); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode go module list: %w", err)
		}
		if module.Main {
			continue
		}
		version := module.Version
		pathValue := module.Path
		if module.Replace != nil {
			pathValue = module.Replace.Path
			version = module.Replace.Version
		}
		if pathValue == "" {
			continue
		}
		out = append(out, cyclonedxComponent{
			Type:       "library",
			BOMRef:     "go-module:" + pathValue + "@" + version,
			Name:       pathValue,
			Version:    version,
			PackageURL: goPackageURL(pathValue, version),
			Properties: []cyclonedxProperty{{
				Name:  "proofkit:source",
				Value: "go list -m -json all",
			}},
		})
	}
	return out, nil
}

func releaseFileComponents(manifest packageJSON) ([]cyclonedxComponent, error) {
	paths, err := releaseFilePaths()
	if err != nil {
		return nil, err
	}
	out := make([]cyclonedxComponent, 0, len(paths))
	for _, path := range paths {
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		out = append(out, cyclonedxComponent{
			Type:    componentType(path),
			BOMRef:  "file:" + filepath.ToSlash(path),
			Name:    filepath.Base(path),
			Version: manifest.Version,
			Hashes: []cyclonedxHash{{
				Alg:     "SHA-256",
				Content: sum,
			}},
			Licenses: []cyclonedxLicense{{
				License: cyclonedxLicenseID{ID: manifest.License},
			}},
			Properties: []cyclonedxProperty{{
				Name:  "proofkit:path",
				Value: filepath.ToSlash(path),
			}},
		})
	}
	return out, nil
}

func releaseFilePaths() ([]string, error) {
	patterns := []string{
		filepath.Join("artifacts", "package", "*.tgz"),
		filepath.Join("artifacts", "pypi", "*.whl"),
	}
	paths := []string{}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
	}
	binaryPaths, err := releasePlatformBinaryPaths()
	if err != nil {
		return nil, err
	}
	paths = append(paths, binaryPaths...)
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("release SBOM requires package, wheel, or binary artifacts")
	}
	return paths, nil
}

func releasePlatformBinaryPaths() ([]string, error) {
	expected := releaseplatform.BinaryPaths()
	expectedSet := map[string]struct{}{}
	for _, path := range expected {
		expectedSet[filepath.ToSlash(path)] = struct{}{}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("release SBOM missing release platform binary %s: %w", path, err)
		}
	}
	matches, err := filepath.Glob(filepath.Join("dist", "platform", "*", releaseplatform.BinaryName))
	if err != nil {
		return nil, err
	}
	for _, match := range matches {
		if _, ok := expectedSet[filepath.ToSlash(match)]; !ok {
			return nil, fmt.Errorf("release SBOM found unmanaged release platform binary %s", match)
		}
	}
	return expected, nil
}

func componentType(path string) string {
	if strings.HasPrefix(filepath.ToSlash(path), "dist/platform/") {
		return "file"
	}
	return "application"
}

func rootComponent(manifest packageJSON) cyclonedxComponent {
	return cyclonedxComponent{
		Type:       "application",
		BOMRef:     rootRef(manifest),
		Name:       manifest.Name,
		Version:    manifest.Version,
		PackageURL: toolComponent + "@" + manifest.Version,
		Licenses: []cyclonedxLicense{{
			License: cyclonedxLicenseID{ID: manifest.License},
		}},
		Properties: []cyclonedxProperty{
			{Name: "proofkit:repository", Value: manifest.Repository.URL},
			{Name: "proofkit:non-claim", Value: "SBOM inventory is release evidence; it does not prove vulnerability absence, license approval, or consumer deployment safety."},
		},
	}
}

func rootRef(manifest packageJSON) string {
	return "pkg:generic/" + manifest.Name + "@" + manifest.Version
}

func componentRefs(components []cyclonedxComponent, root string) []string {
	out := []string{}
	for _, component := range components {
		if component.BOMRef != root {
			out = append(out, component.BOMRef)
		}
	}
	sort.Strings(out)
	return out
}

func goPackageURL(path string, version string) string {
	if version == "" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + version
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
