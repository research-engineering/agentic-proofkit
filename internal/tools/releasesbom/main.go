package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	gobuildinfo "debug/buildinfo"
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

var uuidNamespaceURL = [16]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

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
	SerialNumber string                `json:"serialNumber"`
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
	Scope      string              `json:"scope,omitempty"`
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
	components, dependencies, err := components(manifest)
	if err != nil {
		return err
	}
	sort.Slice(components, func(left int, right int) bool {
		return components[left].BOMRef < components[right].BOMRef
	})
	out := cyclonedxBOM{
		BOMFormat:    bomFormat,
		SpecVersion:  specVersion,
		SerialNumber: sbomSerialNumber(manifest),
		Version:      1,
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

func components(manifest packageJSON) ([]cyclonedxComponent, []cyclonedxDependency, error) {
	sourceModules, err := goModuleInventory()
	if err != nil {
		return nil, nil, err
	}
	paths, err := releaseFilePaths()
	if err != nil {
		return nil, nil, err
	}
	fileComponents, runtimeInventories, err := releaseFileEvidence(manifest, paths, nil)
	if err != nil {
		return nil, nil, err
	}
	goModules, dependencies := projectModuleEvidence(sourceModules, runtimeInventories)
	out := append([]cyclonedxComponent{}, goModules...)
	out = append(out, fileComponents...)
	return out, dependencies, nil
}

func goModuleInventory() ([]goModuleRecord, error) {
	output, err := exec.Command("go", "list", "-m", "-json", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("go list modules: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	out := []goModuleRecord{}
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
		module = canonicalModule(module)
		if module.Path == "" {
			continue
		}
		out = append(out, module)
	}
	return out, nil
}

type artifactRuntimeInventory struct {
	BinaryRef string
	Modules   []goModuleRecord
}

func binaryRuntimeModules(reader io.ReaderAt) ([]goModuleRecord, error) {
	info, err := gobuildinfo.Read(reader)
	if err != nil {
		// A stripped or otherwise non-introspectable binary has no admitted
		// runtime-module evidence. The release file remains an SBOM subject.
		return nil, nil
	}
	modules := make([]goModuleRecord, 0, len(info.Deps))
	for _, module := range info.Deps {
		record := goModuleRecord{Path: module.Path, Version: module.Version}
		if module.Replace != nil {
			record.Replace = &goModuleRecord{Path: module.Replace.Path, Version: module.Replace.Version}
		}
		record = canonicalModule(record)
		if record.Path != "" {
			modules = append(modules, record)
		}
	}
	sort.Slice(modules, func(left, right int) bool {
		return moduleKey(modules[left]) < moduleKey(modules[right])
	})
	return modules, nil
}

func projectModuleEvidence(source []goModuleRecord, artifacts []artifactRuntimeInventory) ([]cyclonedxComponent, []cyclonedxDependency) {
	components := map[string]cyclonedxComponent{}
	for _, raw := range source {
		module := canonicalModule(raw)
		if module.Path == "" {
			continue
		}
		components[moduleKey(module)] = moduleComponent(module, "excluded", []cyclonedxProperty{
			{Name: "proofkit:evidence-class", Value: "source_build_inventory"},
			{Name: "proofkit:source", Value: "go list -m -json all"},
		})
	}
	dependencies := make([]cyclonedxDependency, 0, len(artifacts))
	for _, artifact := range artifacts {
		edges := []string{}
		seen := map[string]struct{}{}
		for _, raw := range artifact.Modules {
			module := canonicalModule(raw)
			if module.Path == "" {
				continue
			}
			key := moduleKey(module)
			component, exists := components[key]
			if !exists {
				component = moduleComponent(module, "required", nil)
			}
			component.Scope = "required"
			component.Properties = appendUniqueProperty(component.Properties, cyclonedxProperty{
				Name: "proofkit:evidence-class", Value: "artifact_build_info",
			})
			components[key] = component
			if _, exists := seen[component.BOMRef]; !exists {
				seen[component.BOMRef] = struct{}{}
				edges = append(edges, component.BOMRef)
			}
		}
		sort.Strings(edges)
		dependencies = append(dependencies, cyclonedxDependency{Ref: artifact.BinaryRef, DependsOn: edges})
	}
	out := make([]cyclonedxComponent, 0, len(components))
	for _, component := range components {
		sort.Slice(component.Properties, func(left, right int) bool {
			if component.Properties[left].Name != component.Properties[right].Name {
				return component.Properties[left].Name < component.Properties[right].Name
			}
			return component.Properties[left].Value < component.Properties[right].Value
		})
		out = append(out, component)
	}
	sort.Slice(out, func(left, right int) bool { return out[left].BOMRef < out[right].BOMRef })
	sort.Slice(dependencies, func(left, right int) bool { return dependencies[left].Ref < dependencies[right].Ref })
	return out, dependencies
}

func canonicalModule(module goModuleRecord) goModuleRecord {
	if module.Replace != nil {
		return goModuleRecord{Path: module.Replace.Path, Version: module.Replace.Version}
	}
	return goModuleRecord{Path: module.Path, Version: module.Version}
}

func moduleKey(module goModuleRecord) string {
	return module.Path + "@" + module.Version
}

func moduleComponent(module goModuleRecord, scope string, properties []cyclonedxProperty) cyclonedxComponent {
	return cyclonedxComponent{
		Type:       "library",
		BOMRef:     "go-module:" + moduleKey(module),
		Name:       module.Path,
		Version:    module.Version,
		PackageURL: goPackageURL(module.Path, module.Version),
		Properties: properties,
		Scope:      scope,
	}
}

func appendUniqueProperty(properties []cyclonedxProperty, property cyclonedxProperty) []cyclonedxProperty {
	for _, existing := range properties {
		if existing == property {
			return properties
		}
	}
	return append(properties, property)
}

func releaseFileEvidence(
	manifest packageJSON,
	paths []string,
	afterHash func(string) error,
) ([]cyclonedxComponent, []artifactRuntimeInventory, error) {
	binaryPaths := map[string]struct{}{}
	for _, path := range releaseplatform.BinaryPaths() {
		binaryPaths[filepath.Clean(path)] = struct{}{}
	}
	out := make([]cyclonedxComponent, 0, len(paths))
	runtimeInventories := make([]artifactRuntimeInventory, 0, len(binaryPaths))
	for _, path := range paths {
		component, modules, isBinary, err := admitReleaseFile(manifest, path, binaryPaths, afterHash)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, component)
		if isBinary {
			runtimeInventories = append(runtimeInventories, artifactRuntimeInventory{
				BinaryRef: component.BOMRef,
				Modules:   modules,
			})
		}
	}
	return out, runtimeInventories, nil
}

func admitReleaseFile(
	manifest packageJSON,
	path string,
	binaryPaths map[string]struct{},
	afterHash func(string) error,
) (cyclonedxComponent, []goModuleRecord, bool, error) {
	var zero cyclonedxComponent
	routeInfo, err := os.Lstat(path)
	if err != nil {
		return zero, nil, false, err
	}
	if routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.Mode().IsRegular() {
		return zero, nil, false, fmt.Errorf("release file %s must be a non-symlink regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return zero, nil, false, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return zero, nil, false, err
	}
	if !os.SameFile(routeInfo, before) {
		return zero, nil, false, fmt.Errorf("release file %s changed before admission", path)
	}
	content, err := io.ReadAll(io.NewSectionReader(file, 0, before.Size()))
	if err != nil {
		return zero, nil, false, err
	}
	if int64(len(content)) != before.Size() {
		return zero, nil, false, fmt.Errorf("release file %s changed during admission", path)
	}
	contentDigest := sha256.Sum256(content)
	if afterHash != nil {
		if err := afterHash(path); err != nil {
			return zero, nil, false, err
		}
	}
	_, isBinary := binaryPaths[filepath.Clean(path)]
	var modules []goModuleRecord
	if isBinary {
		modules, err = binaryRuntimeModules(bytes.NewReader(content))
		if err != nil {
			return zero, nil, false, err
		}
	}
	currentDigest := sha256.New()
	if _, err := io.Copy(currentDigest, io.NewSectionReader(file, 0, before.Size())); err != nil {
		return zero, nil, false, err
	}
	after, err := file.Stat()
	if err != nil {
		return zero, nil, false, err
	}
	currentRoute, err := os.Lstat(path)
	if err != nil || currentRoute.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, after) || !os.SameFile(before, currentRoute) ||
		before.Size() != after.Size() ||
		!bytes.Equal(contentDigest[:], currentDigest.Sum(nil)) {
		return zero, nil, false, fmt.Errorf("release file %s changed during admission", path)
	}
	component := cyclonedxComponent{
		Type:    componentType(path),
		BOMRef:  "file:" + filepath.ToSlash(path),
		Name:    filepath.Base(path),
		Version: manifest.Version,
		Hashes: []cyclonedxHash{{
			Alg:     "SHA-256",
			Content: hex.EncodeToString(contentDigest[:]),
		}},
		Licenses: []cyclonedxLicense{{
			License: cyclonedxLicenseID{ID: manifest.License},
		}},
		Properties: []cyclonedxProperty{{
			Name:  "proofkit:path",
			Value: filepath.ToSlash(path),
		}},
	}
	return component, modules, isBinary, nil
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

func sbomSerialNumber(manifest packageJSON) string {
	return "urn:uuid:" + uuidV5(uuidNamespaceURL, rootRef(manifest))
}

func uuidV5(namespace [16]byte, name string) string {
	hash := sha1.New() // UUID v5 requires SHA-1; this is an identifier, not a security boundary.
	_, _ = hash.Write(namespace[:])
	_, _ = hash.Write([]byte(name))
	sum := hash.Sum(nil)
	uuid := make([]byte, 16)
	copy(uuid, sum)
	uuid[6] = (uuid[6] & 0x0f) | 0x50
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func goPackageURL(path string, version string) string {
	if version == "" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + version
}
