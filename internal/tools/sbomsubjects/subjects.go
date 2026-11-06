// Package sbomsubjects verifies the file evidence emitted by releasesbom.
package sbomsubjects

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

// MaxBytes is the resource limit for SBOM subject admission.
const MaxBytes = 16 << 20

const fileRefPrefix = "file:"
const pathProperty = "proofkit:path"

type bom struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Components  []component `json:"components"`
	Metadata    struct {
		Component *component `json:"component"`
	} `json:"metadata"`
}

type component struct {
	Type       string      `json:"type"`
	BOMRef     string      `json:"bom-ref"`
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	Hashes     []hash      `json:"hashes"`
	Properties []property  `json:"properties"`
	Components []component `json:"components"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Admit matches the exact file-subject set against independently derived
// lowercase SHA-256 digests keyed by canonical repository-relative paths.
// It does not validate the non-file inventory or the CycloneDX schema.
func Admit(content []byte, expected map[string]string, version string) error {
	if len(expected) == 0 || version == "" {
		return fmt.Errorf("release SBOM subject admission requires expected paths, digests, and version")
	}
	document, err := admission.DecodeTypedJSON[bom](bytes.NewReader(content), MaxBytes)
	if err != nil {
		return fmt.Errorf("decode release SBOM subjects: %w", err)
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion == "" {
		return fmt.Errorf("release SBOM must declare its CycloneDX format and version")
	}
	paths := slices.Sorted(maps.Keys(expected))
	for _, subjectPath := range paths {
		digest := expected[subjectPath]
		if subjectPath == "." || !fs.ValidPath(subjectPath) || strings.ContainsAny(subjectPath, ":\\") ||
			len(digest) != sha256.Size*2 || strings.ToLower(digest) != digest {
			return fmt.Errorf("release SBOM expected subject must have a canonical path and lowercase SHA-256")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return fmt.Errorf("release SBOM expected subject must have a hexadecimal SHA-256")
		}
	}
	if root := document.Metadata.Component; root != nil && hasFileSubject(*root) {
		return fmt.Errorf("release SBOM file subjects must be top-level components")
	}
	seen := make(map[string]bool, len(expected))
	for _, item := range document.Components {
		for _, nested := range item.Components {
			if hasFileSubject(nested) {
				return fmt.Errorf("release SBOM file subjects must be top-level components")
			}
		}
		subjectPath, isFile := strings.CutPrefix(item.BOMRef, fileRefPrefix)
		pathValue, pathCount := item.filePath()
		if !isFile && item.Type != "file" && pathCount == 0 {
			continue
		}
		digest, wanted := expected[subjectPath]
		if !isFile || !wanted {
			return fmt.Errorf("release SBOM contains an unexpected file subject")
		}
		if seen[subjectPath] {
			return fmt.Errorf("release SBOM contains duplicate file subject %q", subjectPath)
		}
		componentType := "application"
		if strings.HasPrefix(subjectPath, "dist/platform/") {
			componentType = "file"
		}
		if pathCount != 1 || pathValue != subjectPath || item.Type != componentType ||
			item.Name != path.Base(subjectPath) || item.Version != version {
			return fmt.Errorf("release SBOM file subject %q has incorrect path, name, type, or version", subjectPath)
		}
		if len(item.Hashes) != 1 || item.Hashes[0] != (hash{Alg: "SHA-256", Content: digest}) {
			return fmt.Errorf("release SBOM file subject %q does not have the expected SHA-256", subjectPath)
		}
		seen[subjectPath] = true
	}
	for _, subjectPath := range paths {
		if !seen[subjectPath] {
			return fmt.Errorf("release SBOM is missing file subject %q", subjectPath)
		}
	}
	return nil
}

func (item component) filePath() (value string, count int) {
	for _, property := range item.Properties {
		if property.Name == pathProperty {
			value = property.Value
			count++
		}
	}
	return value, count
}

func hasFileSubject(item component) bool {
	_, pathCount := item.filePath()
	return item.Type == "file" || strings.HasPrefix(item.BOMRef, fileRefPrefix) ||
		pathCount != 0 || slices.ContainsFunc(item.Components, hasFileSubject)
}
