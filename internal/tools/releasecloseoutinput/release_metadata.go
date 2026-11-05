package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

type releaseManifestEvidence struct {
	record releaseManifest
	sha256 string
}

func readReleaseManifest(root string) releaseManifestEvidence {
	const maximumBytes = 16 << 20
	content, err := artifactfile.ReadBounded(root, "artifacts/release/release-manifest.json", maximumBytes)
	if err != nil {
		return releaseManifestEvidence{}
	}
	record, err := admission.DecodeTypedJSON[releaseManifest](bytes.NewReader(content), maximumBytes)
	if err != nil {
		return releaseManifestEvidence{}
	}
	return releaseManifestEvidence{record: record, sha256: fmt.Sprintf("%x", sha256.Sum256(content))}
}

func (evidence releaseManifestEvidence) matches(manifest packageJSON) bool {
	record := evidence.record
	return evidence.sha256 != "" &&
		record.ArtifactKind == "proofkit.release-manifest.v1" &&
		record.Package.Name == manifest.Name &&
		record.Package.Version == manifest.Version &&
		len(record.NonClaims) > 0
}

func releaseNotesDigest(root string, manifest packageJSON) string {
	record, err := releasechange.Read(filepath.Join(root, filepath.FromSlash(releasechange.RecordPath)))
	if err != nil || releasechange.RequireVersion(record, manifest.Version) != nil {
		return ""
	}
	pypiPublished := fileExists(root, "artifacts/pypi-registry/pypi-release.json")
	expected := []byte(releasechange.RenderMarkdown(record, manifest.Name, pythonPackageName, pypiPublished))
	content, err := artifactfile.ReadBounded(root, "artifacts/release/release-notes.md", int64(len(expected)))
	if err != nil || !bytes.Equal(content, expected) {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(content))
}
