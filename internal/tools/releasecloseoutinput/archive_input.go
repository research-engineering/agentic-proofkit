package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagearchive"
)

func verifyPackRecords(root string, path string, manifest packageJSON) (map[string]string, bool) {
	expectedFilename, ok := npmTarballName(manifest.Name, manifest.Version)
	if !ok {
		return nil, false
	}
	records, err := readTypedJSON[[]packRecord](root, path)
	if err != nil || len(records) != 1 {
		return nil, false
	}
	record := records[0]
	if record.Name != manifest.Name || record.Version != manifest.Version || record.Filename != expectedFilename {
		return nil, false
	}
	subjects, err := verifyPackRecordBytesWithin(root, record, maxNPMTarballBytes)
	return subjects, err == nil
}

func verifyPackRecordBytesWithin(root string, record packRecord, maxBytes int64) (map[string]string, error) {
	if filepath.Base(record.Filename) != record.Filename || filepath.Clean(record.Filename) != record.Filename || !filepath.IsLocal(record.Filename) {
		return nil, fmt.Errorf("invalid npm archive filename")
	}
	relativePath := "artifacts/package/" + record.Filename
	content, err := artifactfile.ReadBounded(root, relativePath, maxBytes)
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("npm archive is empty")
	}
	sha1Sum := sha1.Sum(content)
	sha512Sum := sha512.Sum512(content)
	if hex.EncodeToString(sha1Sum[:]) != record.Shasum || "sha512-"+base64.StdEncoding.EncodeToString(sha512Sum[:]) != record.Integrity {
		return nil, fmt.Errorf("npm archive digest mismatch")
	}
	pathsByMember := make(map[string]string)
	for _, target := range releaseplatform.Targets() {
		pathsByMember[target.PackageTarEntry] = target.BinaryPath
	}
	subjects := make(map[string]string, len(pathsByMember)+1)
	entries, err := packagearchive.GzipEntries(content, maxBytes, nil, func(entry packagearchive.Entry, body io.Reader) error {
		path, isBinary := pathsByMember[entry.Name]
		if !isBinary {
			return nil
		}
		hash := sha256.New()
		copied, err := io.Copy(hash, body)
		if err != nil {
			return err
		}
		if copied != entry.Size {
			return io.ErrUnexpectedEOF
		}
		subjects[path] = hex.EncodeToString(hash.Sum(nil))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := packagearchive.VerifyPlatformClosure(entries); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	subjects[relativePath] = hex.EncodeToString(sum[:])
	return subjects, nil
}
