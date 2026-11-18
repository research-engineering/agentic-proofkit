package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/tools/npmpack"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagearchive"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagemetadata"
)

func admitArchive(content []byte, record npmpack.Record) error {
	sha1Sum, sha512Sum := sha1.Sum(content), sha512.Sum512(content)
	if record.Shasum != hex.EncodeToString(sha1Sum[:]) || record.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(sha512Sum[:]) {
		return fmt.Errorf("npm pack record digests do not match captured archive")
	}
	found := false
	_, err := packagearchive.GzipEntries(content, packagearchive.MaxCompressedBytes, nil, func(entry packagearchive.Entry, reader io.Reader) error {
		if entry.Name != "package/package.json" {
			return nil
		}
		if entry.Size > packagemetadata.MaximumBytes {
			return fmt.Errorf("npm archive package manifest exceeds resource limit")
		}
		raw, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		manifest, err := packagemetadata.Admit(raw)
		if err != nil {
			return err
		}
		if manifest.Name != record.Name || manifest.Version != record.Version {
			return fmt.Errorf("npm archive manifest must match pack record name and version")
		}
		found = true
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("npm archive must contain package/package.json")
	}
	return nil
}
