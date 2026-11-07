package main

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagearchive"
)

const (
	maxCompressedArchiveBytes = 128 << 20
	maxExpandedArchiveBytes   = packagearchive.MaxExpandedBytes
	maxArchiveEntries         = packagearchive.MaxEntries
)

func readPackRecords(root, path string) ([]packRecord, error) {
	const limit = 16 << 20
	content, err := artifactfile.ReadBounded(root, path, limit)
	if err != nil {
		return nil, fmt.Errorf("read npm pack record: %w", err)
	}
	records, err := admission.DecodeTypedJSON[[]packRecord](bytes.NewReader(content), limit)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if len(records) != 1 {
		return nil, fmt.Errorf("npm pack must describe exactly the root package, got %d records", len(records))
	}
	return records, nil
}

func readPackageArchive(record packRecord) ([]byte, error) {
	return artifactfile.ReadBounded(".", filepath.ToSlash(recordPath(record)), maxCompressedArchiveBytes)
}

func tarEntryHeadersFromBytes(content []byte) ([]tarEntry, error) {
	return packagearchive.GzipHeaders(content, maxCompressedArchiveBytes, verifyTarEntryHeader)
}

func tarEntryHeadersFromGzip(reader io.Reader) ([]tarEntry, error) {
	return boundedTarEntryHeaders(reader, maxExpandedArchiveBytes, maxArchiveEntries)
}

func boundedTarEntryHeaders(reader io.Reader, maximumBytes int64, maximumEntries int) ([]tarEntry, error) {
	return packagearchive.BoundedHeaders(reader, maximumBytes, maximumEntries, verifyTarEntryHeader)
}
