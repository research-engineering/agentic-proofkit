package main

import (
	"io"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagearchive"
)

const (
	maxCompressedArchiveBytes = 128 << 20
	maxExpandedArchiveBytes   = packagearchive.MaxExpandedBytes
	maxArchiveEntries         = packagearchive.MaxEntries
)

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
