package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
)

const (
	maxCompressedArchiveBytes = 128 << 20
	maxExpandedArchiveBytes   = 512 << 20
	maxArchiveEntries         = 4096
)

func readPackageArchive(record packRecord) ([]byte, error) {
	return artifactfile.ReadBounded(".", filepath.ToSlash(recordPath(record)), maxCompressedArchiveBytes)
}

func tarEntryHeadersFromBytes(content []byte) ([]tarEntry, error) {
	if len(content) > maxCompressedArchiveBytes {
		return nil, fmt.Errorf("package archive exceeds compressed byte limit")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	return tarEntryHeadersFromGzip(gzipReader)
}

func tarEntryHeadersFromGzip(reader io.Reader) ([]tarEntry, error) {
	return boundedTarEntryHeaders(reader, maxExpandedArchiveBytes, maxArchiveEntries)
}

func boundedTarEntryHeaders(reader io.Reader, maximumBytes int64, maximumEntries int) ([]tarEntry, error) {
	if maximumBytes <= 0 || maximumBytes == math.MaxInt64 || maximumEntries <= 0 {
		return nil, fmt.Errorf("package archive limits must be positive and bounded")
	}
	// Count actual traversal, including padding and extension headers. One extra
	// byte distinguishes exact exhaustion from EOF without unbounded probing.
	limited := &io.LimitedReader{R: reader, N: maximumBytes + 1}
	tarReader := tar.NewReader(limited)
	entries := []tarEntry{}
	for {
		header, err := tarReader.Next()
		if limited.N == 0 {
			return nil, fmt.Errorf("package archive exceeds expanded byte limit")
		}
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if len(entries) == maximumEntries {
			return nil, fmt.Errorf("package archive exceeds entry count limit")
		}
		entry := tarEntry{Mode: header.Mode, Name: header.Name, Size: header.Size, Typeflag: header.Typeflag}
		if err := verifyTarEntryHeader(entry); err != nil {
			return nil, err
		}
		if header.Size > limited.N-1 {
			return nil, fmt.Errorf("package archive entry exceeds remaining expanded byte limit")
		}
		entries = append(entries, entry)
	}
}
