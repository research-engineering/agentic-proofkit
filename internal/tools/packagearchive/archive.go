// Package packagearchive admits bounded npm archive topology, not native
// executable compatibility, installed behavior, or publication evidence.
package packagearchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

const (
	MaxExpandedBytes = 512 << 20
	MaxEntries       = 4096
	MaxEntryBytes    = 128 << 20
	MaxBinaryBytes   = 64 << 20
)

type Entry struct {
	Mode     int64
	Name     string
	Size     int64
	Typeflag byte
}

func GzipHeaders(content []byte, maximumCompressedBytes int64, validateHeader func(Entry) error) ([]Entry, error) {
	return GzipEntries(content, maximumCompressedBytes, validateHeader, nil)
}

func GzipEntries(content []byte, maximumCompressedBytes int64, validateHeader func(Entry) error, visitBody func(Entry, io.Reader) error) ([]Entry, error) {
	if maximumCompressedBytes <= 0 || maximumCompressedBytes == math.MaxInt64 {
		return nil, fmt.Errorf("package archive limits must be positive and bounded")
	}
	if int64(len(content)) > maximumCompressedBytes {
		return nil, fmt.Errorf("package archive exceeds compressed byte limit")
	}
	reader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return BoundedEntries(reader, MaxExpandedBytes, MaxEntries, validateHeader, visitBody)
}

func BoundedHeaders(reader io.Reader, maximumBytes int64, maximumEntries int, validateHeader func(Entry) error) ([]Entry, error) {
	return BoundedEntries(reader, maximumBytes, maximumEntries, validateHeader, nil)
}

// visitBody runs after header admission; its bounded reader is valid only
// during that invocation. Unread body bytes remain part of the traversal budget.
func BoundedEntries(reader io.Reader, maximumBytes int64, maximumEntries int, validateHeader func(Entry) error, visitBody func(Entry, io.Reader) error) ([]Entry, error) {
	if maximumBytes <= 0 || maximumBytes == math.MaxInt64 || maximumEntries <= 0 {
		return nil, fmt.Errorf("package archive limits must be positive and bounded")
	}
	// Include padding and extension headers in actual traversal. The one-byte
	// probe distinguishes inclusive exhaustion from EOF without unbounded work.
	limited := &io.LimitedReader{R: reader, N: maximumBytes + 1}
	tarReader := tar.NewReader(limited)
	entries := []Entry{}
	seen := map[string]struct{}{}
	for {
		header, err := tarReader.Next()
		if limited.N == 0 {
			return nil, fmt.Errorf("package archive exceeds expanded byte limit")
		}
		if errors.Is(err, io.EOF) {
			if err := verifyFileTree(seen); err != nil {
				return nil, err
			}
			if err := finishArchive(limited); err != nil {
				return nil, err
			}
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if len(entries) == maximumEntries {
			return nil, fmt.Errorf("package archive exceeds entry count limit")
		}
		entry := Entry{Mode: header.Mode, Name: header.Name, Size: header.Size, Typeflag: header.Typeflag}
		if err := VerifyHeader(entry); err != nil {
			return nil, err
		}
		if validateHeader != nil {
			if err := validateHeader(entry); err != nil {
				return nil, err
			}
		}
		if header.Size > limited.N-1 {
			return nil, fmt.Errorf("package archive entry exceeds remaining expanded byte limit")
		}
		if _, exists := seen[entry.Name]; exists {
			return nil, fmt.Errorf("root package contains duplicate tar entry %s", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		if visitBody != nil {
			if err := visitBody(entry, io.LimitReader(tarReader, entry.Size)); err != nil {
				return nil, err
			}
		}
		entries = append(entries, entry)
	}
}

func verifyFileTree[V any](seen map[string]V) error {
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		prefix := name + "/"
		index := sort.SearchStrings(names, prefix)
		if index < len(names) && strings.HasPrefix(names[index], prefix) {
			return fmt.Errorf("package archive contains conflicting file paths")
		}
	}
	return nil
}

// npm artifacts contain one logical tar archive. Consume its optional zero
// padding through gzip EOF so tar's terminator cannot hide trailer errors.
func finishArchive(limited *io.LimitedReader) error {
	var buffer [32 << 10]byte
	for {
		n, err := limited.Read(buffer[:])
		if limited.N == 0 {
			return fmt.Errorf("package archive exceeds expanded byte limit")
		}
		for _, value := range buffer[:n] {
			if value != 0 {
				return fmt.Errorf("package archive contains data after tar terminator")
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func canonicalEntryPath(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") &&
		!strings.ContainsAny(name, "\x00\\") && path.Clean(name) == name
}

func VerifyHeader(entry Entry) error {
	if !canonicalEntryPath(entry.Name) {
		return fmt.Errorf("root package contains unsafe tar entry path %q", entry.Name)
	}
	if !strings.HasPrefix(entry.Name, "package/") {
		return fmt.Errorf("root package entry must belong to canonical package/ root")
	}
	if entry.Typeflag != tar.TypeReg {
		return fmt.Errorf("root package tar entry %s must be a regular file", entry.Name)
	}
	if entry.Size < 0 || entry.Size > MaxEntryBytes {
		return fmt.Errorf("root package tar entry %s has invalid size %d", entry.Name, entry.Size)
	}
	if IsBinaryEntry(entry.Name) {
		if entry.Size == 0 || entry.Size > MaxBinaryBytes {
			return fmt.Errorf("root package binary entry %s has invalid size %d", entry.Name, entry.Size)
		}
		if entry.Mode&0o111 == 0 {
			return fmt.Errorf("root package binary entry %s must be executable", entry.Name)
		}
	}
	return nil
}

func IsBinaryEntry(name string) bool {
	if name == "package/dist/agentic-proofkit" {
		return true
	}
	for _, entry := range releaseplatform.PackageTarEntries() {
		if name == entry {
			return true
		}
	}
	return false
}

func VerifyPlatformClosure(entries []Entry) error {
	expected := releaseplatform.PackageTarEntrySet()
	for _, entry := range entries {
		if entry.Name != "package/dist/platform" && !strings.HasPrefix(entry.Name, "package/dist/platform/") {
			continue
		}
		if _, ok := expected[entry.Name]; !ok {
			return fmt.Errorf("root package contains unexpected platform entry %s", entry.Name)
		}
		delete(expected, entry.Name)
	}
	for _, name := range releaseplatform.PackageTarEntries() {
		if _, missing := expected[name]; missing {
			return fmt.Errorf("root package missing required entry %s", name)
		}
	}
	return nil
}
