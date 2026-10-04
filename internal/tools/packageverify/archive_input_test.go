package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type countedArchiveReader struct {
	source io.Reader
	read   int
}

func (reader *countedArchiveReader) Read(value []byte) (int, error) {
	n, err := reader.source.Read(value)
	reader.read += n
	return n, err
}

type forbiddenArchiveBody struct{ read bool }

func (body *forbiddenArchiveBody) Read([]byte) (int, error) {
	body.read = true
	return 0, errors.New("forbidden body read")
}

type archiveZeroStream struct{}

func (archiveZeroStream) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func TestArchiveGzipEntrypointRejectsExpandedOverflowBeforeMissingBody(t *testing.T) {
	for _, test := range []struct {
		name string
		size int64
		full bool
	}{
		// Four headers, four bodies and two terminator blocks total exactly 512MiB.
		{"exact", 128<<20 - 3072, true},
		{"near overflow", 128<<20 - 2047, false},
		{"far overflow", 128 << 20, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var compressed bytes.Buffer
			writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 3; index++ {
				if _, err := writer.Write(archiveHeader(t, "package/expanded", 128<<20)); err != nil {
					t.Fatal(err)
				}
				if _, err := io.CopyN(writer, archiveZeroStream{}, 128<<20); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writer.Write(archiveHeader(t, "package/final", test.size)); err != nil {
				t.Fatal(err)
			}
			if test.full {
				if _, err := io.CopyN(writer, archiveZeroStream{}, test.size+1024); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if compressed.Len() >= 128<<20 {
				t.Fatal("fixture does not reach the expanded-input boundary")
			}
			entries, err := tarEntryHeadersFromBytes(compressed.Bytes())
			if test.full {
				if err != nil || len(entries) != 4 || entries[3].Size != test.size {
					t.Fatalf("inclusive gzip expanded boundary: count=%d err=%v", len(entries), err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "remaining expanded byte limit") || entries != nil {
				// No fourth body exists. A bypass reaches truncation, not quota refusal.
				t.Fatalf("gzip entrypoint did not reject before the absent body: count=%d err=%v", len(entries), err)
			}
		})
	}
}

func archiveHeader(t *testing.T, name string, size int64) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	if err := writer.WriteHeader(&tar.Header{Name: name, Size: size, Mode: 0o644, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestArchiveHeaderBudgetPrecedesBody(t *testing.T) {
	for _, test := range []struct {
		name  string
		size  int64
		limit int64
		want  string
	}{
		{"entry", 128<<20 + 1, 512 << 20, "invalid size"},
		{"aggregate", 513, 1024, "remaining expanded byte limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &forbiddenArchiveBody{}
			reader := &countedArchiveReader{source: io.MultiReader(bytes.NewReader(archiveHeader(t, "package/data", test.size)), body)}
			entries, err := boundedTarEntryHeaders(reader, test.limit, 4096)
			if err == nil || !strings.Contains(err.Error(), test.want) || entries != nil || body.read || reader.read != 512 {
				t.Fatalf("header did not dominate payload: entries=%d err=%v body=%v read=%d", len(entries), err, body.read, reader.read)
			}
		})
	}
}

func TestArchiveTraversalInclusiveLimits(t *testing.T) {
	first := archiveHeader(t, "package/a", 0)
	second := archiveHeader(t, "package/b", 0)
	archive := append(append(append([]byte{}, first...), second...), make([]byte, 1024)...)
	for _, test := range []struct {
		name      string
		bytes     int64
		entries   int
		wantError string
	}{
		{"exact", 2048, 2, ""},
		{"expanded overflow", 2047, 2, "expanded byte limit"},
		{"entry overflow", 2048, 1, "entry count limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &countedArchiveReader{source: bytes.NewReader(archive)}
			entries, err := boundedTarEntryHeaders(reader, test.bytes, test.entries)
			if test.wantError == "" {
				if err != nil || len(entries) != 2 || entries[0].Name != "package/a" || entries[1].Name != "package/b" {
					t.Fatalf("valid archive: %v %#v", err, entries)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) || entries != nil {
				t.Fatalf("missing budget refusal: %v %#v", err, entries)
			}
			if int64(reader.read) > test.bytes+1 {
				t.Fatalf("read exceeded overflow probe: %d", reader.read)
			}
		})
	}
}

func TestArchiveExpandedBudgetIncludesMetadata(t *testing.T) {
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	if err := writer.WriteHeader(&tar.Header{Name: "package/data", Mode: 0o644, Typeflag: tar.TypeReg, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": strings.Repeat("x", 2000)}}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader := &countedArchiveReader{source: bytes.NewReader(out.Bytes())}
	entries, err := boundedTarEntryHeaders(reader, 1024, 4096)
	if err == nil || !strings.Contains(err.Error(), "expanded byte limit") || entries != nil || reader.read != 1025 {
		t.Fatalf("metadata escaped actual-work bound: %v read=%d", err, reader.read)
	}
}

func TestArchiveTruncationIsNotSuccess(t *testing.T) {
	_, err := boundedTarEntryHeaders(bytes.NewReader(archiveHeader(t, "package/data", 512)), 4096, 4096)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated body accepted: %v", err)
	}
}

func TestArchiveDefaultCardinalityLimit(t *testing.T) {
	var archive bytes.Buffer
	for index := 0; index < 4096; index++ {
		archive.Write(archiveHeader(t, "package/data", 0))
	}
	positive := append(append([]byte{}, archive.Bytes()...), make([]byte, 1024)...)
	entries, err := tarEntryHeadersFromGzip(bytes.NewReader(positive))
	if err != nil || len(entries) != 4096 {
		t.Fatalf("inclusive default entry bound rejected: %v count=%d", err, len(entries))
	}
	body := &forbiddenArchiveBody{}
	archive.Write(archiveHeader(t, "package/overflow", 1))
	reader := &countedArchiveReader{source: io.MultiReader(bytes.NewReader(archive.Bytes()), body)}
	entries, err = tarEntryHeadersFromGzip(reader)
	if err == nil || !strings.Contains(err.Error(), "entry count limit") || entries != nil || body.read || reader.read != 4097*512 {
		t.Fatalf("default count bound failed before overflow body: %v count=%d read=%d body=%v", err, len(entries), reader.read, body.read)
	}
}

func TestArchiveGzipEntrypointPreservesCardinalityBoundary(t *testing.T) {
	var headers bytes.Buffer
	for index := 0; index < 4096; index++ {
		headers.Write(archiveHeader(t, "package/data", 0))
	}
	for _, test := range []struct {
		name string
		tail []byte
		want string
	}{
		{"exact", make([]byte, 1024), ""},
		{"overflow", archiveHeader(t, "package/unread", 1), "entry count limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var compressed bytes.Buffer
			writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(writer, io.MultiReader(bytes.NewReader(headers.Bytes()), bytes.NewReader(test.tail))); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			entries, err := tarEntryHeadersFromBytes(compressed.Bytes())
			if test.want == "" {
				if err != nil || len(entries) != 4096 {
					t.Fatalf("inclusive gzip cardinality boundary: count=%d err=%v", len(entries), err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.want) || entries != nil {
				t.Fatalf("gzip entry count did not reject before the absent body: count=%d err=%v", len(entries), err)
			}
		})
	}
}

func TestPackageArchiveReadBoundsBeforeHashing(t *testing.T) {
	withWorkingDirectory(t, t.TempDir())
	name := filepath.Join("artifacts", "package", "oversized.tgz")
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(128<<20 + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	record := packRecord{Name: rootPackageName, Filename: "oversized.tgz"}
	for _, run := range []func() error{
		func() error { _, err := verifyRootPackage(record); return err },
		func() error { return verifyPackRecordBytes(record) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "resource limit") {
			t.Fatalf("archive bound did not precede hashing: %v", err)
		}
	}
}
