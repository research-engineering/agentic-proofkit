package packagearchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

type forbiddenBody struct{ read bool }

func (body *forbiddenBody) Read([]byte) (int, error) {
	body.read = true
	return 0, errors.New("forbidden body read")
}

func headerBytes(t *testing.T, header tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := tar.NewWriter(&out).WriteHeader(&header); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestHeaderRefusalsPrecedeBody(t *testing.T) {
	for _, test := range []struct {
		name    string
		header  tar.Header
		prefix  []byte
		bytes   int64
		entries int
		want    string
	}{
		{"path", tar.Header{Name: "package/../escape", Size: 1}, nil, 4096, 10, "unsafe tar entry path"},
		{"type", tar.Header{Name: "package/link", Typeflag: tar.TypeSymlink, Linkname: "target"}, nil, 4096, 10, "must be a regular file"},
		{"entry", tar.Header{Name: "package/data", Size: 128<<20 + 1}, nil, 512 << 20, 10, "invalid size"},
		{"binary", tar.Header{Name: "package/dist/platform/linux-x64/agentic-proofkit", Mode: 0o755, Size: 64<<20 + 1}, nil, 512 << 20, 10, "invalid size"},
		{"remaining", tar.Header{Name: "package/data", Size: 513}, nil, 1024, 10, "remaining expanded byte limit"},
		{"duplicate", tar.Header{Name: "package/data", Size: 1}, headerBytes(t, tar.Header{Name: "package/data"}), 4096, 10, "duplicate tar entry"},
		{"count before unsafe header", tar.Header{Name: "../escape", Size: 1}, headerBytes(t, tar.Header{Name: "package/data"}), 4096, 1, "entry count limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &forbiddenBody{}
			content := append(append([]byte{}, test.prefix...), headerBytes(t, test.header)...)
			entries, err := BoundedHeaders(io.MultiReader(bytes.NewReader(content), body), test.bytes, test.entries, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) || entries != nil || body.read {
				t.Fatalf("header guard: entries=%v err=%v bodyRead=%v", entries, err, body.read)
			}
		})
	}
}

func TestInvalidLimitsDoNotRead(t *testing.T) {
	for _, test := range []struct {
		bytes   int64
		entries int
	}{{0, 1}, {-1, 1}, {math.MaxInt64, 1}, {1024, 0}, {1024, -1}} {
		body := &forbiddenBody{}
		if entries, err := BoundedHeaders(body, test.bytes, test.entries, nil); err == nil || entries != nil || body.read {
			t.Fatalf("invalid limits reached input: bytes=%d entries=%d err=%v read=%v", test.bytes, test.entries, err, body.read)
		}
	}
}

func TestGzipCompressedLimitIsInclusiveAndPrecedesDecode(t *testing.T) {
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	content := append(headerBytes(t, tar.Header{Name: "package/data"}), make([]byte, 1024)...)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := GzipHeaders(out.Bytes(), int64(out.Len()), nil); err != nil || len(entries) != 1 {
		t.Fatalf("exact compressed limit rejected: entries=%v err=%v", entries, err)
	}
	if _, err := GzipHeaders(out.Bytes(), int64(out.Len()-1), nil); err == nil || !strings.Contains(err.Error(), "compressed byte limit") {
		t.Fatalf("compressed overflow not rejected: %v", err)
	}
	if _, err := GzipHeaders([]byte("not gzip"), 1, nil); err == nil || !strings.Contains(err.Error(), "compressed byte limit") {
		t.Fatalf("gzip decode preceded compressed bound: %v", err)
	}
	for _, limit := range []int64{0, -1, math.MaxInt64} {
		if _, err := GzipHeaders([]byte("not gzip"), limit, nil); err == nil || !strings.Contains(err.Error(), "positive and bounded") {
			t.Fatalf("invalid compressed limit reached decode: %v", err)
		}
	}
}

func TestHeaderInclusiveSizes(t *testing.T) {
	for _, entry := range []Entry{
		{Name: "package/data", Typeflag: tar.TypeReg, Size: 128 << 20},
		{Name: "package/dist/agentic-proofkit", Typeflag: tar.TypeReg, Mode: 0o755, Size: 64 << 20},
	} {
		if err := VerifyHeader(entry); err != nil {
			t.Fatalf("inclusive entry bound rejected: %v", err)
		}
		entry.Size++
		if err := VerifyHeader(entry); err == nil {
			t.Fatal("entry bound plus one admitted")
		}
	}
}

func TestConsumerHeaderGuardPrecedesBody(t *testing.T) {
	want := errors.New("consumer-specific header refusal")
	body := &forbiddenBody{}
	content := headerBytes(t, tar.Header{Name: "package/data", Size: 1})
	entries, err := BoundedHeaders(io.MultiReader(bytes.NewReader(content), body), 4096, 10, func(Entry) error { return want })
	if !errors.Is(err, want) || entries != nil || body.read {
		t.Fatalf("consumer header guard: entries=%v err=%v bodyRead=%v", entries, err, body.read)
	}
}
