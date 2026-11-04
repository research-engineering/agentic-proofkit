package packagearchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"testing"
)

func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func framedTar(t *testing.T) []byte {
	t.Helper()
	return append(headerBytes(t, tar.Header{Name: "package/data"}), make([]byte, 1024)...)
}

func TestGzipTrailerErrorsCannotHideBehindTarTerminator(t *testing.T) {
	valid := gzipBytes(t, framedTar(t))
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{"crc", func(b []byte) []byte { b[len(b)-8] ^= 1; return b }, gzip.ErrChecksum},
		{"size", func(b []byte) []byte { b[len(b)-4] ^= 1; return b }, gzip.ErrChecksum},
		{"footer byte", func(b []byte) []byte { return b[:len(b)-1] }, io.ErrUnexpectedEOF},
		{"footer", func(b []byte) []byte { return b[:len(b)-8] }, io.ErrUnexpectedEOF},
		{"compressed byte", func(b []byte) []byte { return append(b, 1) }, io.ErrUnexpectedEOF},
		{"compressed junk", func(b []byte) []byte { return append(b, []byte("not a gzip member")...) }, gzip.ErrHeader},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := test.mutate(bytes.Clone(valid))
			entries, err := GzipHeaders(content, int64(len(content)), nil)
			if !errors.Is(err, test.want) || entries != nil {
				t.Fatalf("terminal framing: entries=%v err=%v want=%v", entries, err, test.want)
			}
		})
	}
}

func TestSingleTarFramingPreservesZeroPaddingAndGzipMembers(t *testing.T) {
	raw := framedTar(t)
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{"plain", gzipBytes(t, raw)},
		{"optional tar terminator", gzipBytes(t, raw[:len(raw)-1024])},
		{"single tar zero block", gzipBytes(t, raw[:len(raw)-512])},
		{"zero padding", gzipBytes(t, append(bytes.Clone(raw), make([]byte, 4096)...))},
		{"zero member", append(gzipBytes(t, raw), gzipBytes(t, make([]byte, 4096))...)},
		{"split member", append(gzipBytes(t, raw[:700]), gzipBytes(t, raw[700:])...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries, err := GzipHeaders(test.content, int64(len(test.content)), nil)
			if err != nil || len(entries) != 1 || entries[0].Name != "package/data" {
				t.Fatalf("valid framing: entries=%v err=%v", entries, err)
			}
		})
	}
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{"nonzero", gzipBytes(t, append(bytes.Clone(raw), 1))},
		{"hidden tar", gzipBytes(t, append(bytes.Clone(raw), raw...))},
		{"hidden member", append(gzipBytes(t, raw), gzipBytes(t, raw)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries, err := GzipHeaders(test.content, int64(len(test.content)), nil)
			if err == nil || !strings.Contains(err.Error(), "after tar terminator") || entries != nil {
				t.Fatalf("hidden payload: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestRegularEntriesFormOneFileTree(t *testing.T) {
	for _, test := range []struct {
		name  string
		names []string
		want  bool
	}{
		{"siblings", []string{"package/a", "package/a-b", "package/b/child"}, true},
		{"ancestor before", []string{"package/a", "package/a-b", "package/a/child"}, false},
		{"ancestor after", []string{"package/a/child", "package/a-b", "package/a"}, false},
		{"root delimiter", []string{"package/a", "packagex/a"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var raw []byte
			for _, name := range test.names {
				raw = append(raw, headerBytes(t, tar.Header{Name: name})...)
			}
			raw = append(raw, make([]byte, 1024)...)
			content := gzipBytes(t, raw)
			entries, err := GzipHeaders(content, int64(len(content)), nil)
			if (err == nil) != test.want || test.want && len(entries) != len(test.names) || !test.want && entries != nil {
				t.Fatalf("regular file tree: entries=%v err=%v want=%v", entries, err, test.want)
			}
		})
	}
}

func TestTailSharesInclusiveExpandedBudget(t *testing.T) {
	content := append(framedTar(t), make([]byte, 4096)...)
	for _, extra := range []int{0, 1} {
		reader := bytes.NewReader(append(bytes.Clone(content), make([]byte, extra)...))
		entries, err := BoundedHeaders(reader, int64(len(content)), 10, nil)
		if extra == 0 {
			if err != nil || len(entries) != 1 || reader.Len() != 0 {
				t.Fatalf("inclusive tail: entries=%v err=%v unread=%d", entries, err, reader.Len())
			}
		} else if err == nil || !strings.Contains(err.Error(), "expanded byte limit") || entries != nil {
			t.Fatalf("tail overflow: entries=%v err=%v", entries, err)
		}
	}
}

func TestBodyVisitorPreservesUnreadPayloadAndEntryOrder(t *testing.T) {
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, name := range []string{"package/first", "package/second"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Size: 3}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, take := range []int{1, 3} {
		var observed []string
		entries, err := BoundedEntries(bytes.NewReader(raw.Bytes()), int64(raw.Len()), 2, nil, func(entry Entry, body io.Reader) error {
			content := make([]byte, take)
			if _, err := io.ReadFull(body, content); err != nil {
				return err
			}
			if string(content) != "abc"[:take] {
				t.Fatalf("visitor payload=%q", content)
			}
			observed = append(observed, entry.Name)
			return nil
		})
		if err != nil || len(entries) != 2 || strings.Join(observed, ",") != "package/first,package/second" {
			t.Fatalf("visitor traversal: take=%d entries=%v observed=%v err=%v", take, entries, observed, err)
		}
	}
}

func TestBodyVisitorErrorsAndAdmissionPrecedePayload(t *testing.T) {
	want := errors.New("visitor refusal")
	for _, invalidHeader := range []bool{false, true} {
		name := "package/data"
		if invalidHeader {
			name = "packagex/data"
		}
		body := &forbiddenBody{}
		visited := false
		reader := io.MultiReader(bytes.NewReader(headerBytes(t, tar.Header{Name: name, Size: 1})), body)
		entries, err := BoundedEntries(reader, 4096, 10, nil, func(Entry, io.Reader) error {
			visited = true
			return want
		})
		if entries != nil || body.read || visited == invalidHeader || invalidHeader && err == nil || !invalidHeader && !errors.Is(err, want) {
			t.Fatalf("visitor admission: invalid=%v visited=%v bodyRead=%v entries=%v err=%v", invalidHeader, visited, body.read, entries, err)
		}
	}
}
