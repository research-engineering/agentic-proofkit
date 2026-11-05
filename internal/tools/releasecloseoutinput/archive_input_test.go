package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/packagearchive"
)

func TestWheelCriterionRejectsUnsafeNonBinaryEntries(t *testing.T) {
	const entryLimit = 4096
	regular := func(name string) zip.FileHeader {
		header := zip.FileHeader{Name: name, Method: zip.Store}
		header.SetMode(0o644)
		return header
	}
	extra := regular("agentic_proofkit/extra.py")
	symlink := extra
	symlink.SetMode(os.ModeSymlink | 0o777)
	// The fixture adds one executable member; all other entries are unique.
	bounded := make([]zip.FileHeader, entryLimit)
	for i := range bounded {
		bounded[i] = regular(fmt.Sprintf("agentic_proofkit/data/%d", i))
	}
	for _, test := range []struct {
		name, want string
		extras     []zip.FileHeader
	}{
		{"regular", "satisfied", []zip.FileHeader{extra}},
		{"symlink", "missing_evidence", []zip.FileHeader{symlink}},
		{"noncanonical", "missing_evidence", []zip.FileHeader{regular("agentic_proofkit//extra.py")}},
		{"file ancestor", "missing_evidence", []zip.FileHeader{regular("agentic_proofkit/bin")}},
		{"duplicate non-binary", "missing_evidence", []zip.FileHeader{extra, extra}},
		{"exact entry limit", "satisfied", bounded[:entryLimit-1]},
		{"over entry limit", "missing_evidence", bounded},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			wheel, binary := writePythonWheelFixture(t, root, test.extras...)
			writeJSON(t, filepath.Join(root, "artifacts/pypi/python-packages.json"), map[string]any{
				"packageName": testPythonPackageName, "packageVersion": "1.2.3",
				"packages": []any{map[string]any{"binarySha256": binary, "filename": testPythonWheelName, "name": testPythonPackageName, "sha256": wheel, "version": "1.2.3"}},
			})
			result, _ := pythonArtifactCriterion(root, packageJSON{Version: "1.2.3"})
			if result.Status != test.want {
				t.Fatalf("wheel topology criterion = %q, want %q", result.Status, test.want)
			}
		})
	}
}

// Literal owner expectations avoid using the production platform projection as
// both fixture generator and the only acceptance oracle.
func npmArchiveHeaders() []tar.Header {
	names := []string{
		"package/dist/platform/darwin-arm64/agentic-proofkit",
		"package/dist/platform/darwin-x64/agentic-proofkit",
		"package/dist/platform/linux-arm64/agentic-proofkit",
		"package/dist/platform/linux-x64/agentic-proofkit",
	}
	headers := []tar.Header{{Name: "package/package.json", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}}
	for _, name := range names {
		headers = append(headers, tar.Header{Name: name, Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})
	}
	return headers
}

func npmArchive(t *testing.T, headers []tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	gzipWriter := gzip.NewWriter(&out)
	writer := tar.NewWriter(gzipWriter)
	for _, header := range headers {
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := io.CopyN(writer, npmZeroStream{}, header.Size); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestValidPackRecordsRejectsHashMatchingMalformedArchives(t *testing.T) {
	duplicate := npmArchiveHeaders()
	duplicate = append(duplicate, duplicate[0])
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{"raw bytes", []byte("package")},
		{"duplicate", npmArchive(t, duplicate)},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeNPMArtifact(t, root, testNPMTarballName, test.content)
			if _, ok := verifyPackRecords(root, filepath.Join("artifacts", "package", "npm-pack.json"), packageJSON{Name: testNPMPackageName, Version: "1.2.3"}); ok {
				t.Fatal("malformed archive admitted with matching outer hashes")
			}
		})
	}
}

func TestValidPackRecordsRequiresCompleteSingleArchive(t *testing.T) {
	valid := npmArchive(t, npmArchiveHeaders())
	reader, err := gzip.NewReader(bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	crc := bytes.Clone(valid)
	crc[len(crc)-8] ^= 1
	size := bytes.Clone(valid)
	size[len(size)-4] ^= 1
	for _, test := range []struct {
		name    string
		content []byte
		want    bool
	}{
		{"valid", valid, true},
		{"optional tar terminator", gzipArchiveBytes(t, raw[:len(raw)-1024]), true},
		{"single tar zero block", gzipArchiveBytes(t, raw[:len(raw)-512]), true},
		{"extra package file", npmArchive(t, append(npmArchiveHeaders(), tar.Header{Name: "package/extra", Mode: 0o644, Typeflag: tar.TypeReg})), true},
		{"zero padding", gzipArchiveBytes(t, append(bytes.Clone(raw), make([]byte, 4096)...)), true},
		{"zero member", append(bytes.Clone(valid), gzipArchiveBytes(t, make([]byte, 4096))...), true},
		{"split member", append(gzipArchiveBytes(t, raw[:777]), gzipArchiveBytes(t, raw[777:])...), true},
		{"crc", crc, false},
		{"size", size, false},
		{"footer byte", valid[:len(valid)-1], false},
		{"footer", valid[:len(valid)-8], false},
		{"compressed byte", append(bytes.Clone(valid), 1), false},
		{"compressed junk", append(bytes.Clone(valid), []byte("not a gzip member")...), false},
		{"decoded data", gzipArchiveBytes(t, append(bytes.Clone(raw), 1)), false},
		{"hidden tar", gzipArchiveBytes(t, append(bytes.Clone(raw), raw...)), false},
		{"hidden member", append(bytes.Clone(valid), valid...), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			// Every structural negative has independently recomputed outer hashes.
			writeNPMArtifact(t, root, testNPMTarballName, test.content)
			_, got := verifyPackRecords(root, "artifacts/package/npm-pack.json", packageJSON{Name: testNPMPackageName, Version: "1.2.3"})
			if got != test.want {
				t.Fatalf("complete single archive admitted=%v want=%v", got, test.want)
			}
		})
	}
}

func TestCloseoutNPMArchiveTopology(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]tar.Header) []tar.Header
	}{
		{"traversal", func(h []tar.Header) []tar.Header { h[0].Name = "package/../escape"; return h }},
		{"file ancestor before", func(h []tar.Header) []tar.Header {
			return append([]tar.Header{{Name: "package/dist", Mode: 0o644, Typeflag: tar.TypeReg}}, h...)
		}},
		{"file ancestor after", func(h []tar.Header) []tar.Header {
			return append(h, tar.Header{Name: "package/dist", Mode: 0o644, Typeflag: tar.TypeReg})
		}},
		{"root alias", func(h []tar.Header) []tar.Header {
			e := h[1]
			e.Name = "packagex/dist/platform/darwin-arm64/agentic-proofkit"
			return append(h, e)
		}},
		{"absolute", func(h []tar.Header) []tar.Header { h[0].Name = "/escape"; return h }},
		{"backslash", func(h []tar.Header) []tar.Header { h[0].Name = `package\escape`; return h }},
		{"noncanonical", func(h []tar.Header) []tar.Header { h[0].Name = "package/./data"; return h }},
		{"symlink", func(h []tar.Header) []tar.Header {
			h[0].Typeflag = tar.TypeSymlink
			h[0].Size = 0
			h[0].Linkname = "target"
			return h
		}},
		{"hardlink", func(h []tar.Header) []tar.Header {
			h[0].Typeflag = tar.TypeLink
			h[0].Size = 0
			h[0].Linkname = "target"
			return h
		}},
		{"directory", func(h []tar.Header) []tar.Header { h[0].Typeflag = tar.TypeDir; h[0].Size = 0; return h }},
		{"fifo member", func(h []tar.Header) []tar.Header { h[0].Typeflag = tar.TypeFifo; h[0].Size = 0; return h }},
		{"duplicate binary", func(h []tar.Header) []tar.Header { return append(h, h[1]) }},
		{"extra platform", func(h []tar.Header) []tar.Header {
			e := h[1]
			e.Name = "package/dist/platform/windows-x64/agentic-proofkit"
			return append(h, e)
		}},
		{"extra platform file", func(h []tar.Header) []tar.Header { e := h[1]; e.Name += ".extra"; return append(h, e) }},
		{"platform namespace file", func(h []tar.Header) []tar.Header { e := h[0]; e.Name = "package/dist/platform"; return append(h, e) }},
		{"empty binary", func(h []tar.Header) []tar.Header { h[1].Size = 0; return h }},
		{"non executable binary", func(h []tar.Header) []tar.Header { h[1].Mode = 0o644; return h }},
	}
	for i := 1; i <= 4; i++ {
		tests = append(tests, struct {
			name   string
			mutate func([]tar.Header) []tar.Header
		}{fmt.Sprintf("missing platform %d", i), func(h []tar.Header) []tar.Header { return append(h[:i], h[i+1:]...) }})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := completeFixture(t)
			// Only the final archive changes; its external claims are recomputed.
			writeNPMArtifact(t, root, testNPMTarballName, npmArchive(t, test.mutate(npmArchiveHeaders())))
			input, err := buildInput(root)
			if err != nil {
				t.Fatal(err)
			}
			assertCriterionStatus(t, input, "proofkit.release_closeout.package_artifacts", "missing_evidence")
			assertCloseoutOutcome(t, input, 1, "failed")
			assertFailedRule(t, input, "proofkit.release_closeout.package_artifacts")
		})
	}
}

func TestCloseoutNPMArchiveCardinality(t *testing.T) {
	for _, count := range []int{4096, 4097} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			headers := npmArchiveHeaders()
			for len(headers) < count {
				headers = append(headers, tar.Header{Name: fmt.Sprintf("package/data-%d", len(headers)), Mode: 0o644, Typeflag: tar.TypeReg})
			}
			content := npmArchive(t, headers)
			root := t.TempDir()
			writeNPMArtifact(t, root, testNPMTarballName, content)
			_, got := verifyPackRecords(root, "artifacts/package/npm-pack.json", packageJSON{Name: testNPMPackageName, Version: "1.2.3"})
			if got != (count == 4096) {
				t.Fatalf("entry count %d admitted=%v", count, got)
			}
		})
	}
}

func TestBuildInputRejectsUnadmittedNPMArchiveSubjects(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"outside symlink to identical bytes", func(t *testing.T, root string) {
			path := filepath.Join(root, "artifacts", "package", testNPMTarballName)
			target := filepath.Join(t.TempDir(), testNPMTarballName)
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"regular malformed archive with matching checksums", func(t *testing.T, root string) {
			writeNPMArtifact(t, root, testNPMTarballName, []byte("not a gzip archive"))
			packagePaths := []string{"artifacts/package/" + testNPMTarballName, "artifacts/pypi/" + testPythonWheelName}
			writeChecksumFile(t, root, "artifacts/release/sbom-subjects.sha256", packagePaths)
			writeCloseoutArchiveChecksums(t, root)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := completeFixture(t)
			test.mutate(t, root)
			input, err := buildInput(root)
			if err != nil {
				t.Fatal(err)
			}
			assertCriterionStatus(t, input, "proofkit.release_closeout.package_artifacts", "missing_evidence")
			assertCloseoutOutcome(t, input, 1, "failed")
			assertCriterionStatus(t, input, "proofkit.release_closeout.manifest_and_sbom", "missing_evidence")
		})
	}
}

func TestCloseoutNPMEntrySizeBoundaries(t *testing.T) {
	for _, test := range []struct {
		name string
		size int64
	}{
		{"entry", 128 << 20},
		{"binary", 64 << 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, delta := range []int64{0, 1} {
				headers := npmArchiveHeaders()
				if test.name == "binary" {
					headers[1].Size = test.size + delta
				} else {
					headers = append(headers, tar.Header{Name: "package/data", Mode: 0o644, Size: test.size + delta, Typeflag: tar.TypeReg})
				}
				root := t.TempDir()
				writeNPMArtifact(t, root, testNPMTarballName, npmArchive(t, headers))
				_, got := verifyPackRecords(root, "artifacts/package/npm-pack.json", packageJSON{Name: testNPMPackageName, Version: "1.2.3"})
				if got != (delta == 0) {
					t.Fatalf("entry size %d admitted=%v", test.size+delta, got)
				}
			}
		})
	}
}

func TestCloseoutNPMRejectsInvalidCompressedInputs(t *testing.T) {
	for _, content := range [][]byte{nil, []byte("package"), gzipArchiveBytes(t, []byte("package")), gzipArchiveBytes(t, make([]byte, 1024))} {
		root := t.TempDir()
		writeNPMArtifact(t, root, testNPMTarballName, content)
		if _, ok := verifyPackRecords(root, "artifacts/package/npm-pack.json", packageJSON{Name: testNPMPackageName, Version: "1.2.3"}); ok {
			t.Fatal("non-package archive admitted")
		}
	}
	root := t.TempDir()
	content := npmArchive(t, npmArchiveHeaders())
	writeNPMArtifact(t, root, testNPMTarballName, content)
	record := packRecord{Filename: testNPMTarballName, Shasum: testSHA1(content), Integrity: testNPMIntegrity(content)}
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		if subjects, err := verifyPackRecordBytesWithin(root, record, limit); err == nil || subjects != nil {
			t.Fatalf("invalid limit %d admitted", limit)
		}
	}
	file, err := os.OpenFile(filepath.Join(root, "artifacts", "package", testNPMTarballName), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxNPMTarballBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if subjects, err := verifyPackRecordBytesWithin(root, record, maxNPMTarballBytes); err == nil || subjects != nil {
		t.Fatal("oversized compressed file admitted")
	}
}

func gzipArchiveBytes(t *testing.T, content []byte) []byte {
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

type npmZeroStream struct{}

func (npmZeroStream) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func TestCloseoutNPMExpandedBoundary(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(fmt.Sprint(overflow), func(t *testing.T) {
			var out bytes.Buffer
			gzipWriter, err := gzip.NewWriterLevel(&out, gzip.BestSpeed)
			if err != nil {
				t.Fatal(err)
			}
			writer := tar.NewWriter(gzipWriter)
			headers := npmArchiveHeaders()
			for i := 0; i < 4; i++ {
				size := int64(128 << 20)
				if i == 3 {
					// Five small fixture members use 5120 bytes; four data
					// headers and the tar terminator use another 3072.
					size -= 8192
					if overflow {
						size++
					}
				}
				headers = append(headers, tar.Header{Name: fmt.Sprintf("package/expanded-%d", i), Mode: 0o644, Typeflag: tar.TypeReg, Size: size})
			}
			for _, header := range headers {
				if err := writer.WriteHeader(&header); err != nil {
					t.Fatal(err)
				}
				if _, err := io.CopyN(writer, npmZeroStream{}, header.Size); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gzipWriter.Close(); err != nil {
				t.Fatal(err)
			}
			content := out.Bytes()
			root := t.TempDir()
			writeNPMArtifact(t, root, testNPMTarballName, content)
			_, got := verifyPackRecords(root, "artifacts/package/npm-pack.json", packageJSON{Name: testNPMPackageName, Version: "1.2.3"})
			if got == overflow {
				t.Fatalf("512 MiB expanded boundary: overflow=%v admitted=%v", overflow, got)
			}
			if !overflow {
				reader, err := gzip.NewReader(bytes.NewReader(content))
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				n, err := io.Copy(io.Discard, reader)
				if err != nil || n != int64(packagearchive.MaxExpandedBytes) {
					t.Fatalf("independent expanded length=%d err=%v", n, err)
				}
			}
		})
	}
}
