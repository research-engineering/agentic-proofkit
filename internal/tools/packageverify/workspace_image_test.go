package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/png"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceImageAdmission(t *testing.T) {
	t.Parallel()
	valid := workspacePNG(t, 8, 5)
	for _, content := range [][]byte{valid, workspacePNG(t, 2048, 1536)} {
		if err := verifyWorkspaceImage(content); err != nil {
			t.Fatalf("valid bounded PNG rejected: %v", err)
		}
	}
	const sentinel = "private-workspace-image-sentinel"
	cases := []struct {
		name    string
		content []byte
		want    string
	}{
		{"empty", nil, "byte bounds"},
		{"overflow", make([]byte, (2<<20)+1), "byte bounds"},
		{"invalid", []byte(sentinel), "PNG metadata"},
		{"truncated after metadata", valid[:33], "complete PNG"},
		{"corrupt payload", append(append([]byte{}, valid[:33]...), []byte(sentinel)...), "complete PNG"},
		{"width before decode", workspacePNGHeader(valid, 2049, 1), "dimension bounds"},
		{"height before decode", workspacePNGHeader(valid, 1, 1537), "dimension bounds"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := verifyWorkspaceImage(item.content)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("PNG admission did not reject the intended boundary: %v", err)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Fatal("PNG diagnostic disclosed input bytes")
			}
		})
	}
}

func TestWorkspaceImageHeaderAndInventory(t *testing.T) {
	t.Parallel()
	entry := tarEntry{Name: "package/docs/images/workspace.png", Mode: 0o644, Size: 2 << 20, Typeflag: tar.TypeReg}
	if err := verifyTarEntryHeader(entry); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*tarEntry){
		func(e *tarEntry) { e.Size = 0 },
		func(e *tarEntry) { e.Size++ },
		func(e *tarEntry) { e.Mode = 0o755 },
		func(e *tarEntry) { e.Typeflag = tar.TypeSymlink },
	} {
		invalid := entry
		mutate(&invalid)
		if err := verifyTarEntryHeader(invalid); err == nil {
			t.Fatal("invalid image header admitted")
		}
	}
	if !allowedRootEntry(entry.Name) || allowedRootEntry("package/docs/images/other.png") {
		t.Fatal("image inventory is not exact")
	}
	entries := toSet(requiredRootEntries())
	delete(entries, entry.Name)
	if err := verifyRequiredRootEntries(entries); err == nil {
		t.Fatal("package omitted its required illustration")
	}
	if err := verifyMarkdownDestinations("package/README.md", "![Workspace](docs/images/workspace.png)", entries); err == nil {
		t.Fatal("README image reference resolved without an image")
	}
}

func TestWorkspaceImageExactByteBoundary(t *testing.T) {
	t.Parallel()
	valid := workspacePNG(t, 1, 1)
	// A valid ancillary text chunk fills the payload without changing dimensions.
	payload := bytes.Repeat([]byte("x"), 2097152-len(valid)-12)
	copy(payload, "fixture\x00")
	chunk := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	chunk = append(chunk, "tEXt"...)
	chunk = append(chunk, payload...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(chunk[4:]))
	content := append(append(append([]byte{}, valid[:len(valid)-12]...), chunk...), valid[len(valid)-12:]...)
	if len(content) != 2097152 {
		t.Fatal("exact-limit fixture has the wrong byte length")
	}
	if _, err := png.Decode(bytes.NewReader(content)); err != nil {
		t.Fatalf("exact-limit fixture is not a complete PNG: %v", err)
	}
	if err := verifyWorkspaceImage(content); err != nil {
		t.Fatalf("inclusive PNG byte boundary rejected: %v", err)
	}
	if err := verifyWorkspaceImage(append(content, 0)); err == nil || !strings.Contains(err.Error(), "byte bounds") {
		t.Fatal("payload above the exact byte boundary was not rejected")
	}
}

func TestPackageVerifierImageFailureProcess(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	binaryPath := filepath.Join(t.TempDir(), "packageverify")
	build := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, "./internal/tools/packageverify")
	build.Dir = filepath.Join("..", "..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual package verifier: %v\n%s", err, output)
	}
	const sentinel = "private-image-process-sentinel"
	entries := map[string]string{}
	for _, name := range requiredRootEntries() {
		entries[name] = "fixture"
	}
	entries["package/docs/images/workspace.png"] = sentinel
	archive := mustReadBytes(t, writePackageTarball(t, entries))
	root := t.TempDir()
	const filename = "image-proof.tgz"
	writeFileBytes(t, filepath.Join(root, "artifacts/package", filename), archive)
	records, err := json.Marshal([]packRecord{{Filename: filename, Name: rootPackageName, Version: "1.2.3", Integrity: testNPMIntegrity(archive), Shasum: testSHA1(archive)}})
	if err != nil {
		t.Fatal(err)
	}
	writeFileBytes(t, filepath.Join(root, "artifacts/package/npm-pack.json"), records)
	command := exec.CommandContext(ctx, binaryPath)
	command.Dir = root
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "PNG metadata") {
		t.Fatal("actual verifier did not reject at the image boundary with failure exit and stderr only")
	}
	if bytes.Contains(stdout.Bytes(), []byte(sentinel)) || bytes.Contains(stderr.Bytes(), []byte(sentinel)) {
		t.Fatal("actual verifier disclosed image input bytes")
	}
}

func TestRootPackageDecodesImageFromArchive(t *testing.T) {
	root := t.TempDir()
	withWorkingDirectory(t, root)
	good := workspacePNG(t, 4, 3)
	// A clean source image must not hide corrupted bytes in the package.
	writeFileBytes(t, filepath.Join(root, "docs/images/workspace.png"), good)
	for _, content := range [][]byte{good, []byte("invalid archive image")} {
		entries := map[string]string{}
		for _, name := range requiredRootEntries() {
			entries[name] = "fixture"
		}
		entries["package/docs/images/workspace.png"] = string(content)
		archive := mustReadBytes(t, writePackageTarball(t, entries))
		filename := "image-proof.tgz"
		writeFileBytes(t, filepath.Join(root, "artifacts/package", filename), archive)
		_, err := verifyRootPackage(packRecord{Filename: filename, Name: rootPackageName, Version: "1.2.3", Integrity: testNPMIntegrity(archive), Shasum: testSHA1(archive)})
		if bytes.Equal(content, good) {
			if err != nil {
				t.Fatalf("valid archive image rejected: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "PNG metadata") {
			t.Fatalf("bad archive passed beside valid source: %v", err)
		}
	}
}

func FuzzWorkspaceImageAdmission(f *testing.F) {
	f.Add(workspacePNG(f, 1, 1))
	f.Add([]byte("not a PNG"))
	f.Fuzz(func(t *testing.T, content []byte) {
		if err := verifyWorkspaceImage(content); err != nil {
			return
		}
		decoded, err := png.Decode(bytes.NewReader(content))
		if err != nil || len(content) > 2<<20 {
			t.Fatal("image admitted without complete bounded PNG bytes")
		}
		bounds := decoded.Bounds()
		if bounds.Dx() < 1 || bounds.Dx() > 2048 || bounds.Dy() < 1 || bounds.Dy() > 1536 {
			t.Fatal("image admitted outside dimension bounds")
		}
	})
}

func workspacePNG(t testing.TB, width, height int) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := png.Encode(&output, image.NewNRGBA(image.Rect(0, 0, width, height))); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func workspacePNGHeader(valid []byte, width, height uint32) []byte {
	header := append([]byte{}, valid[:33]...)
	binary.BigEndian.PutUint32(header[16:20], width)
	binary.BigEndian.PutUint32(header[20:24], height)
	binary.BigEndian.PutUint32(header[29:33], crc32.ChecksumIEEE(header[12:29]))
	return header
}
