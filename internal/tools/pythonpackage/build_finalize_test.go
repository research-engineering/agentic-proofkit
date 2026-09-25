package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wheelFailureWriter struct {
	writeErr        error
	closeErr        error
	writes          int
	closes          int
	wroteAfterClose bool
}

func (writer *wheelFailureWriter) Write(data []byte) (int, error) {
	writer.writes++
	writer.wroteAfterClose = writer.wroteAfterClose || writer.closes != 0
	if writer.writeErr != nil {
		return 0, writer.writeErr
	}
	return len(data), nil
}

func (writer *wheelFailureWriter) Close() error {
	writer.closes++
	return writer.closeErr
}

func TestWriteWheelRetainsFinalizationFailures(t *testing.T) {
	writeErr := errors.New("archive write failed")
	closeErr := errors.New("file close failed")
	for _, scenario := range []struct {
		name     string
		entries  []wheelEntry
		writeErr error
		closeErr error
	}{
		{"central-directory", nil, writeErr, nil},
		{"buffered-entry-finalize", []wheelEntry{{Path: "x", Content: []byte("payload")}}, writeErr, nil},
		{"file-close", nil, nil, closeErr},
		{"both-finalizers", nil, writeErr, closeErr},
		{"body-and-close", []wheelEntry{{Path: strings.Repeat("x", 5000)}}, writeErr, closeErr},
		{"header-and-finalizers", []wheelEntry{{Path: strings.Repeat("x", 1<<16)}}, writeErr, closeErr},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			writer := &wheelFailureWriter{writeErr: scenario.writeErr, closeErr: scenario.closeErr}
			err := writeWheelTo(writer, scenario.entries)
			if err == nil {
				t.Fatal("failed output reported success")
			}
			for _, expected := range []error{scenario.writeErr, scenario.closeErr} {
				if expected != nil && !errors.Is(err, expected) {
					t.Fatalf("lost failure %v: %v", expected, err)
				}
			}
			if scenario.name == "header-and-finalizers" && !strings.Contains(err.Error(), "Name too long") {
				t.Fatalf("lost primary header failure: %v", err)
			}
			if writer.closes != 1 || writer.writes == 0 || writer.wroteAfterClose {
				t.Fatalf("invalid finalization order/count: %+v", writer)
			}
		})
	}
}

func TestWriteWheelPreservesOutputOnFailure(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "existing"}[existing], func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "candidate.whl")
			original := []byte("previous complete output")
			if existing {
				if err := os.WriteFile(path, original, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeWheel(path, []wheelEntry{{Path: strings.Repeat("x", 1<<16)}}); err == nil {
				t.Fatal("invalid header reported success")
			}
			content, err := os.ReadFile(path)
			if existing {
				if err != nil || !bytes.Equal(content, original) {
					t.Fatalf("previous output changed: %q, %v", content, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed output remains: %v", err)
			}
			assertNoWheelTemporaryFiles(t, root)
		})
	}
}

func TestWriteWheelCleansUpAfterRenameFailure(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "candidate.whl")
	if err := os.Mkdir(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeWheel(destination, nil); err == nil {
		t.Fatal("rename over directory reported success")
	}
	info, err := os.Stat(destination)
	if err != nil || !info.IsDir() {
		t.Fatalf("destination directory changed: %v", err)
	}
	assertNoWheelTemporaryFiles(t, root)
}

func TestWriteWheelFinalizedRoundtripIsDeterministic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "candidate.whl")
	entries := []wheelEntry{
		{Path: "module.py", Content: []byte("value = 1\n"), Mode: 0o644},
		{Path: "bin/tool", Content: []byte("executable"), Mode: 0o755},
	}
	var previous []byte
	for iteration := 0; iteration < 2; iteration++ {
		if err := writeWheel(path, entries); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if iteration != 0 && !bytes.Equal(previous, content) {
			t.Fatal("wheel bytes changed across identical builds")
		}
		if iteration != 0 {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("replacement changed existing wheel permissions: info=%v error=%v", info, err)
			}
		}
		previous = content
		archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if len(archive.File) != len(entries) {
			t.Fatal("wheel inventory changed")
		}
		for index, file := range archive.File {
			expected := entries[index]
			if file.Name != expected.Path || file.Mode().Perm() != expected.Mode {
				t.Fatalf("entry metadata changed: %s %v", file.Name, file.Mode())
			}
			reader, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			actual, readErr := io.ReadAll(reader)
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil || !bytes.Equal(actual, expected.Content) {
				t.Fatalf("entry content changed: read=%v close=%v", readErr, closeErr)
			}
		}
		assertNoWheelTemporaryFiles(t, root)
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoWheelTemporaryFiles(t *testing.T, root string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, ".wheel-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary output remains: %v, %v", files, err)
	}
}
