//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The wheel at the expected path must be admitted through one bounded
// regular-file read: a FIFO is rejected without waiting for a writer.
func TestVerifyWheelRecordRejectsFIFOWheelWithoutWriter(t *testing.T) {
	native, err := currentTarget()
	if err != nil {
		t.Skip(err)
	}
	t.Chdir(t.TempDir())
	const version = "1.2.3"
	record := wheelRecord{
		AbiTag: abiTag, Filename: wheelFilename(version, native), Name: packageName, PlatformTag: native.PlatformTag,
		PythonTag: pythonTag, Version: version, WheelTag: native.WheelTag,
	}
	if err := os.MkdirAll(filepath.Join("artifacts", "pypi"), 0o700); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join("artifacts", "pypi", record.Filename)
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := verifyWheelRecord(packageJSON{Version: version}, native, record)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "read bounded wheel") {
			t.Fatalf("verifyWheelRecord() error = %v, want bounded wheel admission rejection", err)
		}
	case <-time.After(10 * time.Second):
		if writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			writer.Close()
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		t.Fatal("verifyWheelRecord waited for a FIFO writer before bounded wheel admission")
	}
}

// Installed CLI probes parse stdout only: help written to stderr with exit 0
// must not be observed as the same bytes as help written to stdout.
func TestRunArgvWithEnvironmentDistinguishesStdoutFromStderr(t *testing.T) {
	environment := pythonVerificationEnvironment(os.Environ(), nil)
	help := "Discover command families:\n  agentic-proofkit help families\n"
	output, err := runArgvWithEnvironment("", environment, []string{"/bin/sh", "-c", `printf '%s' "$0"`, help})
	if err != nil || string(output) != help {
		t.Fatalf("stdout help = %q, %v; want exact stdout", output, err)
	}
	output, err = runArgvWithEnvironment("", environment, []string{"/bin/sh", "-c", `printf '%s' "$0" >&2`, help})
	if err == nil {
		t.Fatalf("stderr-only help observed as success: output=%q", output)
	}
	output, err = runArgvWithEnvironment("", environment, []string{"/bin/sh", "-c", `printf '%s' "$0"; printf 'warning\n' >&2`, help})
	if err == nil {
		t.Fatalf("successful CLI probe with stderr bytes was accepted: output=%q", output)
	}
}
