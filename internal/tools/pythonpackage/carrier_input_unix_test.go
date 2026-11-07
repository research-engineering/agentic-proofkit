//go:build darwin || linux

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWheelCarrierConsumersRejectFIFO(t *testing.T) {
	const packageSetPath = "artifacts/pypi/python-packages.json"
	manifest := testPackageManifest("1.2.3")
	native := releaseTargets()[0]
	build := func() error { _, err := buildWheel(".", manifest, native); return err }
	const wrapperPath = "python/agentic_proofkit/__init__.py"
	wheelPath := filepath.Join("artifacts/pypi", wheelFilename(manifest.Version, native))
	wheel := []byte("wheel bytes bound before archive inspection")
	verify := func() error {
		_, err := verifyWheelRecord(manifest, native, wheelRecord{
			Name: packageName, Version: manifest.Version, Filename: filepath.Base(wheelPath),
			PythonTag: pythonTag, AbiTag: abiTag, PlatformTag: native.PlatformTag, WheelTag: native.WheelTag,
			Sha256: fmt.Sprintf("%x", sha256.Sum256(wheel)),
		})
		return err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, path, context string
		consume             func() error
	}{
		{"package set", packageSetPath, "read " + packageSetPath, func() error { return verifyPythonPackagesForTargets([]target{native}) }},
		{"build binary", native.BinaryPath, "read platform binary", build},
		{"verify binary", native.BinaryPath, "read platform binary", verify},
		{"build license", licenseFilename, "read " + licenseFilename, build},
		{"build wrapper", wrapperPath, "read wheel source " + wrapperPath, build},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			for path, content := range map[string][]byte{
				"package.json": manifestBytes, native.BinaryPath: []byte("binary fixture"), wheelPath: wheel,
				licenseFilename: []byte(testLicenseContent), sourceCLIContractPath: []byte(testCLIContractContent),
				wrapperPath: []byte("# fixture\n"), "python/agentic_proofkit/__main__.py": []byte("# fixture\n"),
				"python/agentic_proofkit/cli.py": []byte("# fixture\n"),
			} {
				if path == test.path {
					continue
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Dir(test.path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(test.path, 0o600); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- test.consume() }()
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), test.context) || !strings.Contains(err.Error(), "artifact source must be a regular non-symlink file") {
					t.Fatalf("wheel carrier refusal = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("wheel carrier reader blocked on a FIFO")
			}
		})
	}
}
