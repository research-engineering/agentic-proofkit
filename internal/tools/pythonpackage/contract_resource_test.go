package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
)

// The wheel builder and verifier read the source contract under the bound of
// the installed contract readers, so neither embeds nor compares a contract
// those readers refuse.
func TestWheelBuildAndVerifyReadSourceContractUnderMaximumContractBytes(t *testing.T) {
	manifest := testPackageManifest("1.2.3")
	target := releaseTargets()[2]
	binary := []byte("binary")
	wheel := []byte("not a wheel")
	wheelSHA := sha256.Sum256(wheel)
	binarySHA := sha256.Sum256(binary)
	record := wheelRecord{
		AbiTag:       abiTag,
		BinarySha256: hex.EncodeToString(binarySHA[:]),
		Filename:     wheelFilename(manifest.Version, target),
		Name:         packageName,
		PlatformTag:  target.PlatformTag,
		PythonTag:    pythonTag,
		Sha256:       hex.EncodeToString(wheelSHA[:]),
		Version:      manifest.Version,
		WheelTag:     target.WheelTag,
	}
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(installedclicontract.MaximumContractBytes+extra), func(t *testing.T) {
			root := t.TempDir()
			contract := bytes.Repeat([]byte(" "), installedclicontract.MaximumContractBytes+extra)
			for path, content := range map[string][]byte{
				"python/agentic_proofkit/__init__.py":               []byte("init"),
				"python/agentic_proofkit/__main__.py":               []byte("main"),
				"python/agentic_proofkit/cli.py":                    []byte("cli"),
				sourceCLIContractPath:                               contract,
				licenseFilename:                                     []byte(testLicenseContent),
				target.BinaryPath:                                   binary,
				filepath.Join("artifacts", "pypi", record.Filename): wheel,
			} {
				absolute := filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(absolute, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var entries []wheelEntry
			var buildErr, verifyErr error
			withWorkingDirectory(t, root, func() {
				entries, buildErr = wheelEntries(manifest, target, binary)
				_, verifyErr = verifyWheelRecord(manifest, target, record)
			})
			if extra == 1 {
				if buildErr == nil || entries != nil {
					t.Fatalf("builder embedded a contract over the bound: %v", buildErr)
				}
				if verifyErr == nil || !strings.HasPrefix(verifyErr.Error(), "read source CLI contract:") {
					t.Fatalf("verifier read a contract over the bound: %v", verifyErr)
				}
				return
			}
			if buildErr != nil || !slices.ContainsFunc(entries, func(entry wheelEntry) bool {
				return entry.Path == embeddedCLIContractPath && bytes.Equal(entry.Content, contract)
			}) {
				t.Fatalf("builder refused or dropped an exact-bound contract: %v", buildErr)
			}
			// The fixture wheel is not a zip, so the verifier must fail after the
			// contract read, not at it.
			if verifyErr == nil || strings.HasPrefix(verifyErr.Error(), "read source CLI contract:") {
				t.Fatalf("verifier refused an exact-bound contract: %v", verifyErr)
			}
		})
	}
}

func TestWheelContractResourceLimitDoesNotRaiseOtherEntryLimits(t *testing.T) {
	for _, test := range []struct {
		path  string
		limit int
	}{
		{embeddedCLIContractPath, 8 << 20},
		{"agentic_proofkit/cli.py", 1 << 20},
		{"agentic_proofkit/proofkit/other.json", 1 << 20},
		{"agentic_proofkit/proofkit/cli-contract.v2.json.extra", 1 << 20},
	} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", test.path, extra), func(t *testing.T) {
				var buffer bytes.Buffer
				writer := zip.NewWriter(&buffer)
				entry, err := writer.Create(test.path)
				if err != nil {
					t.Fatal(err)
				}
				content := bytes.Repeat([]byte(" "), test.limit+extra)
				if _, err := entry.Write(content); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
				if err != nil {
					t.Fatal(err)
				}
				got, err := readZipFile(reader.File[0])
				if extra == 1 {
					if err == nil || got != nil {
						t.Fatal("one-over entry returned bytes")
					}
				} else if err != nil || !bytes.Equal(got, content) {
					t.Fatalf("exact-bound entry failed: %v", err)
				}
			})
		}
	}
	if maximumWheelEntryBytes("agentic_proofkit/bin/agentic-proofkit") != 64<<20 || installedclicontract.MaximumContractBytes != 8<<20 {
		t.Fatal("binary or contract bound differs from its explicit resource policy")
	}
}
