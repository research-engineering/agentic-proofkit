package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyWheelRecordBindsEveryWrapperSource(t *testing.T) {
	manifest := testPackageManifest("1.2.3")
	for _, target := range releaseTargets() {
		for _, changed := range []string{"", "__init__.py", "__main__.py", "cli.py"} {
			name := changed
			if name == "" {
				name = "unchanged"
			}
			t.Run(target.PlatformSuffix+"/"+name, func(t *testing.T) {
				root := t.TempDir()
				binaryContent := wrapperSourceTargetHeader(t, target)
				for relative, content := range map[string][]byte{
					"python/agentic_proofkit/__init__.py": []byte("# original init\n"),
					"python/agentic_proofkit/__main__.py": []byte("# original main\n"),
					"python/agentic_proofkit/cli.py":      []byte("# original cli\n"),
					sourceCLIContractPath:                 []byte(testCLIContractContent),
					licenseFilename:                       []byte(testLicenseContent),
					target.BinaryPath:                     binaryContent,
				} {
					absolute := filepath.Join(root, filepath.FromSlash(relative))
					if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(absolute, content, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				withWorkingDirectory(t, root, func() {
					entries, err := wheelEntries(manifest, target, binaryContent)
					if err != nil {
						t.Fatal(err)
					}
					if changed != "" {
						found := false
						for index := range entries {
							if entries[index].Path == "agentic_proofkit/"+changed {
								entries[index].Content = []byte("raise SystemExit(77)\n")
								found = true
							}
						}
						if !found {
							t.Fatal("mutation did not change a wrapper")
						}
						last := len(entries) - 1
						entries[last].Content = recordContent(entries[:last], entries[last].Path)
					}
					filename := wheelFilename(manifest.Version, target)
					wheelPath := filepath.Join("artifacts", "pypi", filename)
					if err := os.MkdirAll(filepath.Dir(wheelPath), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := writeWheel(wheelPath, entries); err != nil {
						t.Fatal(err)
					}
					digest, err := fileSHA256(wheelPath)
					if err != nil {
						t.Fatal(err)
					}
					record := wheelRecord{
						AbiTag: abiTag, BinarySha256: binarySHA256(binaryContent), Filename: filename,
						Name: packageName, PlatformSuffix: target.PlatformSuffix, PlatformTag: target.PlatformTag,
						PythonTag: pythonTag, Sha256: digest, Version: manifest.Version, WheelTag: target.WheelTag,
					}
					wheel, err := verifyWheelRecord(manifest, target, record)
					if changed == "" {
						if err != nil || len(wheel) == 0 {
							t.Fatalf("unchanged wheel rejected: %v", err)
						}
					} else if err == nil || wheel != nil || !strings.Contains(err.Error(), "wheel wrapper differs from current source") {
						t.Fatalf("changed wrapper admitted or rejected for the wrong predicate: wheelBytes=%d err=%v", len(wheel), err)
					}
				})
			})
		}
	}
}

// Format headers exercise source equality for every release target without
// executing a synthetic or foreign-platform program.
func wrapperSourceTargetHeader(t *testing.T, target target) []byte {
	t.Helper()
	if target.GOOS == "darwin" {
		content := macho64WithMinimumMacOS(13, 0, 0)
		if target.GOARCH == "amd64" {
			binary.LittleEndian.PutUint32(content[4:8], 0x01000007)
		}
		return content
	}
	content := make([]byte, 64)
	copy(content, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(content[16:18], 2)
	machine := uint16(62)
	if target.GOARCH == "arm64" {
		machine = 183
	} else if target.GOARCH != "amd64" {
		t.Fatalf("unsupported fixture architecture %q", target.GOARCH)
	}
	binary.LittleEndian.PutUint16(content[18:20], machine)
	binary.LittleEndian.PutUint32(content[20:24], 1)
	binary.LittleEndian.PutUint16(content[52:54], 64)
	return content
}
