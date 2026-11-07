package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const fixtureVersion = "1.2.3"
const fixtureNPMName = "@research-engineering/agentic-proofkit"
const fixtureSBOMPath = "artifacts/release/sbom.cdx.json"

func fileSHA256(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func writeJSON(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o644)
}

type fixtureSBOMComponent struct {
	Type       string              `json:"type"`
	BOMRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	Properties []map[string]string `json:"properties,omitempty"`
	Hashes     []map[string]string `json:"hashes,omitempty"`
}

func fixtureSBOMComponents(t *testing.T, records []packRecord, packages *pythonPackageSet) []fixtureSBOMComponent {
	t.Helper()
	subject := func(path, kind, digest string) fixtureSBOMComponent {
		return fixtureSBOMComponent{
			Type: kind, BOMRef: "file:" + path, Name: filepath.Base(path), Version: fixtureVersion,
			Properties: []map[string]string{{"name": "proofkit:path", "value": path}},
			Hashes:     []map[string]string{{"alg": "SHA-256", "content": digest}},
		}
	}
	components := []fixtureSBOMComponent{
		{Type: "library", BOMRef: "go-module:example.test/module@v1.0.0", Name: "example.test/module", Version: "v1.0.0"},
	}
	for _, target := range releaseplatform.Targets() {
		digest := sha256.Sum256(carrierBinary(target.PlatformSuffix))
		components = append(components, subject(target.BinaryPath, "file", fmt.Sprintf("%x", digest)))
	}
	for _, path := range expectedPackageArtifactPaths(records, packages) {
		digest, err := fileSHA256(path)
		if err != nil {
			t.Fatal(err)
		}
		components = append(components, subject(filepath.ToSlash(path), "application", digest))
	}
	return components
}

func writeFixtureSBOM(t *testing.T, components []fixtureSBOMComponent) {
	t.Helper()
	if err := writeJSON(fixtureSBOMPath, map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseManifestConfinesMetadataOutput(t *testing.T) {
	for _, name := range []string{"checksums.sha256", "sbom-subjects.sha256", "release-manifest.json", "release-notes.md", "metadata-checksums.sha256"} {
		t.Run(name, func(t *testing.T) {
			writeReleaseManifestFixture(t, false)
			if err := run(); err != nil {
				t.Fatalf("ordinary manifest output: %v", err)
			}
			output := filepath.Join("artifacts", "release", name)
			want, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if name == "metadata-checksums.sha256" {
				manifest, err := fileSHA256("artifacts/release/release-manifest.json")
				if err != nil {
					t.Fatal(err)
				}
				notes, err := fileSHA256("artifacts/release/release-notes.md")
				if err != nil {
					t.Fatal(err)
				}
				expected := fmt.Sprintf("%s  release-manifest.json\n%s  release-notes.md\n", manifest, notes)
				if string(want) != expected {
					t.Fatalf("metadata checksums = %q; want %q", want, expected)
				}
			}
			if info, err := os.Lstat(output); err != nil || info.Mode() != 0o600 {
				t.Fatalf("ordinary metadata output permissions: %v, %v", info, err)
			}
			if err := os.Remove(output); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(t.TempDir(), "unrelated.txt")
			writeFile(t, sentinel, "unrelated bytes")
			if err := os.Symlink(sentinel, output); err != nil {
				t.Fatal(err)
			}
			if err := run(); err == nil || !strings.Contains(err.Error(), "write "+name+": artifact destination must be a regular non-symlink file") {
				t.Fatalf("unsafe metadata output = %v", err)
			}
			if content, err := os.ReadFile(sentinel); err != nil || string(content) != "unrelated bytes" {
				t.Fatalf("unrelated file changed: %q, %v", content, err)
			}
			if err := os.Remove(output); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(sentinel, output); err != nil {
				t.Fatal(err)
			}
			if err := run(); err != nil {
				t.Fatalf("replace existing regular metadata output: %v", err)
			}
			if content, err := os.ReadFile(sentinel); err != nil || string(content) != "unrelated bytes" {
				t.Fatalf("hardlink peer changed: %q, %v", content, err)
			}
			if content, err := os.ReadFile(output); err != nil || string(content) != string(want) {
				t.Fatalf("replacement bytes = %q, %v; want %q", content, err, want)
			}
			if info, err := os.Lstat(output); err != nil || info.Mode() != 0o600 {
				t.Fatalf("replacement metadata output permissions: %v, %v", info, err)
			}
		})
	}
}

func writeFixtureNPMRecord(t *testing.T, carrier string) packRecord {
	t.Helper()
	shasum, integrity := npmFileClaims(t, carrier)
	record := packRecord{Name: fixtureNPMName, Version: fixtureVersion, Filename: filepath.Base(carrier), Shasum: shasum, Integrity: integrity}
	if err := writeJSON("artifacts/package/npm-pack.json", []packRecord{record}); err != nil {
		t.Fatal(err)
	}
	return record
}

func writeReleaseManifestFixture(t *testing.T, withWheels bool) (string, []packRecord, *pythonPackageSet) {
	t.Helper()
	t.Chdir(t.TempDir())
	for _, directory := range []string{"release", "artifacts/package", "artifacts/pypi", "artifacts/release"} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, "package.json", `{"name":"`+fixtureNPMName+`","version":"`+fixtureVersion+`","license":"MIT","repository":{"url":"https://github.com/example/proofkit"}}`)
	writeFile(t, "go.mod", "module example.test/proofkit\n")
	writeFile(t, releasechange.RecordPath, `{"schemaVersion":2,"version":"1.2.3","previousVersion":"1.2.2","changeClass":"compatible","additions":[],"breakingChanges":[],"migration":{"required":false,"steps":[]},"platformRequirements":["Linux"],"knownLimitations":["Fixture has no publication evidence."],"rollback":{"strategy":"previous_admitted_version"}}`)
	carrier := filepath.Join("artifacts", "package", "research-engineering-agentic-proofkit-1.2.3.tgz")
	writeNPMCarrier(t, carrier, "")
	records := []packRecord{writeFixtureNPMRecord(t, carrier)}
	var packages *pythonPackageSet
	if withWheels {
		packages = &pythonPackageSet{
			ArtifactKind: "proofkit.python-package-set.v1", SchemaVersion: 1,
			PackageName: pythonPackageName, PackageVersion: fixtureVersion,
		}
		for _, target := range releaseplatform.Targets() {
			filename := "agentic_proofkit-" + fixtureVersion + "-" + target.WheelTag + ".whl"
			path := filepath.Join("artifacts", "pypi", filename)
			binary := carrierBinary(target.PlatformSuffix)
			writeWheelCarrier(t, path, binary)
			digest, err := fileSHA256(path)
			if err != nil {
				t.Fatal(err)
			}
			packages.Packages = append(packages.Packages, pythonWheelRecord{
				Filename: filename, Name: pythonPackageName, Version: fixtureVersion, Sha256: digest,
				PlatformSuffix: target.PlatformSuffix, BinarySha256: fmt.Sprintf("%x", sha256.Sum256(binary)),
				PythonTag: "py3", AbiTag: "none", PlatformTag: target.PlatformTag, WheelTag: target.WheelTag,
			})
		}
		if err := writeJSON("artifacts/pypi/python-packages.json", packages); err != nil {
			t.Fatal(err)
		}
	}
	writeFixtureSBOM(t, fixtureSBOMComponents(t, records, packages))
	return carrier, records, packages
}

func TestReleaseManifestRequiresExactSBOMFileSubjects(t *testing.T) {
	for _, mode := range []struct {
		name       string
		withWheels bool
	}{
		{name: "npm_only"},
		{name: "with_wheels", withWheels: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			_, records, packages := writeReleaseManifestFixture(t, mode.withWheels)
			if err := run(); err != nil {
				t.Fatalf("valid release rejected: %v", err)
			}
			assertReleaseChecksumSubjects(t, records, packages)
			outputs := retainReleaseOutputs(t)
			// The carrier files and their recorded outer digests remain valid.
			// Each SBOM mutation would get its own matching outer checksum.
			for _, mutant := range []struct {
				name, diagnostic string
				mutate           func([]fixtureSBOMComponent) []fixtureSBOMComponent
			}{
				{"empty", "missing file subject", func(_ []fixtureSBOMComponent) []fixtureSBOMComponent { return nil }},
				{"missing binary", "missing file subject", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					return append(items[:1], items[2:]...)
				}},
				{"missing npm", "missing file subject", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					return items[:len(items)-1]
				}},
				{"extra archive", "unexpected file subject", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					extra := items[len(items)-1]
					extra.BOMRef = "file:artifacts/package/other.tgz"
					extra.Name = "other.tgz"
					extra.Properties = []map[string]string{{"name": "proofkit:path", "value": "artifacts/package/other.tgz"}}
					return append(items, extra)
				}},
				{"duplicate binary", "duplicate file subject", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					return append(items, items[1])
				}},
				{"swapped binary digest", "expected SHA-256", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					items[1].Hashes = items[2].Hashes
					return items
				}},
				{"wrong archive digest", "expected SHA-256", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					items[len(items)-1].Hashes = items[1].Hashes
					return items
				}},
				{"wrong name", "incorrect path, name, type, or version", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					items[1].Name = "imposter"
					return items
				}},
				{"wrong path property", "incorrect path, name, type, or version", func(items []fixtureSBOMComponent) []fixtureSBOMComponent {
					items[1].Properties = items[2].Properties
					return items
				}},
			} {
				t.Run(mutant.name, func(t *testing.T) {
					writeFixtureSBOM(t, mutant.mutate(fixtureSBOMComponents(t, records, packages)))
					assertRejectedSBOM(t, mutant.diagnostic, outputs)
				})
			}
			if mode.withWheels {
				t.Run("missing wheel", func(t *testing.T) {
					items := fixtureSBOMComponents(t, records, packages)
					writeFixtureSBOM(t, append(items[:len(items)-2], items[len(items)-1]))
					assertRejectedSBOM(t, "missing file subject", outputs)
				})
				t.Run("wrong wheel digest", func(t *testing.T) {
					items := fixtureSBOMComponents(t, records, packages)
					items[len(items)-2].Hashes = items[len(items)-1].Hashes
					writeFixtureSBOM(t, items)
					assertRejectedSBOM(t, "expected SHA-256", outputs)
				})
			}
		})
	}
}

func assertReleaseChecksumSubjects(t *testing.T, records []packRecord, packages *pythonPackageSet) {
	t.Helper()
	var lines []string
	for _, path := range expectedPackageArtifactPaths(records, packages) {
		digest, err := fileSHA256(path)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, digest+"  "+filepath.Base(path)+"\n")
	}
	for _, name := range []string{"sbom-subjects.sha256", "checksums.sha256"} {
		if name == "checksums.sha256" {
			digest, err := fileSHA256(fixtureSBOMPath)
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, digest+"  sbom.cdx.json\n")
		}
		got, err := os.ReadFile(filepath.Join("artifacts", "release", name))
		if err != nil || string(got) != strings.Join(lines, "") {
			t.Fatalf("%s changed archive checksum contract: %v\ngot: %s", name, err, got)
		}
	}
}

type retainedReleaseOutput struct {
	info    os.FileInfo
	content []byte
}

func retainReleaseOutputs(t *testing.T) map[string]retainedReleaseOutput {
	t.Helper()
	outputs := map[string]retainedReleaseOutput{}
	marker := time.Unix(1000000000, 0)
	for _, name := range []string{"checksums.sha256", "sbom-subjects.sha256", "release-manifest.json", "release-notes.md", "metadata-checksums.sha256"} {
		path := filepath.Join("artifacts", "release", name)
		content, err := os.ReadFile(path)
		if err != nil || len(content) == 0 {
			t.Fatalf("valid release did not write %s: %v", name, err)
		}
		if err := os.Chtimes(path, marker, marker); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		outputs[path] = retainedReleaseOutput{info: info, content: content}
	}
	return outputs
}

func assertRejectedSBOM(t *testing.T, diagnostic string, outputs map[string]retainedReleaseOutput) {
	t.Helper()
	if err := run(); err == nil || !strings.Contains(err.Error(), "release SBOM") || !strings.Contains(err.Error(), diagnostic) {
		t.Fatalf("expected SBOM rejection %q, got %v", diagnostic, err)
	}
	assertRetainedReleaseOutputs(t, outputs)
}

func assertRetainedReleaseOutputs(t *testing.T, outputs map[string]retainedReleaseOutput) {
	t.Helper()
	for path, want := range outputs {
		info, err := os.Stat(path)
		if err != nil || !os.SameFile(info, want.info) || !info.ModTime().Equal(want.info.ModTime()) {
			t.Fatalf("failed admission replaced or rewrote %s: %v", path, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want.content) {
			t.Fatalf("failed admission modified %s: %v", path, err)
		}
	}
}
