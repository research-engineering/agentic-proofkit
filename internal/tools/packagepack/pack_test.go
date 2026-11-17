package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/npmpack"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagemetadata"
)

const fixtureManifest = `{"name":"pack-fixture","version":"1.2.3","description":"A small fixture"}`

func TestPackCapturedHandoffAndPhaseFailures(t *testing.T) {
	for _, phase := range []string{"success", "child", "child-cleanup", "report", "missing", "symlink", "executable", "digest", "metadata", "cleanup", "tar-publish", "report-publish"} {
		t.Run(phase, func(t *testing.T) {
			manifest := fixtureManifest
			if phase == "metadata" {
				manifest = strings.Replace(manifest, "A small fixture", "api_key=syntheticvalue0123456789012345", 1)
			}
			archive := fixtureArchive(t, []string{"package/package.json"}, []string{manifest})
			root := preparePackChild(t, archive, phase)
			cleanupCount, published := 0, []string{}
			cleanup := func(stage string) error {
				cleanupCount++
				if phase == "cleanup" || phase == "child-cleanup" {
					t.Cleanup(func() { _ = os.RemoveAll(stage) })
					return errors.New("controlled cleanup refusal")
				}
				return os.RemoveAll(stage)
			}
			publish := func(root, path string, content []byte, mode fs.FileMode) error {
				if cleanupCount != 1 {
					t.Fatal("publication preceded required cleanup")
				}
				published = append(published, path)
				if phase == "tar-publish" || phase == "report-publish" && strings.HasSuffix(path, ".json") {
					return errors.New("controlled publication refusal")
				}
				return artifactfile.WriteAtomic(root, path, content, mode)
			}
			err := pack(cleanup, publish)
			if (err == nil) != (phase == "success") {
				t.Fatalf("phase %s error = %v", phase, err)
			}
			if err != nil {
				want := map[string]string{
					"child": "npm pack:", "child-cleanup": "npm pack:",
					"report": "invalid", "missing": "open artifact file failed",
					"symlink": "non-symlink", "executable": "non-executable",
					"digest": "digests do not match", "metadata": "secret",
					"cleanup": "controlled cleanup refusal", "tar-publish": "controlled publication refusal",
					"report-publish": "controlled publication refusal",
				}[phase]
				if want == "" || !strings.Contains(err.Error(), want) {
					t.Fatalf("phase %s failed for wrong cause: %v, want %q", phase, err, want)
				}
				if phase == "child-cleanup" && !strings.Contains(err.Error(), "controlled cleanup refusal") {
					t.Fatal("cleanup failure hidden by child failure")
				}
			}
			if cleanupCount != 1 {
				t.Fatalf("required cleanup calls = %d", cleanupCount)
			}
			calls := readFixture(t, filepath.Join(root, "calls.jsonl"))
			if bytes.Count(calls, []byte{'\n'}) != 1 {
				t.Fatalf("pack invocations = %s", calls)
			}
			tarPath := filepath.Join(packageDirectory, "pack-fixture-1.2.3.tgz")
			reportPath := filepath.Join(packageDirectory, "npm-pack.json")
			if phase == "success" || phase == "report-publish" {
				if !bytes.Equal(readFixture(t, tarPath), archive) {
					t.Fatal("published bytes differ from the captured archive")
				}
			} else if _, err := os.Lstat(tarPath); !os.IsNotExist(err) {
				t.Fatalf("refused phase published a final archive: %v", err)
			}
			if phase != "success" {
				if _, err := os.Lstat(reportPath); !os.IsNotExist(err) {
					t.Fatalf("refused phase committed a new report: %v", err)
				}
				if phase != "tar-publish" && phase != "report-publish" && len(published) != 0 {
					t.Fatal("publication began before handoff admission completed")
				}
				return
			}
			var records []npmpack.Record
			if err := json.Unmarshal(readFixture(t, reportPath), &records); err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].ID != "pack-fixture@1.2.3" || records[0] != fixtureRecord(archive) {
				t.Fatalf("unexpected final record: %+v", records)
			}
		})
	}
}

func TestPackPreflightPreservesPriorOutputs(t *testing.T) {
	for _, unsafe := range []string{"source", "ancestor", "target"} {
		t.Run(unsafe, func(t *testing.T) {
			root := preparePackChild(t, fixtureArchive(t, []string{"package/package.json"}, []string{fixtureManifest}), "success")
			outside := t.TempDir()
			writeFixture(t, filepath.Join(outside, "sentinel"), "keep")
			writeFixture(t, filepath.Join(packageDirectory, "npm-pack.json"), "prior report")
			if unsafe == "source" {
				writeFixture(t, "package.json", `{"description":"api_key=syntheticvalue0123456789012345"}`)
			} else {
				alias := "artifacts"
				if unsafe == "target" {
					alias = packageDirectory
				}
				if err := os.Rename(alias, alias+"-prior"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, alias); err != nil {
					t.Fatal(err)
				}
			}
			want := "symlink"
			if unsafe == "source" {
				want = "secret"
			}
			if err := run(); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("unsafe preflight failed for wrong cause: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "calls.jsonl")); !os.IsNotExist(err) {
				t.Fatalf("child launched: %v", err)
			}
			if string(readFixture(t, filepath.Join(outside, "sentinel"))) != "keep" {
				t.Fatal("outside changed")
			}
			reportPath := filepath.Join(packageDirectory, "npm-pack.json")
			if unsafe == "ancestor" {
				reportPath = "artifacts-prior/package/npm-pack.json"
			}
			if unsafe == "target" {
				reportPath = packageDirectory + "-prior/npm-pack.json"
			}
			if string(readFixture(t, reportPath)) != "prior report" {
				t.Fatal("prior report changed")
			}
		})
	}
}

func TestPackArchiveAdmissionUsesCompleteCapturedBytes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		names, contents []string
		corrupt         bool
	}{
		{"ordinary", []string{"package/package.json"}, []string{fixtureManifest}, false},
		{"missing manifest", []string{"package/other"}, []string{"data"}, false},
		{"duplicate manifest", []string{"package/package.json", "package/package.json"}, []string{fixtureManifest, fixtureManifest}, false},
		{"unsafe path after manifest", []string{"package/package.json", "../escape"}, []string{fixtureManifest, "data"}, false},
		{"mismatched version", []string{"package/package.json"}, []string{strings.Replace(fixtureManifest, "1.2.3", "2.0.0", 1)}, false},
		{"corrupt trailer", []string{"package/package.json"}, []string{fixtureManifest}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := fixtureArchive(t, tc.names, tc.contents)
			if tc.corrupt {
				archive[len(archive)-1] ^= 1
			}
			err := admitArchive(archive, fixtureRecord(archive))
			if (err == nil) != (tc.name == "ordinary") {
				t.Fatalf("admitArchive error = %v", err)
			}
		})
	}
}

func TestPackRejectsUnsafeChildIdentity(t *testing.T) {
	for _, name := range []string{"../escape.tgz", "/escape.tgz", "different.tgz", `dir\escape.tgz`} {
		t.Run(name, func(t *testing.T) {
			r := fixtureRecord(nil)
			r.Filename = name
			if err := admitRecordIdentity(r, packagemetadata.Record{Name: "pack-fixture", Version: "1.2.3"}); err == nil {
				t.Fatal("unsafe filename admitted")
			}
		})
	}
}

func TestNpmPackChildHelper(t *testing.T) {
	if os.Getenv("PROOFKIT_NPM_CHILD") != "1" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	if len(args) != 7 || !slices.Equal(args[:5], []string{"--silent", "pack", "--json", "--ignore-scripts", "--pack-destination"}) || args[6] != "." {
		os.Exit(87)
	}
	stage, phase := args[5], os.Getenv("PROOFKIT_NPM_PHASE")
	f, err := os.OpenFile(os.Getenv("PROOFKIT_NPM_CALLS"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(88)
	}
	if err := json.NewEncoder(f).Encode(args); err != nil {
		os.Exit(88)
	}
	_ = f.Close()
	if phase == "child" || phase == "child-cleanup" {
		os.Exit(9)
	}
	if phase == "report" {
		fmt.Print("not json")
		os.Exit(0)
	}
	content, err := os.ReadFile(os.Getenv("PROOFKIT_NPM_ARCHIVE"))
	if err != nil {
		os.Exit(89)
	}
	record := fixtureRecord(content)
	name := filepath.Join(stage, record.Filename)
	if phase == "symlink" {
		err = os.Symlink(os.Getenv("PROOFKIT_NPM_ARCHIVE"), name)
	} else if phase != "missing" {
		err = os.WriteFile(name, content, 0o644)
	}
	if err != nil {
		os.Exit(90)
	}
	if phase == "executable" {
		if os.Chmod(name, 0o755) != nil {
			os.Exit(90)
		}
	}
	if phase == "digest" {
		record.Shasum = strings.Repeat("0", 40)
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]npmpack.Record{record.Name: record}) != nil {
		os.Exit(91)
	}
	os.Exit(0)
}

func preparePackChild(t *testing.T, archive []byte, phase string) string {
	t.Helper()
	root, fixture := t.TempDir(), t.TempDir()
	t.Chdir(root)
	writeFixture(t, "package.json", fixtureManifest)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(fixture, "npm")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexec \"$PROOFKIT_NPM_TEST_EXECUTABLE\" -test.run='^TestNpmPackChildHelper$' -- \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(fixture, "fixture.tgz")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"PATH": fixture, "PROOFKIT_NPM_CHILD": "1", "PROOFKIT_NPM_TEST_EXECUTABLE": executable, "PROOFKIT_NPM_ARCHIVE": archivePath, "PROOFKIT_NPM_PHASE": phase, "PROOFKIT_NPM_CALLS": filepath.Join(root, "calls.jsonl")} {
		t.Setenv(key, value)
	}
	return root
}

func fixtureRecord(content []byte) npmpack.Record {
	a, b := sha1.Sum(content), sha512.Sum512(content)
	return npmpack.Record{Filename: "pack-fixture-1.2.3.tgz", ID: "pack-fixture@1.2.3", Name: "pack-fixture", Version: "1.2.3", Shasum: hex.EncodeToString(a[:]), Integrity: "sha512-" + base64.StdEncoding.EncodeToString(b[:])}
}

func fixtureArchive(t *testing.T, names, contents []string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for i, name := range names {
		content := []byte(contents[i])
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func writeFixture(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
