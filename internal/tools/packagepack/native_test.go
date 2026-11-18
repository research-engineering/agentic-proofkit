package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNPMPackDisablesLifecycleScripts(t *testing.T) {
	npm, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal("native hook witness requires the repository npm toolchain")
	}
	version, err := exec.Command(npm, "--version").Output()
	if err != nil || string(bytes.TrimSpace(version)) != "12.2.0" {
		t.Fatal("native hook witness requires pinned npm 12.2.0")
	}
	t.Chdir(t.TempDir())
	t.Setenv("npm_config_cache", t.TempDir())
	t.Setenv("npm_config_userconfig", filepath.Join(t.TempDir(), "npmrc"))
	t.Setenv("npm_config_offline", "true")
	t.Setenv("npm_config_ignore_scripts", "false")
	manifest := `{"name":"pack-fixture","version":"1.2.3","files":["index.js"],"scripts":{` +
		`"prepack":"node -e \"require('node:fs').appendFileSync('hooks','prepack\\n')\"",` +
		`"prepare":"node -e \"require('node:fs').appendFileSync('hooks','prepare\\n')\"",` +
		`"postpack":"node -e \"require('node:fs').appendFileSync('hooks','postpack\\n')\""}}`
	writeFixture(t, "package.json", manifest)
	writeFixture(t, "index.js", "export {};\n")
	control := exec.Command(npm, "--silent", "pack", "--json", "--ignore-scripts=false", "--pack-destination", t.TempDir(), ".")
	if out, err := control.CombinedOutput(); err != nil {
		t.Fatalf("hook-active control failed: %v\n%s", err, out)
	}
	if string(readFixture(t, "hooks")) != "prepack\nprepare\npostpack\n" {
		t.Fatal("hook-active control did not execute every selected hook")
	}
	if err := os.Remove("hooks"); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("hooks"); !os.IsNotExist(err) {
		t.Fatalf("scripts-disabled pack executed a lifecycle hook: %v", err)
	}
	if len(readFixture(t, filepath.Join(packageDirectory, "npm-pack.json"))) == 0 {
		t.Fatal("scripts-disabled pack did not complete publication")
	}
}

func TestPackPreservesPreparedOutputModes(t *testing.T) {
	for _, mask := range []string{"022", "077"} {
		t.Run(mask, func(t *testing.T) {
			preparePackChild(t, fixtureArchive(t, []string{"package/package.json"}, []string{fixtureManifest}), "success")
			t.Setenv("PROOFKIT_NPM_MODE_MASK", mask)
			command := exec.Command("/bin/sh", "-c", "umask "+mask+"; exec \"$PROOFKIT_NPM_TEST_EXECUTABLE\" -test.run='^TestPackModeHelper$'")
			if out, err := command.CombinedOutput(); err != nil || string(out) != "mode-ok\n" {
				t.Fatalf("umask %s control: %v\n%s", mask, err, out)
			}
		})
	}
}

func TestPackModeHelper(t *testing.T) {
	mask := os.Getenv("PROOFKIT_NPM_MODE_MASK")
	if mask == "" {
		return
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o644)
	if mask == "077" {
		want = 0o600
	}
	for _, name := range []string{"pack-fixture-1.2.3.tgz", "npm-pack.json"} {
		info, err := os.Stat(filepath.Join(packageDirectory, name))
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("mode mismatch: %v, want %o", err, want)
		}
	}
	if _, err := os.Stdout.WriteString("mode-ok\n"); err != nil {
		os.Exit(92)
	}
	os.Exit(0)
}

func TestPackCaptureInclusiveBound(t *testing.T) {
	stage := t.TempDir()
	name := "bounded.tgz"
	writeFixture(t, filepath.Join(stage, name), strings.Repeat("x", 32))
	if content, _, err := captureOutput(stage, name, 32); err != nil || len(content) != 32 {
		t.Fatalf("inclusive bound: %v", err)
	}
	if _, _, err := captureOutput(stage, name, 31); err == nil || !strings.Contains(err.Error(), "resource limit") {
		t.Fatalf("excess bound admitted: %v", err)
	}
}
