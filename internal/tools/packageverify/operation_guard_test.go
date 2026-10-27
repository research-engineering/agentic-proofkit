package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestRunVerifierManifestGuardPrecedesOutsideConsumer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake npm carrier is a POSIX shell script")
	}
	const repository = "git+https://github.com/research-engineering/agentic-proofkit.git"
	const specPath = "docs/specs/proofkit-spec-proof-core"
	fakeBin := t.TempDir()
	writeFileBytes(t, filepath.Join(fakeBin, "npm"), []byte(fakeNPM))
	if err := os.Chmod(filepath.Join(fakeBin, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROOFKIT_OPERATION_TAMPER", "")
	writeFixture := func(t *testing.T, repositoryURL string) {
		t.Helper()
		writeFileBytes(t, "go.mod", []byte("module fixture\n\ngo 1.27.3\n"))
		entries := map[string]string{}
		for _, entry := range requiredRootEntries() {
			entries[entry] = "Fixture document.\n"
			if rootBinaryEntry(entry) {
				entries[entry] = "#!/bin/sh\necho executed >> \"$PROOFKIT_OPERATION_MARKERS/binary.log\"\nexit 1\n"
			}
		}
		closure := packageReferenceClosureFixture()
		var contract map[string]any
		if err := json.Unmarshal([]byte(closure["package/proofkit/cli-contract.v2.json"]), &contract); err != nil {
			t.Fatal(err)
		}
		contract["processContract"].(map[string]any)["commandRouteGrammar"] = testCommandRouteGrammar()
		encoded, err := json.Marshal(contract)
		if err != nil {
			t.Fatal(err)
		}
		entries["package/proofkit/cli-contract.v2.json"] = string(encoded)
		entries["package/README.md"] = closure["package/README.md"]
		entries["package/package.json"] = packageManifestFixture(repositoryURL)
		entries[workspaceImageEntry] = string(workspacePNG(t, 1, 1))
		entries["package/proofkit/requirement-bindings.json"] = `{"requirements":[],"bindings":[]}`
		entries["package/proofkit/witness-plan.json"] = `{"commands":[],"policies":[]}`
		entries["package/proofkit/command-families.v1.json"] = `{"families":[]}`
		entries["package/proofkit/receipt-producer-policy.json"] = `{"producers":[]}`
		entries["package/"+specPath+"/overview.md"] = "Fixture specification.\n"
		entries["package/"+specPath+"/requirements.v2.json"] = packageReferenceSource(specPath, "REQ-PROOFKIT-SPEC-005", "REQ-PROOFKIT-SPEC-026")
		for entry, content := range entries {
			writeFileBytes(t, filepath.FromSlash(strings.TrimPrefix(entry, "package/")), []byte(content))
		}
		writeFileBytes(t, "internal/tools/packageverify/main.go", []byte("package main\n"))
		content := mustReadBytes(t, writePackageTarball(t, entries))
		record := packRecord{Name: rootPackageName, Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: testNPMIntegrity(content), Shasum: testSHA1(content)}
		writeFileBytes(t, filepath.Join("artifacts", "package", record.Filename), content)
		encoded, err = json.Marshal([]packRecord{record})
		if err != nil {
			t.Fatal(err)
		}
		writeFileBytes(t, filepath.Join("artifacts", "package", "npm-pack.json"), encoded)
	}
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "inadmissible repository", true: "restored repository"}[admitted], func(t *testing.T) {
			withWorkingDirectory(t, t.TempDir())
			markers := t.TempDir()
			t.Setenv("PROOFKIT_OPERATION_MARKERS", markers)
			url := repository
			if !admitted {
				url = "git+https://github.com/example/agentic-proofkit.git"
			}
			writeFixture(t, url)
			err := runVerifier()
			log, logErr := os.ReadFile(filepath.Join(markers, "npm.log"))
			if logErr != nil && !os.IsNotExist(logErr) {
				t.Fatal(logErr)
			}
			_, binaryErr := os.Stat(filepath.Join(markers, "binary.log"))
			if !admitted {
				if len(log) != 0 || !os.IsNotExist(binaryErr) {
					t.Fatalf("inadmissible manifest reached an outside consumer: npm=%q binary=%v error=%v", log, binaryErr, err)
				}
				if err == nil || err.Error() != "root package repository must be "+repository {
					t.Fatalf("expected repository-boundary refusal, got %v", err)
				}
				return
			}
			expectedLog := "install --ignore-scripts --no-audit --no-fund\n--silent exec --offline -- agentic-proofkit help\n"
			if err == nil || string(log) != expectedLog {
				t.Fatalf("restored manifest did not reach install and intentional exec failure: npm=%q error=%v", log, err)
			}
		})
	}
}

// fakeNPM records every invocation. "install" materializes the consumer's
// package tarball like npm would (optionally tampering one installed byte);
// every other invocation, such as "npm exec", is an execution and fails.
const fakeNPM = `#!/bin/sh
echo "$*" >> "$PROOFKIT_OPERATION_MARKERS/npm.log"
if [ "$1" = install ]; then
  root=node_modules/@research-engineering/agentic-proofkit
  mkdir -p "$root" && tar -xzf ./*.tgz -C "$root" --strip-components=1 || exit 1
  if [ -n "$PROOFKIT_OPERATION_TAMPER" ]; then printf ' ' >> "$root/proofkit/cli-contract.v2.json"; fi
  exit 0
fi
exit 1
`

// Whole-operation guard order of verifyExactTarballConsumer: the carrier
// snapshot is admitted before npm installs anything, and the installed bytes
// are proven exact before any installed carrier executes. Each guard is
// injected to fail and then restored, so the effect is shown to depend on it.
func TestExactTarballConsumerGuardsPrecedeInstallAndExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake npm carrier is a POSIX shell script")
	}
	target, err := releaseplatform.CurrentTarget()
	if err != nil {
		t.Fatalf("current platform has no admitted npm package target: %v", err)
	}
	contract := mustReadBytes(t, filepath.Join("..", "..", "..", "proofkit", "cli-contract.v2.json"))
	readme := mustReadBytes(t, filepath.Join("..", "..", "..", "README.md"))
	fakeBin := t.TempDir()
	writeFileBytes(t, filepath.Join(fakeBin, "npm"), []byte(fakeNPM))
	if err := os.Chmod(filepath.Join(fakeBin, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	executedBinary := "#!/bin/sh\necho executed >> \"$PROOFKIT_OPERATION_MARKERS/binary.log\"\nexit 1\n"
	artifact := func(contract []byte) rootPackageArtifact {
		tarball := writePackageTarball(t, map[string]string{
			"package/package.json":                  `{"name":"@research-engineering/agentic-proofkit","version":"1.2.3","bin":{"agentic-proofkit":"dist/agentic-proofkit"}}`,
			"package/dist/agentic-proofkit":         executedBinary,
			target.PackageTarEntry:                  executedBinary,
			"package/README.md":                     string(readme),
			"package/proofkit/cli-contract.v2.json": string(contract),
		})
		return rootPackageArtifact{Content: mustReadBytes(t, tarball), Record: packRecord{Filename: "agentic-proofkit-1.2.3.tgz"}}
	}
	observe := func(t *testing.T, value rootPackageArtifact, tamper bool) (string, bool, error) {
		t.Helper()
		markers := t.TempDir()
		t.Setenv("PROOFKIT_OPERATION_MARKERS", markers)
		t.Setenv("PROOFKIT_OPERATION_TAMPER", map[bool]string{true: "1"}[tamper])
		err := verifyExactTarballConsumer(value)
		log, _ := os.ReadFile(filepath.Join(markers, "npm.log"))
		_, binaryErr := os.Stat(filepath.Join(markers, "binary.log"))
		return string(log), binaryErr == nil, err
	}
	executed := func(log string, binary bool) bool {
		return binary || strings.Contains(log, "exec")
	}

	t.Run("carrier admission precedes install", func(t *testing.T) {
		log, binary, err := observe(t, artifact([]byte(`{"commands":[]}`)), false)
		if err == nil || !strings.Contains(err.Error(), "admit package carrier CLI contract") {
			t.Fatalf("inadmissible carrier error=%v", err)
		}
		if log != "" || binary {
			t.Fatalf("an inadmissible carrier reached npm or execution: npm=%q binary=%v", log, binary)
		}
		log, _, err = observe(t, artifact(contract), false)
		if err == nil || !strings.HasPrefix(log, "install ") {
			t.Fatalf("restored carrier did not reach install: npm=%q err=%v", log, err)
		}
	})

	t.Run("installed bytes are proven before execution", func(t *testing.T) {
		log, binary, err := observe(t, artifact(contract), true)
		if err == nil || !strings.Contains(err.Error(), "differs from the exact package tarball") {
			t.Fatalf("tampered install error=%v", err)
		}
		if !strings.HasPrefix(log, "install ") || executed(log, binary) {
			t.Fatalf("a tampered install executed an installed carrier: npm=%q binary=%v", log, binary)
		}
		log, binary, err = observe(t, artifact(contract), false)
		if err == nil || !executed(log, binary) {
			t.Fatalf("exact install did not reach execution: npm=%q binary=%v err=%v", log, binary, err)
		}
	})
}
