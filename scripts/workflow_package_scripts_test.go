package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/npmmanifest"
)

func readPackageScriptsForTest(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	scripts, err := npmmanifest.Scripts(raw)
	if err != nil {
		t.Fatal(err)
	}
	return scripts
}

func namedTestVerdict(output []byte, verdict, name string) bool {
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.HasPrefix(line, "--- "+verdict+": "+name+" (") && strings.HasSuffix(line, "s)") {
			return true
		}
	}
	return false
}

func TestNamedTestVerdictRequiresTheExactParent(t *testing.T) {
	for _, verdict := range []string{"PASS", "FAIL"} {
		if !namedTestVerdict([]byte("--- "+verdict+": TestOwner (0.00s)\n"), verdict, "TestOwner") {
			t.Fatal("exact parent verdict was not observed")
		}
		for _, output := range []string{
			"--- SKIP: TestOwner (0.00s)\n    --- " + verdict + ": TestOwner/control (0.00s)\n",
			"--- " + verdict + ": TestOwnerSuffix (0.00s)\n",
			"    --- " + verdict + ": TestOwner (0.00s)\n",
			"testing: warning: no tests to run\nPASS\n",
		} {
			if namedTestVerdict([]byte(output), verdict, "TestOwner") {
				t.Fatal("another or skipped test supplied the named parent verdict")
			}
		}
	}
}

// Reuse the compiled test executable so the real file readers, not copies of
// their bodies, must distinguish a canonical source from a case-shadowed one.
func TestPackageScriptConsumersRejectShadowedSource(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	scripts := readPackageScriptsForTest(t)
	canonical, err := json.Marshal(scripts)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"check", "platform:smoke", "browser:static-check"} {
		scripts[name] = "true"
	}
	inert, err := json.Marshal(scripts)
	if err != nil {
		t.Fatal(err)
	}
	shadow := []byte(fmt.Sprintf(`{"scripts":%s,"Scripts":%s}`, inert, canonical))
	if err := validatePlatformSmokeOwnerScript(shadow); err == nil {
		t.Fatal("platform validator accepted the case-shadowed command")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ name, failure string }{
		{"TestRootCheckRetainsRequiredProofGates", "root check must retain the exact ordered AND-only proof gates"},
		{"TestBrowserStaticCollectorRetainsEveryOracleSuite", "browser:static-check must run type checking and every owned oracle suite without suppression"},
	} {
		for _, counterfeit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/shadow=%t", target.name, counterfeit), func(t *testing.T) {
				root := t.TempDir()
				working := filepath.Join(root, "scripts")
				if err := os.Mkdir(working, 0o700); err != nil {
					t.Fatal(err)
				}
				content := raw
				if counterfeit {
					content = shadow
				}
				if err := os.WriteFile(filepath.Join(root, "package.json"), content, 0o600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, executable, "-test.v", "-test.run=^"+target.name+"$")
				command.Dir = working
				command.Env = []string{"HOME=" + root, "TMPDIR=" + root}
				output, runErr := command.CombinedOutput()
				if ctx.Err() != nil {
					t.Fatal("script-owner child exceeded its execution bound")
				}
				if !counterfeit {
					if runErr != nil || !namedTestVerdict(output, "PASS", target.name) {
						t.Fatal("canonical script owner did not execute its named oracle successfully")
					}
					return
				}
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) || exit.ExitCode() != 1 ||
					!namedTestVerdict(output, "FAIL", target.name) || !bytes.Contains(output, []byte(target.failure)) {
					t.Fatal("case-shadowed script owner did not fail its actual command assertion")
				}
			})
		}
	}
}
