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

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/gitfixture"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/npmmanifest"
)

func TestBrowserScriptReadersRejectShadowedSource(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	scripts, err := npmmanifest.Scripts(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(scripts)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"browser:visual", "browser:matrix", "browser:matrix:static", "browser:matrix:workspace"} {
		scripts[name] = "true"
	}
	inert, err := json.Marshal(scripts)
	if err != nil {
		t.Fatal(err)
	}
	shadow := []byte(fmt.Sprintf(`{"scripts":%s,"Scripts":%s}`, inert, canonical))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ name, failure string }{
		{"TestBrowserMatrixScriptsAreSeparateFromThePackageGate", " = \"true\", want "},
		{"TestBrowserVisualScriptIsSeparateFromThePackageGate", "browser:visual must delegate to the single Go orchestrator"},
	} {
		for _, counterfeit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/shadow=%t", target.name, counterfeit), func(t *testing.T) {
				fixture := t.TempDir()
				if output, err := gitfixture.Command(fixture, "init", "--quiet").CombinedOutput(); err != nil {
					t.Fatalf("initialize script-owner fixture: %v (%s)", err, output)
				}
				content := raw
				if counterfeit {
					content = shadow
				}
				if err := os.WriteFile(filepath.Join(fixture, "package.json"), content, 0o600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, executable, "-test.v", "-test.run=^"+target.name+"$")
				command.Dir = fixture
				command.Env = []string{"HOME=" + fixture, "TMPDIR=" + fixture, "PATH=" + filepath.Dir(gitExecutable),
					"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=" + os.DevNull, "GIT_CONFIG_GLOBAL=" + os.DevNull}
				output, runErr := command.CombinedOutput()
				if ctx.Err() != nil {
					t.Fatal("browser script-owner child exceeded its execution bound")
				}
				// The delimiter after the full parent name excludes descendant verdicts.
				observed := "\n" + string(output)
				if !counterfeit {
					if runErr != nil || !strings.Contains(observed, "\n--- PASS: "+target.name+" (") {
						t.Fatal("canonical browser script owner did not pass its named oracle")
					}
					return
				}
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) || exit.ExitCode() != 1 ||
					!strings.Contains(observed, "\n--- FAIL: "+target.name+" (") || !bytes.Contains(output, []byte(target.failure)) {
					t.Fatal("case-shadowed browser script owner did not fail its actual command assertion")
				}
			})
		}
	}
}
