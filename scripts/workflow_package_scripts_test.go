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
	"reflect"
	"testing"
	"time"
)

// Select the same case-sensitive, whole-object property as npm's JSON reader.
// Command bodies and lifecycle policy belong to the individual gate owners.
func packageScriptsFromJSON(raw []byte) (map[string]string, error) {
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("package manifest must be a JSON object")
	}
	var values map[string]any
	if err := json.Unmarshal(manifest["scripts"], &values); err != nil || values == nil {
		return nil, fmt.Errorf("package manifest must contain the exact scripts object")
	}
	scripts := make(map[string]string, len(values))
	for name, value := range values {
		command, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("package scripts must contain only string commands")
		}
		scripts[name] = command
	}
	return scripts, nil
}

func readPackageScriptsForTest(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	scripts, err := packageScriptsFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return scripts
}

func TestPackageScriptsSelectExactNPMObject(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"canonical", `{"scripts":{"check":"owned check"}}`, map[string]string{"check": "owned check"}},
		{"later case variant", `{"scripts":{"check":"true"},"Scripts":{"check":"owned check"}}`, map[string]string{"check": "true"}},
		{"earlier case variant", `{"Scripts":{"check":"owned check"},"scripts":{"check":"true"}}`, map[string]string{"check": "true"}},
		{"whole last object", `{"scripts":{"check":"old check","old":"old only"},"scripts":{"check":"new check","new":"new only"}}`, map[string]string{"check": "new check", "new": "new only"}},
		{"empty last object", `{"scripts":{"check":"old check"},"scripts":{}}`, map[string]string{}},
		{"explicit empty command", `{"scripts":{"postpython:verify":""}}`, map[string]string{"postpython:verify": ""}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			got, err := packageScriptsFromJSON([]byte(item.raw))
			if err != nil || !reflect.DeepEqual(got, item.want) {
				t.Fatalf("selected scripts=%v error=%v, want %v", got, err, item.want)
			}
		})
	}
	for _, raw := range []string{
		`{`, `null`, `[]`, `{}`, `{"Scripts":{"check":"owned check"}}`,
		`{"scripts":null}`, `{"scripts":[]}`, `{"scripts":"check"}`,
		`{"scripts":{"check":null}}`, `{"scripts":{"check":false}}`,
		`{"scripts":{"check":0}}`, `{"scripts":{"check":{}}}`,
		`{"scripts":{"check":[]}}`,
	} {
		if got, err := packageScriptsFromJSON([]byte(raw)); err == nil || got != nil {
			t.Fatal("malformed or non-string script owner was admitted")
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
					if runErr != nil || !bytes.Contains(output, []byte("--- PASS: "+target.name)) {
						t.Fatal("canonical script owner did not execute its named oracle successfully")
					}
					return
				}
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) || exit.ExitCode() != 1 ||
					!bytes.Contains(output, []byte("--- FAIL: "+target.name)) || !bytes.Contains(output, []byte(target.failure)) {
					t.Fatal("case-shadowed script owner did not fail its actual command assertion")
				}
			})
		}
	}
}
