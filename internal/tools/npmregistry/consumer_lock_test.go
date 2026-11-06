package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestVerifyConsumerLockBindsOnlyTheCandidateArchive(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "npm-pack.json")
	lock := filepath.Join(root, "package-lock.json")
	writeFixture(t, candidate, `[{
		"name":"@example/cli","version":"1.2.3","filename":"example-cli-1.2.3.tgz","integrity":"sha512-expected","shasum":"abc"
	}]`)
	valid := `{
		"lockfileVersion":3,
		"packages":{
			"":{"dependencies":{"@example/cli":"1.2.3"}},
			"node_modules/@example/cli":{
				"version":"1.2.3","resolved":"https://registry.npmjs.org/@example/cli/-/cli-1.2.3.tgz",
				"integrity":"sha512-expected","bin":{"cli":"dist/cli"}
			}
		}
	}`
	writeFixture(t, lock, valid)
	if err := verifyConsumerLock(candidate, lock); err != nil {
		t.Fatalf("valid npm lock rejected: %v", err)
	}
	for _, test := range []struct{ name, before, after string }{
		{"range", `"@example/cli":"1.2.3"`, `"@example/cli":"^1.2.3"`},
		{"version", `"version":"1.2.3"`, `"version":"1.2.4"`},
		{"format", `"lockfileVersion":3`, `"lockfileVersion":2`},
		{"origin", "https://registry.npmjs.org", "https://registry.example.com"},
		{"integrity", "sha512-expected", "sha512-other"},
		{"executable", "dist/cli", "dist/unreviewed"},
		{"unresolved dependency", `"bin":{`, `"dependencies":{"unreviewed":"1.0.0"},"bin":{`},
		{"link", `"version":"1.2.3"`, `"version":"1.2.3","link":true`},
		{"bundle", `"version":"1.2.3"`, `"version":"1.2.3","inBundle":true`},
		{"extra dependency", `"node_modules/@example/cli":{`, `"node_modules/unreviewed":{},"node_modules/@example/cli":{`},
		{"ambiguous integrity", `"integrity":"sha512-expected"`, `"integrity":"sha512-other","integrity":"sha512-expected"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := strings.Replace(valid, test.before, test.after, 1)
			if mutated == valid {
				t.Fatal("fixture mutation did not apply")
			}
			writeFixture(t, lock, mutated)
			if err := verifyConsumerLock(candidate, lock); err == nil {
				t.Fatal("mismatched npm lock was admitted")
			}
		})
	}
	t.Run("type errors omit unadmitted package keys", func(t *testing.T) {
		const key = "UNADMITTED_LOCK_MAP_KEY"
		writeFixture(t, lock, `{"lockfileVersion":3,"packages":{"`+key+`":{"version":7}}}`)
		err := verifyConsumerLock(candidate, lock)
		if err == nil || !strings.Contains(err.Error(), "invalid JSON value type") || strings.Contains(err.Error(), key) {
			t.Fatalf("expected a bounded JSON type diagnostic without the caller key, got %v", err)
		}
	})
}

func TestReleaseConsumerBindsTheLockBeforeInstallingAndExecuting(t *testing.T) {
	script := releaseNPMStep(t, "Verify root-only registry install and signatures")
	if !strings.HasPrefix(script, "set -euo pipefail\n") {
		t.Fatal("expected a fail-closed registry consumer step")
	}
	position := -1
	for _, fragment := range []string{
		`npm install "${package_name}@${package_version}" ` + "\\\n    --package-lock-only \\",
		`go -C "$repo_root" run ./internal/tools/npmregistry verify-consumer-lock ` + "\\\n" +
			`  "$repo_root/artifacts/package/npm-pack.json" "$consumer/package-lock.json"`,
		`npm ci --ignore-scripts`,
		`npm audit signatures`,
		`./node_modules/.bin/agentic-proofkit`,
	} {
		next := strings.Index(script, fragment)
		if next <= position {
			t.Fatalf("missing or reordered registry consumer command: %s", fragment)
		}
		position = next
	}
}

func TestReleaseCaptureWaitsForAnAcceptedUploadWithoutRepublishing(t *testing.T) {
	script := releaseNPMStep(t, "Capture published registry artifact identity")
	const control = `
elapsed=0
npm() {
  case "$1" in
    pack)
      [[ " $* " == *" --prefer-online "* ]] || return 2
      printf 'probe\n' >&2
      [ "$elapsed" -ge "$AVAILABLE_AFTER" ];;
    run) printf 'registry evidence\n';;
    *) printf 'unexpected npm command\n' >&2; exit 2;;
  esac
}
node() {
  if [ "$#" -eq 0 ]; then printf '@example/cli\n'; else printf '1.2.3\n'; fi
}
go() { printf 'capture admitted\n'; }
sleep() { elapsed=$((elapsed + $1)); }
`
	for _, availableAfter := range []int{450, 1200} {
		t.Run(strconv.Itoa(availableAfter), func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "/bin/bash", "-c", control+script)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "AVAILABLE_AFTER="+strconv.Itoa(availableAfter), "REGISTRY_URL=https://registry.npmjs.org")
			output, err := cmd.CombinedOutput()
			observed := string(output)
			if availableAfter == 450 {
				if err != nil || strings.Count(observed, "probe\n") != 31 ||
					!strings.Contains(observed, "capture admitted\nregistry evidence\n") {
					t.Fatalf("delayed availability did not reach admitted evidence: %v\n%s", err, output)
				}
			} else if err == nil || strings.Count(observed, "probe\n") != 80 ||
				strings.Contains(observed, "capture admitted") || !strings.Contains(observed, "check the registry before rerunning") {
				t.Fatalf("persistent unavailability did not stop safely: %v\n%s", err, output)
			}
		})
	}
}

func releaseNPMStep(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Name, Run string }
		}
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	var script string
	var count int
	for _, step := range workflow.Jobs["publish"].Steps {
		if step.Name == name {
			script = step.Run
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one npm publisher step %q, got %d", name, count)
	}
	return script
}
