package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/jsonreportcliadaptersource"
)

func TestReleaseWorkflowInstalledAdapterBundleMatchesOwner(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	steps := workflow.Jobs["publish"].Steps
	index, err := uniqueStepIndex(steps, "Verify root-only registry install and signatures")
	if err != nil || index < 0 {
		t.Fatalf("registry install verification step: index=%d error=%v", index, err)
	}
	const start = "\nnode - registry-install-json-adapter-source.json /tmp/proofkit-owner-json-adapter-source.json <<'ADAPTER_BUNDLE'\n"
	_, body, found := strings.Cut(steps[index].Run, start)
	program, tail, closed := strings.Cut(body, "\nADAPTER_BUNDLE\n")
	if !found || !closed || program == "" || strings.Contains(tail, start) {
		t.Fatal("missing or ambiguous installed adapter bundle verifier")
	}
	owner, err := jsonreportcliadaptersource.Build("typescript", "json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(installed, expected map[string]any)
		want   string
	}{
		{name: "matching"},
		{"retired schema", func(got, _ map[string]any) { got["schemaVersion"] = 2 }, "schemaVersion mismatch"},
		{"retired generator", func(got, _ map[string]any) {
			got["generatorId"] = "proofkit.json-report-cli-adapter-source.typescript.v3"
		}, "generatorId mismatch"},
		{"changed exports", func(got, _ map[string]any) { got["exportedSymbols"] = []string{"different"} }, "bundle does not match"},
		{"changed non-claims", func(got, _ map[string]any) { got["nonClaims"] = []string{"different"} }, "bundle does not match"},
		{"different self-consistent source", func(got, _ map[string]any) {
			source := got["source"].(string) + "\n// different source\n"
			got["source"] = source
			got["sourceSha256"] = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(source)))
		}, "bundle does not match"},
		{"matching forged hash", func(got, want map[string]any) {
			got["sourceSha256"], want["sourceSha256"] = "sha256:wrong", "sha256:wrong"
		}, "source hash mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installed, expected := maps.Clone(owner), maps.Clone(owner)
			if tc.mutate != nil {
				tc.mutate(installed, expected)
			}
			dir := t.TempDir()
			installedPath, ownerPath := filepath.Join(dir, "installed.json"), filepath.Join(dir, "owner.json")
			writeBundle := func(path string, bundle map[string]any) {
				t.Helper()
				data, err := json.Marshal(bundle)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeBundle(installedPath, installed)
			writeBundle(ownerPath, expected)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "node", "-", installedPath, ownerPath)
			command.Dir = dir
			command.Stdin = strings.NewReader(program)
			output, err := command.CombinedOutput()
			if tc.want == "" {
				if err != nil || len(output) != 0 {
					t.Fatalf("matching bundle: error=%v output=%s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), tc.want) {
				t.Fatalf("verifier did not reject %q: error=%v output=%s", tc.want, err, output)
			}
		})
	}
}
