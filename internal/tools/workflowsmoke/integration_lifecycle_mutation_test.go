package workflowsmoke_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func TestInstalledLifecycleWitnessRejectsUpdateWithoutEffects(t *testing.T) {
	for _, selectedTool := range []string{"codex", "claude"} {
		t.Run(selectedTool, func(t *testing.T) {
			if err := workflowsmoke.Verify(t.Context(), applicationRunner); err != nil {
				t.Fatalf("positive lifecycle control failed: %v", err)
			}
			interceptions := 0
			var replay *workflowsmoke.Result
			run := func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, error) {
				args := invocation.Args
				operation := slices.Index(args, "--operation")
				if len(args) < 2 || args[0] != "integration" || args[1] != "apply" || operation < 0 || operation+1 >= len(args) || args[operation+1] != "update" {
					return applicationRunner(ctx, invocation)
				}
				toolIndex, rootIndex := slices.Index(args, "--tool"), slices.Index(args, "--repo-root")
				if toolIndex < 0 || rootIndex < 0 || toolIndex+1 >= len(args) || rootIndex+1 >= len(args) {
					t.Fatal("update witness omitted its exact tool or root")
				}
				tool, root := args[toolIndex+1], args[rootIndex+1]
				if tool != selectedTool {
					return applicationRunner(ctx, invocation)
				}
				interceptions++
				if replay != nil {
					return *replay, nil
				}
				bootstrap := ".agents/skills/agentic-proofkit/SKILL.md"
				if tool == "claude" {
					bootstrap = ".claude/skills/agentic-proofkit/SKILL.md"
				}
				paths := []string{bootstrap, "proofkit/integrations/" + tool + ".v1.json"}
				before := make([][]byte, len(paths))
				for index, path := range paths {
					content, err := os.ReadFile(filepath.Join(root, path))
					if err != nil {
						t.Fatal(err)
					}
					before[index] = content
				}
				result, err := applicationRunner(ctx, invocation)
				if err != nil || result.ExitCode != 0 {
					t.Fatalf("positive update control failed: %v", err)
				}
				// Keep valid process/replay outcomes while mutating only the disk effect.
				second, err := applicationRunner(ctx, invocation)
				if err != nil || second.ExitCode != 0 {
					t.Fatalf("positive replay control failed: %v", err)
				}
				replay = &second
				for index, path := range paths {
					if err := os.WriteFile(filepath.Join(root, path), before[index], 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return result, nil
			}
			if err := workflowsmoke.Verify(t.Context(), run); err == nil || err.Error() != "installed lifecycle did not preserve source bytes" {
				t.Fatalf("update-effect mutation must fail at the source-byte oracle: %v", err)
			}
			if interceptions != 2 {
				t.Fatalf("update-effect mutation intercepted %d calls, want apply and replay", interceptions)
			}
		})
	}
}
