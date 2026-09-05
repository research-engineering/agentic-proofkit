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
	interceptions := 0
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
		for index, path := range paths {
			if err := os.WriteFile(filepath.Join(root, path), before[index], 0o644); err != nil {
				t.Fatal(err)
			}
		}
		interceptions++
		return result, nil
	}
	if err := workflowsmoke.Verify(t.Context(), run); err == nil {
		t.Fatal("an update carrier retaining prior bytes passed its installed witness")
	}
	if interceptions == 0 {
		t.Fatal("the update-effect mutation was not executed")
	}
}
