package workflowsmoke_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func TestVerifyAcceptsApplicationCLI(t *testing.T) {
	if err := workflowsmoke.Verify(applicationRunner); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsCarrierContractMutations(t *testing.T) {
	mutations := []struct {
		name  string
		match string
		apply func(workflowsmoke.Result) workflowsmoke.Result
	}{
		{name: "planner identity", match: "change-workflow-plan --input -", apply: replaceStdout(`{"reportKind":"wrong"}\n`)},
		{name: "compact layout", match: "--json-layout compact change-workflow-plan --input -", apply: replaceStdout("{\n  \"reportKind\": \"proofkit.change-workflow-plan\"\n}\n")},
		{name: "envelope identity", match: "change-workflow-plan --input - --agent-envelope", apply: replaceStdout(`{"envelopeId":"wrong"}\n`)},
		{name: "text styling", match: "change-workflow-plan --input - --format text --color never", apply: replaceStdout("\x1b[31mChange workflow plan\x1b[0m\n")},
		{name: "failure stdout", match: "change-workflow-plan", apply: func(result workflowsmoke.Result) workflowsmoke.Result {
			result.Stdout = []byte("unexpected")
			return result
		}},
		{name: "guidance slots", match: "native-evidence-guidance", apply: replaceStdout(`{"guidanceId":"proofkit.native-evidence-guidance.v1","slots":[]}\n`)},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			applied := false
			runner := func(input []byte, args ...string) (workflowsmoke.Result, error) {
				result, err := applicationRunner(input, args...)
				if err == nil && !applied && strings.Join(args, " ") == mutation.match {
					result = mutation.apply(result)
					applied = true
				}
				return result, err
			}
			if err := workflowsmoke.Verify(runner); err == nil {
				t.Fatal("carrier mutation was accepted")
			}
			if !applied {
				t.Fatalf("mutation route %q was not exercised", mutation.match)
			}
		})
	}
}

func applicationRunner(input []byte, args ...string) (workflowsmoke.Result, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := app.Run(context.Background(), args, bytes.NewReader(input), &stdout, &stderr)
	return workflowsmoke.Result{ExitCode: exitCode, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

func replaceStdout(value string) func(workflowsmoke.Result) workflowsmoke.Result {
	return func(result workflowsmoke.Result) workflowsmoke.Result {
		result.Stdout = []byte(value)
		return result
	}
}
