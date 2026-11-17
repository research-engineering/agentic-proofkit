package cliexec

import (
	"strings"
	"testing"
)

func TestSafeDisplayArgvChecksTheComposedPresentation(t *testing.T) {
	for _, path := range []string{"inputs/a b/authorization:", "inputs/unsafe\u202e.json", "inputs/bad\xff.json"} {
		if display, err := SafeDisplayArgv([]string{BinaryName, "witness-plan", "--input", path}, "prepared command"); err == nil || display != "" || strings.Contains(err.Error(), path) {
			t.Fatal("unsafe composed display was retained or disclosed")
		}
	}
	for _, prefix := range [][]string{{BinaryName}, {"npm", "exec", "--offline", "--", BinaryName}, {"/opt/task-validation/bin/python", "-m", "agentic_proofkit"}} {
		for _, path := range []string{"inputs/a b.json", "inputs/a'b.json ", "inputs/task-validation.json"} {
			argv := append(append([]string{}, prefix...), "witness-plan", "--input", path)
			display, err := SafeDisplayArgv(argv, "prepared command")
			if err != nil || display != DisplayArgv(argv) {
				t.Fatal("safe structural presentation lost exact quoting or identity")
			}
		}
	}
}
