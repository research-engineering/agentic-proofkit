package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExactDisplayedRouteOperandsRejectsWhitespaceAndExpansionMutants(t *testing.T) {
	const prefix = "/venv/bin/python -m agentic_proofkit help "
	operands, err := exactDisplayedRouteOperands([]byte("Commands:\n    "+prefix+"self-check\n"), prefix, "test routes")
	if err != nil || len(operands) != 1 || operands[0] != "self-check" {
		t.Fatalf("exact route operands=%v error=%v, want [self-check]", operands, err)
	}
	mutants := map[string]string{
		"two-space indent": "  " + prefix + "self-check\n",
		"leading NBSP":     "\u00a0   " + prefix + "self-check\n",
		"trailing NBSP":    "    " + prefix + "self-check\u00a0\n",
		"semicolon":        "    " + prefix + "self-check;touch-pwned\n",
		"expansion":        "    " + prefix + "$(touch-pwned)\n",
		"duplicate":        "    " + prefix + "self-check\n    " + prefix + "self-check\n",
		"empty operand":    "    " + prefix + "\n",
	}
	for name, output := range mutants {
		t.Run(name, func(t *testing.T) {
			if _, err := exactDisplayedRouteOperands([]byte(output), prefix, "test routes"); err == nil {
				t.Fatalf("mutant survived exact route admission: %q", strings.TrimSuffix(output, "\n"))
			}
		})
	}
}

func TestInstalledWheelContinuationUsesExactPythonModuleProfileWithoutNPM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows wheels are not supported")
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	withWorkingDirectory(t, repositoryRoot, func() {
		runInstalledWheelContinuationWitness(t, repositoryRoot)
	})
}

func runInstalledWheelContinuationWitness(t *testing.T, repositoryRoot string) {
	t.Helper()
	target, err := currentTarget()
	if err != nil {
		t.Skipf("current platform has no admitted wheel target: %v", err)
	}
	manifest, err := readPackageJSON()
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), "agentic-proofkit")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/agentic-proofkit")
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build current native CLI: %v\n%s", err, output)
	}
	binaryContent, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := wheelEntries(manifest, target, binaryContent)
	if err != nil {
		t.Fatal(err)
	}
	wheelPath := filepath.Join(t.TempDir(), wheelFilename(manifest.Version, target))
	if err := writeWheel(wheelPath, entries); err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required for the installed wheel continuation witness: %v", err)
	}
	consumer := t.TempDir()
	if output, err := runCommand("", python, "-m", "venv", consumer); err != nil {
		t.Fatalf("create Python consumer venv: %v\n%s", err, output)
	}
	venvPython := filepath.Join(consumer, "bin", "python")
	if err := verifyInstalledPythonWheel(consumer, venvPython, wheelPath); err != nil {
		t.Fatal(err)
	}
}
