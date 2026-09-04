package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
)

func TestPipInstallArgumentsAreIsolatedAndOffline(t *testing.T) {
	want := []string{"-m", "pip", "--isolated", "install", "--no-index", "--no-deps", "--no-input", "/tmp/package.whl"}
	if got := pipInstallArguments("/tmp/package.whl"); !reflect.DeepEqual(got, want) {
		t.Fatalf("pipInstallArguments()=%v, want %v", got, want)
	}
}

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

func TestExactDisplayedCommandRoutesAdmitBoundedMultiTokenRoutes(t *testing.T) {
	const prefix = "/venv/bin/python -m agentic_proofkit help "
	contract := testInstalledCLIContract(t)
	routes, err := exactDisplayedCommandRoutes([]byte("Commands:\n    "+prefix+"adopt plan\n"), prefix, "test command routes", contract)
	if err != nil || len(routes) != 1 || routes[0] != "adopt plan" {
		t.Fatalf("exact command routes=%v error=%v, want [adopt plan]", routes, err)
	}
	mutants := map[string]string{
		"empty token":       "adopt  plan",
		"too many tokens":   "one two three four five",
		"shell punctuation": "adopt plan;touch-pwned",
		"quoted token":      "adopt 'plan'",
	}
	for name, route := range mutants {
		t.Run(name, func(t *testing.T) {
			output := []byte("Commands:\n    " + prefix + route + "\n")
			if _, err := exactDisplayedCommandRoutes(output, prefix, "test command routes", contract); err == nil {
				t.Fatalf("mutant survived exact command-route admission: %q", route)
			}
		})
	}
}

func testInstalledCLIContract(t *testing.T) installedclicontract.Contract {
	t.Helper()
	contract, err := installedclicontract.Admit([]byte(`{"processContract":{"commandRouteGrammar":{"minimumTokens":1,"maximumTokens":4,"separator":" ","tokenPattern":"^[a-z0-9]+(?:-[a-z0-9]+)*$","ambiguityPolicy":"no_route_is_prefix_of_another"}},"commands":[{"command":"sample","route":["adopt","plan"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func TestInstalledPythonCommandRoutesRequireExactContractBijection(t *testing.T) {
	expected := map[string]string{"adopt plan": "adopt-plan", "self-check": "self-check"}
	if err := requireInstalledPythonCommandRouteBijection(
		map[string]string{"adopt plan": "adopt-plan", "self-check": "self-check"},
		expected,
	); err != nil {
		t.Fatalf("exact route bijection rejected: %v", err)
	}
	mutants := []map[string]string{
		{"adopt plan": "adopt-plan"},
		{"adopt plan": "wrong-command", "self-check": "self-check"},
		{"adopt plan": "adopt-plan", "other": "self-check"},
		{"adopt plan": "adopt-plan", "self-check": "self-check", "other": "other"},
	}
	for _, mutant := range mutants {
		if err := requireInstalledPythonCommandRouteBijection(mutant, expected); err == nil {
			t.Fatalf("route mutant survived exact bijection: %v", mutant)
		}
	}
}

func TestInstalledWheelContinuationUsesExactPythonModuleProfileWithoutNPM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Fatal("Windows wheels are not supported")
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	withWorkingDirectory(t, repositoryRoot, func() {
		runInstalledWheelContinuationWitness(t, repositoryRoot)
	})
}

func TestInstalledPythonCarrierRejectsContractReplacementRemovalAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Fatal("Windows wheels are not supported")
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	withWorkingDirectory(t, repositoryRoot, func() {
		fixture := prepareInstalledWheelFixture(t, repositoryRoot)
		if err := installPythonWheel(fixture.venvPython, fixture.wheelPath, fixture.environment); err != nil {
			t.Fatal(err)
		}
		renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, fixture.venvPython)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyInstalledPythonCarrier(fixture.consumer, fixture.environment, renderer, fixture.contract, fixture.binary); err != nil {
			t.Fatalf("exact installed carrier was rejected: %v", err)
		}
		contractPath := installedPythonContractPath(t, fixture)
		externalContractPath := filepath.Join(t.TempDir(), "cli-contract.v2.json")
		if err := os.WriteFile(externalContractPath, fixture.contract, 0o600); err != nil {
			t.Fatal(err)
		}
		restore := func(t *testing.T) {
			t.Helper()
			if err := os.Remove(contractPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.WriteFile(contractPath, fixture.contract, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		mutations := []struct {
			name  string
			apply func(*testing.T)
		}{
			{name: "replacement", apply: func(t *testing.T) {
				if err := os.WriteFile(contractPath, append(append([]byte(nil), fixture.contract...), '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "removal", apply: func(t *testing.T) {
				if err := os.Remove(contractPath); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "symlink", apply: func(t *testing.T) {
				if err := os.Remove(contractPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(externalContractPath, contractPath); err != nil {
					t.Fatal(err)
				}
			}},
		}
		for _, mutation := range mutations {
			t.Run(mutation.name, func(t *testing.T) {
				restore(t)
				mutation.apply(t)
				if _, err := verifyInstalledPythonCarrier(fixture.consumer, fixture.environment, renderer, fixture.contract, fixture.binary); err == nil {
					t.Fatal("mutated installed contract was accepted")
				}
			})
		}
	})
}

func TestPythonVerificationEnvironmentRemovesAmbientImportControls(t *testing.T) {
	environment := pythonVerificationEnvironment([]string{
		"PATH=/usr/bin",
		"PYTHONHOME=/tmp/home",
		"PYTHONPATH=/tmp/path",
		"PYTHONNOUSERSITE=0",
		"proofkit_fixture=retained",
	}, map[string]string{
		"PATH":       "/empty",
		"PYTHONPATH": "/attacker",
	})
	values := map[string]string{}
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("environment entry is malformed: %q", entry)
		}
		if _, duplicate := values[name]; duplicate {
			t.Fatalf("environment contains duplicate key %q", name)
		}
		values[name] = value
	}
	if values["PATH"] != "/empty" || values["proofkit_fixture"] != "retained" {
		t.Fatalf("non-Python environment was not preserved exactly: %v", values)
	}
	if values["PYTHONNOUSERSITE"] != "1" || values["PYTHONSAFEPATH"] != "1" {
		t.Fatalf("Python isolation controls = %v, want enabled", values)
	}
	for name := range values {
		if strings.HasPrefix(strings.ToUpper(name), "PYTHON") && name != "PYTHONNOUSERSITE" && name != "PYTHONSAFEPATH" {
			t.Fatalf("ambient Python import control survived: %s", name)
		}
	}
}

func runInstalledWheelContinuationWitness(t *testing.T, repositoryRoot string) {
	t.Helper()
	fixture := prepareInstalledWheelFixture(t, repositoryRoot)
	if err := verifyInstalledPythonWheel(fixture.consumer, fixture.venvPython, fixture.wheelPath, fixture.contract, fixture.binary, fixture.environment); err != nil {
		t.Fatal(err)
	}
}

type installedWheelFixture struct {
	binary      []byte
	consumer    string
	contract    []byte
	environment []string
	venvPython  string
	wheelPath   string
}

func prepareInstalledWheelFixture(t *testing.T, repositoryRoot string) installedWheelFixture {
	t.Helper()
	target, err := currentTarget()
	if err != nil {
		t.Fatalf("current platform has no admitted wheel target: %v", err)
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
	environment := pythonVerificationEnvironment(os.Environ(), nil)
	if output, err := runCommandWithEnvironment("", environment, python, "-m", "venv", consumer); err != nil {
		t.Fatalf("create Python consumer venv: %v\n%s", err, output)
	}
	venvPython := filepath.Join(consumer, "bin", "python")
	expectedContract, err := os.ReadFile(filepath.Join(repositoryRoot, sourceCLIContractPath))
	if err != nil {
		t.Fatal(err)
	}
	return installedWheelFixture{
		binary:      binaryContent,
		consumer:    consumer,
		contract:    expectedContract,
		environment: environment,
		venvPython:  venvPython,
		wheelPath:   wheelPath,
	}
}

func installedPythonContractPath(t *testing.T, fixture installedWheelFixture) string {
	t.Helper()
	const script = `
import os
from importlib.resources import files

print(os.fspath(files("agentic_proofkit").joinpath("proofkit", "cli-contract.v2.json")))
`
	output, err := runCommandWithEnvironment("", fixture.environment, fixture.venvPython, "-I", "-c", script)
	if err != nil {
		t.Fatalf("resolve installed contract path: %v\n%s", err, output)
	}
	path := strings.TrimSuffix(string(output), "\n")
	resolvedConsumer, err := filepath.EvalSymlinks(fixture.consumer)
	if err != nil {
		t.Fatal(err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(resolvedConsumer, resolvedPath)
	if err != nil || !filepath.IsLocal(relative) || filepath.IsAbs(relative) {
		t.Fatalf("installed contract path %q is outside consumer root %q", path, fixture.consumer)
	}
	return path
}
