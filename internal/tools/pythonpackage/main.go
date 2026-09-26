package main

import (
	"fmt"
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: go run ./internal/tools/pythonpackage <build|build-current|verify|verify-current|verify-minimum|verify-minimum-installed>")
	}
	switch args[0] {
	case "build":
		return buildPythonPackages()
	case "build-current":
		return buildCurrentPythonPackage()
	case "verify":
		return verifyPythonPackages()
	case "verify-current":
		return verifyCurrentPythonPackage()
	case "verify-minimum":
		return verifyMinimumPython()
	case "verify-minimum-installed":
		return verifyMinimumInstalledPython()
	default:
		return fmt.Errorf("unknown python package command %q", args[0])
	}
}
