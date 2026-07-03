package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: go run ./internal/tools/pythonpackage <build|build-current|verify|verify-current>")
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
	default:
		return fmt.Errorf("unknown python package command %q", args[0])
	}
}
