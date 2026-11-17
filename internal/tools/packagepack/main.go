package main

import (
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
)

func main() {
	if err := run(); err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
}
