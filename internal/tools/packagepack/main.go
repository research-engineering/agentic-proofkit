package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/tools/npmpack"
)

func main() {
	if err := run(); err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	packageDir := filepath.Join("artifacts", "package")
	if err := os.RemoveAll(packageDir); err != nil {
		return err
	}
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		return err
	}
	records := []npmpack.Record{}
	rootRecords, err := npmPack(".")
	if err != nil {
		return err
	}
	records = append(records, rootRecords...)
	sort.Slice(records, func(left int, right int) bool {
		return records[left].Name < records[right].Name
	})
	content, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(packageDir, "npm-pack.json"), append(content, '\n'), 0o644)
}

func npmPack(packageRoot string) ([]npmpack.Record, error) {
	command := exec.Command("npm", "--silent", "pack", "--json", "--pack-destination", filepath.Join("artifacts", "package"), packageRoot)
	stderr := diagnostic.NewStderrCapture()
	command.Stderr = stderr
	output, err := command.Output()
	if err != nil {
		if childErr := stderr.Failure("npm pack child stderr"); childErr != nil {
			return nil, fmt.Errorf("npm pack %s: %w; %s", packageRoot, err, childErr)
		}
		return nil, fmt.Errorf("npm pack %s: %w", packageRoot, err)
	}
	record, err := npmpack.DecodeNPM12Report(bytes.NewReader(output), int64(len(output)))
	if err != nil {
		return nil, fmt.Errorf("parse npm pack output for %s: %w", packageRoot, err)
	}
	return []npmpack.Record{record}, nil
}
