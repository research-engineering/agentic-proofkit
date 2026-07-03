package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

type packRecord struct {
	Filename  string `json:"filename"`
	ID        string `json:"id,omitempty"`
	Integrity string `json:"integrity"`
	Name      string `json:"name"`
	Shasum    string `json:"shasum"`
	Version   string `json:"version"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
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
	records := []packRecord{}
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

func npmPack(packageRoot string) ([]packRecord, error) {
	output, err := exec.Command("npm", "pack", "--json", "--pack-destination", filepath.Join("artifacts", "package"), packageRoot).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("npm pack %s: %w\n%s", packageRoot, err, output)
	}
	records, err := admission.DecodeTypedJSON[[]packRecord](bytes.NewReader(output), int64(len(output)))
	if err != nil {
		return nil, fmt.Errorf("parse npm pack output for %s: %w\n%s", packageRoot, err, output)
	}
	if len(records) != 1 {
		return nil, fmt.Errorf("npm pack %s must return exactly one record", packageRoot)
	}
	return records, nil
}
