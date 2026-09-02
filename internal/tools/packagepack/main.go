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
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
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
	records, err := decodeNPM12PackOutput(output)
	if err != nil {
		return nil, fmt.Errorf("parse npm pack output for %s: %w", packageRoot, err)
	}
	return records, nil
}

func decodeNPM12PackOutput(output []byte) ([]packRecord, error) {
	keyed, err := admission.DecodeTypedJSON[map[string]packRecord](bytes.NewReader(output), int64(len(output)))
	if err != nil {
		return nil, err
	}
	if len(keyed) != 1 {
		return nil, fmt.Errorf("npm pack output must contain exactly one keyed record")
	}
	for key, record := range keyed {
		if key != record.Name {
			return nil, fmt.Errorf("npm pack output key must equal the record package name")
		}
		return []packRecord{record}, nil
	}
	return nil, fmt.Errorf("npm pack output must contain exactly one keyed record")
}
