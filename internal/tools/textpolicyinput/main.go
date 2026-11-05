package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/textpolicy"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

var binarySuffixes = []string{
	".avif",
	".bin",
	".bmp",
	".gif",
	".ico",
	".jpeg",
	".jpg",
	".pdf",
	".png",
	".pyc",
	".svgz",
	".tgz",
	".webp",
	".zip",
}

type input struct {
	SchemaVersion int          `json:"schemaVersion"`
	ReportID      string       `json:"reportId"`
	NonClaims     []string     `json:"nonClaims"`
	Policy        policy       `json:"policy"`
	Files         []fileRecord `json:"files"`
}

type policy struct {
	AllowTab                 bool     `json:"allowTab"`
	AsciiOnly                bool     `json:"asciiOnly"`
	BinarySuffixes           []string `json:"binarySuffixes"`
	RejectTrailingWhitespace bool     `json:"rejectTrailingWhitespace"`
	RequireFinalNewline      bool     `json:"requireFinalNewline"`
}

type fileRecord struct {
	ContentBase64 *string `json:"contentBase64,omitempty"`
	Path          string  `json:"path"`
	State         string  `json:"state"`
}

const batchBudget = 8 << 20
const inputLimit = 32 << 20

func main() {
	run(os.Args[1:])
}

func run(args []string) {
	if len(args) > 1 || len(args) == 1 && args[0] != "--check" {
		exit(fmt.Errorf("usage: textpolicyinput [--check]"))
	}
	check := len(args) == 1
	repoRoot, err := repoRoot()
	if err != nil {
		exit(err)
	}
	files, err := repoFiles(repoRoot)
	if err != nil {
		exit(err)
	}
	records := []fileRecord{}
	batchBytes, failures := 0, 0
	flush := func() {
		count, err := checkBatch(records)
		if err != nil {
			exit(err)
		}
		failures += count
		records, batchBytes = nil, 0
	}
	for _, path := range files {
		record, err := readRecord(repoRoot, path)
		if err != nil {
			exit(err)
		}
		if check {
			size := len(path)*6 + 128
			if record.ContentBase64 != nil {
				size += len(*record.ContentBase64)
			}
			if len(records) > 0 && batchBytes+size > batchBudget {
				flush()
			}
			batchBytes += size
		}
		records = append(records, record)
	}
	if check {
		flush()
		if failures > 0 {
			os.Exit(1)
		}
		fmt.Printf("Text policy passed for %d inventoried paths.\n", len(files))
		return
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(batchInput(records)); err != nil {
		exit(fmt.Errorf("encode text policy input: %w", err))
	}
}

func readRecord(repoRoot, path string) (fileRecord, error) {
	record := fileRecord{Path: path, State: "present"}
	if isBinaryCandidate(path) {
		return record, nil
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(path)))
	if os.IsNotExist(err) {
		record.State = "missing"
		return record, nil
	}
	if err != nil {
		return fileRecord{}, fmt.Errorf("read %s: %w", path, err)
	}
	content := base64.StdEncoding.EncodeToString(data)
	record.ContentBase64 = &content
	return record, nil
}

func checkBatch(records []fileRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	content, err := json.Marshal(batchInput(records))
	if err != nil {
		return 0, err
	}
	// Use the same input admission and evaluation as the public command.
	value, err := admission.DecodeJSON(bytes.NewReader(content), inputLimit)
	if err != nil {
		return 0, err
	}
	report, code, err := textpolicy.Build(value)
	if err != nil {
		return 0, err
	}
	if code != 0 {
		if err := json.NewEncoder(os.Stdout).Encode(report.JSONValue()); err != nil {
			return 0, err
		}
	}
	return code, nil
}

func batchInput(records []fileRecord) input {
	return input{
		SchemaVersion: 1,
		ReportID:      "proofkit.source.text-policy",
		NonClaims: []string{
			"Proofkit source text policy input does not claim consumer repository policy.",
		},
		Policy: policy{
			AllowTab:                 true,
			AsciiOnly:                true,
			BinarySuffixes:           binarySuffixes,
			RejectTrailingWhitespace: true,
			RequireFinalNewline:      true,
		},
		Files: records,
	}
}

func repoRoot() (string, error) {
	output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("resolve git repository root: %w", err)
	}
	decoded, err := unicodepolicy.DecodeUTF8(output)
	if err != nil {
		return "", fmt.Errorf("git repository root output is not valid UTF-8")
	}
	return strings.TrimSpace(decoded), nil
}

func repoFiles(repoRoot string) ([]string, error) {
	command := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	command.Dir = repoRoot
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("list git files: %w", err)
	}
	decoded, err := unicodepolicy.DecodeUTF8(output)
	if err != nil {
		return nil, fmt.Errorf("git file inventory is not valid UTF-8")
	}
	seen := map[string]struct{}{}
	files := []string{}
	for _, path := range strings.Split(decoded, "\x00") {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		files = append(files, path)
	}
	sort.Strings(files)
	return files, nil
}

func isBinaryCandidate(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	for _, suffix := range binarySuffixes {
		if extension == suffix {
			return true
		}
	}
	return false
}

func exit(err error) {
	diagnostic.WriteError(os.Stderr, err)
	os.Exit(1)
}
