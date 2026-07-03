package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
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
	ContentBase64 string `json:"contentBase64,omitempty"`
	Path          string `json:"path"`
	State         string `json:"state"`
}

func main() {
	repoRoot, err := repoRoot()
	if err != nil {
		exit(err)
	}
	files, err := repoFiles(repoRoot)
	if err != nil {
		exit(err)
	}
	records := make([]fileRecord, 0, len(files))
	for _, path := range files {
		record := fileRecord{Path: path, State: "present"}
		if isBinaryCandidate(path) {
			records = append(records, record)
			continue
		}
		data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(path)))
		if os.IsNotExist(err) {
			record.State = "missing"
			records = append(records, record)
			continue
		}
		if err != nil {
			exit(fmt.Errorf("read %s: %w", path, err))
		}
		record.ContentBase64 = base64.StdEncoding.EncodeToString(data)
		records = append(records, record)
	}
	payload := input{
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
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		exit(fmt.Errorf("encode text policy input: %w", err))
	}
}

func repoRoot() (string, error) {
	output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("resolve git repository root: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func repoFiles(repoRoot string) ([]string, error) {
	command := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	command.Dir = repoRoot
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("list git files: %w", err)
	}
	seen := map[string]struct{}{}
	files := []string{}
	for _, path := range strings.Split(string(output), "\x00") {
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
	_, _ = fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
