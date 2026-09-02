package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/trustedpublisher"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
	"github.com/research-engineering/agentic-proofkit/internal/tools/npmpack"
)

const (
	artifactKind       = "proofkit.published-registry-artifact-set.v1"
	maxPackRecordBytes = 8 << 20
	schemaVersion      = 1
)

type packRecord struct {
	Filename  string `json:"filename"`
	Integrity string `json:"integrity"`
	Name      string `json:"name"`
	Shasum    string `json:"shasum"`
	Version   string `json:"version"`
}

type registryArtifactSet struct {
	ArtifactKind       string       `json:"artifactKind"`
	AuthorityChannel   string       `json:"authorityChannel"`
	AuthorityValidator string       `json:"authorityValidator"`
	NonClaims          []string     `json:"nonClaims"`
	Packages           []packRecord `json:"packages"`
	PublicationMode    string       `json:"publicationMode"`
	Registry           string       `json:"registry"`
	SchemaVersion      int          `json:"schemaVersion"`
	Source             string       `json:"source"`
}

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "capture-pack-reports" {
		if len(os.Args) < 4 {
			err = fmt.Errorf("capture-pack-reports requires an output path and at least one input report")
		} else {
			err = capturePackReports(os.Args[2], os.Args[3:])
		}
	} else if len(os.Args) != 1 {
		err = fmt.Errorf("unsupported npm registry evidence argument")
	} else {
		err = run(".")
	}
	if err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
}

func capturePackReports(outputPath string, inputPaths []string) error {
	records := make([]npmpack.Record, 0, len(inputPaths))
	seenNames := map[string]struct{}{}
	seenFiles := map[string]struct{}{}
	for _, inputPath := range inputPaths {
		file, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		record, decodeErr := npmpack.DecodeNPM12Report(file, maxPackRecordBytes)
		closeErr := file.Close()
		err = errors.Join(decodeErr, closeErr)
		if err != nil {
			return fmt.Errorf("admit npm pack report: %w", err)
		}
		if _, duplicate := seenNames[record.Name]; duplicate {
			return fmt.Errorf("npm pack reports contain duplicate package name")
		}
		if _, duplicate := seenFiles[record.Filename]; duplicate {
			return fmt.Errorf("npm pack reports contain duplicate package filename")
		}
		seenNames[record.Name] = struct{}{}
		seenFiles[record.Filename] = struct{}{}
		records = append(records, record)
	}
	sort.Slice(records, func(left int, right int) bool {
		return records[left].Name < records[right].Name
	})
	return writeJSON(outputPath, records)
}

func run(root string) error {
	local, err := readPackRecords(filepath.Join(root, "artifacts", "package", "npm-pack.json"), "local npm package evidence")
	if err != nil {
		return err
	}
	registry, err := readPackRecords(filepath.Join(root, "artifacts", "registry", "npm-pack.json"), "npm registry evidence")
	if err != nil {
		return err
	}
	if err := requireExactPackageSet(registry, local); err != nil {
		return err
	}
	modeBytes, err := os.ReadFile(filepath.Join(root, "artifacts", "registry", "npm-publication-mode.txt"))
	if err != nil {
		return err
	}
	if len(modeBytes) > 64 {
		return fmt.Errorf("npm publication mode exceeds byte limit")
	}
	modeText, err := unicodepolicy.DecodeUTF8(modeBytes)
	if err != nil {
		return fmt.Errorf("npm publication mode is not valid UTF-8")
	}
	mode, err := trustedpublisher.AdmitPublicationMode(strings.TrimSpace(modeText), "npm registry evidence publicationMode")
	if err != nil {
		return err
	}
	source, ok := releasechannel.NPMRegistryEvidenceSource(mode)
	if !ok {
		return fmt.Errorf("npm registry evidence publication mode has no canonical source")
	}
	channel := releasechannel.Must(releasechannel.RegistryRelease)
	record := registryArtifactSet{
		ArtifactKind:       artifactKind,
		AuthorityChannel:   string(channel.ID),
		AuthorityValidator: channel.AuthorityValidator,
		NonClaims: []string{
			"npm registry identity does not prove consumer installation, consumer adoption, or rollout.",
		},
		Packages:        registry,
		PublicationMode: mode,
		Registry:        channel.RegistryURL,
		SchemaVersion:   schemaVersion,
		Source:          source,
	}
	return writeJSON(filepath.Join(root, "artifacts", "registry", "published-registry-artifact-set.json"), record)
}

func readPackRecords(path string, context string) ([]packRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	records, err := admission.DecodeTypedJSON[[]packRecord](file, maxPackRecordBytes)
	if err != nil {
		return nil, fmt.Errorf("admit %s: %w", path, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	seenNames := map[string]struct{}{}
	seenFiles := map[string]struct{}{}
	for index := range records {
		record := &records[index]
		fields := []struct {
			name  string
			value *string
		}{
			{name: "filename", value: &record.Filename},
			{name: "integrity", value: &record.Integrity},
			{name: "name", value: &record.Name},
			{name: "shasum", value: &record.Shasum},
			{name: "version", value: &record.Version},
		}
		for _, field := range fields {
			value, err := admit.NonEmptyText(*field.value, fmt.Sprintf("%s[%d].%s", context, index, field.name))
			if err != nil {
				return nil, err
			}
			*field.value = value
		}
		if _, duplicate := seenNames[record.Name]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate package name", context)
		}
		if _, duplicate := seenFiles[record.Filename]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate package filename", context)
		}
		seenNames[record.Name] = struct{}{}
		seenFiles[record.Filename] = struct{}{}
	}
	sort.Slice(records, func(left int, right int) bool {
		return records[left].Filename < records[right].Filename
	})
	return records, nil
}

func requireExactPackageSet(registry []packRecord, local []packRecord) error {
	if len(registry) != len(local) {
		return fmt.Errorf("npm registry package set must match local package evidence")
	}
	localByFilename := make(map[string]packRecord, len(local))
	for _, record := range local {
		localByFilename[record.Filename] = record
	}
	for _, record := range registry {
		expected, ok := localByFilename[record.Filename]
		if !ok || record != expected {
			return fmt.Errorf("npm registry package %s does not match local package identity and bytes", record.Filename)
		}
	}
	return nil
}

func writeJSON(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".npm-registry-evidence-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
