package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/npmpack"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagearchive"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packagemetadata"
)

const packageDirectory = "artifacts/package"

func run() error {
	return pack(os.RemoveAll, artifactfile.WriteAtomic)
}

// The two effect parameters make cleanup and final commit failures independently
// observable; child execution and admission use the same path as the entrypoint.
func pack(cleanup func(string) error, publish func(string, string, []byte, fs.FileMode) error) (result error) {
	manifest, err := packagemetadata.Read(".")
	if err != nil {
		return err
	}
	if err := artifactfile.ResetDirectory(".", packageDirectory); err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "proofkit-npm-pack-*")
	if err != nil {
		return fmt.Errorf("create npm pack staging: %w", err)
	}
	pendingCleanup := true
	defer func() {
		if pendingCleanup {
			result = errors.Join(result, cleanup(stage))
		}
	}()
	record, err := npmPack(".", stage)
	if err != nil {
		return err
	}
	if err := admitRecordIdentity(record, manifest); err != nil {
		return err
	}
	archive, archiveMode, err := captureOutput(stage, record.Filename, packagearchive.MaxCompressedBytes)
	if err != nil {
		return err
	}
	if err := admitArchive(archive, record); err != nil {
		return err
	}
	report, err := json.MarshalIndent([]npmpack.Record{record}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "npm-pack.json"), append(report, '\n'), 0o644); err != nil {
		return err
	}
	report, reportMode, err := captureOutput(stage, "npm-pack.json", 16<<20)
	if err != nil {
		return err
	}
	// Required cleanup finishes before either final output. An admitted tar may
	// remain if the last report publication fails; this is not a transaction.
	pendingCleanup = false
	if err := cleanup(stage); err != nil {
		return fmt.Errorf("clean npm pack staging: %w", err)
	}
	if err := publish(".", packageDirectory+"/"+record.Filename, archive, archiveMode); err != nil {
		return err
	}
	return publish(".", packageDirectory+"/npm-pack.json", report, reportMode)
}

func npmPack(packageRoot, stage string) (npmpack.Record, error) {
	command := exec.Command("npm", "--silent", "pack", "--json", "--ignore-scripts", "--pack-destination", stage, packageRoot)
	stderr := diagnostic.NewStderrCapture()
	command.Stderr = stderr
	output, err := command.Output()
	if err != nil {
		if childErr := stderr.Failure("npm pack child stderr"); childErr != nil {
			return npmpack.Record{}, fmt.Errorf("npm pack: %w; %s", err, childErr)
		}
		return npmpack.Record{}, fmt.Errorf("npm pack: %w", err)
	}
	return npmpack.DecodeNPM12Report(bytes.NewReader(output), int64(len(output)))
}

func admitRecordIdentity(record npmpack.Record, manifest packagemetadata.Record) error {
	expected := strings.ReplaceAll(strings.TrimPrefix(record.Name, "@"), "/", "-") + "-" + record.Version + ".tgz"
	if record.Name != manifest.Name || record.Version != manifest.Version {
		return fmt.Errorf("npm pack record must match source package name and version")
	}
	if record.Filename != expected || !fs.ValidPath(record.Filename) || filepath.Base(record.Filename) != record.Filename || strings.ContainsAny(record.Filename, "\\\x00") {
		return fmt.Errorf("npm pack filename must be the canonical package basename")
	}
	return nil
}

func captureOutput(stage, name string, limit int64) ([]byte, fs.FileMode, error) {
	content, err := artifactfile.ReadBounded(stage, name, limit)
	if err != nil {
		return nil, 0, err
	}
	info, err := os.Lstat(filepath.Join(stage, name))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 || info.Mode()&^fs.FileMode(0o777) != 0 {
		return nil, 0, fmt.Errorf("npm staged output must be a non-executable regular file")
	}
	return content, info.Mode().Perm(), nil
}
