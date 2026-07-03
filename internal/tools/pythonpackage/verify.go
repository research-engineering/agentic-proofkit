package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func verifyPythonPackages() error {
	return verifyPythonPackagesForTargets(releaseTargets())
}

func verifyCurrentPythonPackage() error {
	current, err := currentTarget()
	if err != nil {
		return err
	}
	return verifyPythonPackagesForTargets([]target{current})
}

func verifyPythonPackagesForTargets(selectedTargets []target) error {
	manifest, err := readPackageJSON()
	if err != nil {
		return err
	}
	packageSet, err := readPackageSet(filepath.Join("artifacts", "pypi", "python-packages.json"))
	if err != nil {
		return err
	}
	if packageSet.ArtifactKind != artifactKind || packageSet.SchemaVersion != schemaVersion {
		return fmt.Errorf("python package set has unexpected artifact kind or schema version")
	}
	if packageSet.PackageName != packageName || packageSet.PackageVersion != manifest.Version {
		return fmt.Errorf("python package set package identity mismatch")
	}
	if len(packageSet.Packages) != len(selectedTargets) {
		return fmt.Errorf("python package set must contain %d wheels, got %d", len(selectedTargets), len(packageSet.Packages))
	}
	recordsBySuffix := map[string]wheelRecord{}
	for _, record := range packageSet.Packages {
		if _, exists := recordsBySuffix[record.PlatformSuffix]; exists {
			return fmt.Errorf("duplicate python wheel platform suffix %s", record.PlatformSuffix)
		}
		recordsBySuffix[record.PlatformSuffix] = record
	}
	for _, target := range selectedTargets {
		record, ok := recordsBySuffix[target.PlatformSuffix]
		if !ok {
			return fmt.Errorf("missing python wheel for %s", target.PlatformSuffix)
		}
		if err := verifyWheelRecord(manifest, target, record); err != nil {
			return err
		}
	}
	return verifyLocalPythonConsumer(recordsBySuffix)
}

func readPackageSet(path string) (packageSet, error) {
	return readAdmittedJSON[packageSet](path)
}

func verifyWheelRecord(manifest packageJSON, target target, record wheelRecord) error {
	if record.Name != packageName || record.Version != manifest.Version {
		return fmt.Errorf("python wheel %s package identity mismatch", record.Filename)
	}
	if record.Filename != wheelFilename(manifest.Version, target) {
		return fmt.Errorf("python wheel filename mismatch for %s: %s", target.PlatformSuffix, record.Filename)
	}
	if record.PythonTag != pythonTag || record.AbiTag != abiTag || record.PlatformTag != target.PlatformTag || record.WheelTag != target.WheelTag {
		return fmt.Errorf("python wheel tag mismatch for %s", record.Filename)
	}
	wheelPath := filepath.Join("artifacts", "pypi", record.Filename)
	sha, err := fileSHA256(wheelPath)
	if err != nil {
		return err
	}
	if sha != record.Sha256 {
		return fmt.Errorf("python wheel sha256 mismatch for %s", record.Filename)
	}
	binary, err := os.ReadFile(target.BinaryPath)
	if err != nil {
		return err
	}
	binarySHA := sha256.Sum256(binary)
	if record.BinarySha256 != fmt.Sprintf("%x", binarySHA[:]) {
		return fmt.Errorf("python wheel binary sha256 mismatch for %s", record.Filename)
	}
	return verifyWheelContents(wheelPath, manifest.Version, target)
}

func verifyWheelContents(path string, version string, target target) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()
	entries := map[string]*zip.File{}
	for _, file := range reader.File {
		if _, exists := entries[file.Name]; exists {
			return fmt.Errorf("%s contains duplicate entry %s", path, file.Name)
		}
		entries[file.Name] = file
	}
	distInfo := distInfoDir(version)
	required := []string{
		"agentic_proofkit/__init__.py",
		"agentic_proofkit/__main__.py",
		"agentic_proofkit/cli.py",
		"agentic_proofkit/bin/agentic-proofkit",
		distInfo + "/METADATA",
		distInfo + "/WHEEL",
		distInfo + "/entry_points.txt",
		distInfo + "/RECORD",
	}
	for _, entry := range required {
		if _, ok := entries[entry]; !ok {
			return fmt.Errorf("%s missing required entry %s", path, entry)
		}
	}
	for entry := range entries {
		if !contains(required, entry) {
			return fmt.Errorf("%s contains unexpected entry %s", path, entry)
		}
	}
	wheel, err := readZipFile(entries[distInfo+"/WHEEL"])
	if err != nil {
		return err
	}
	if string(wheel) != wheelMetadata(target) {
		return fmt.Errorf("%s WHEEL metadata must match release platform target %s", path, target.PlatformSuffix)
	}
	entryPointsContent, err := readZipFile(entries[distInfo+"/entry_points.txt"])
	if err != nil {
		return err
	}
	if string(entryPointsContent) != entryPoints() {
		return fmt.Errorf("%s entry_points.txt mismatch", path)
	}
	return verifyRecord(entries, distInfo+"/RECORD")
}

func verifyRecord(entries map[string]*zip.File, recordPath string) error {
	recordFile, ok := entries[recordPath]
	if !ok {
		return fmt.Errorf("missing RECORD")
	}
	content, err := readZipFile(recordFile)
	if err != nil {
		return err
	}
	reader := csv.NewReader(bytes.NewReader(content))
	rows, err := reader.ReadAll()
	if err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, row := range rows {
		if len(row) != 3 {
			return fmt.Errorf("RECORD row must contain three fields")
		}
		name, hashField, sizeField := row[0], row[1], row[2]
		file, ok := entries[name]
		if !ok {
			return fmt.Errorf("RECORD references missing entry %s", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("RECORD duplicates entry %s", name)
		}
		seen[name] = struct{}{}
		if name == recordPath {
			if hashField != "" || sizeField != "" {
				return fmt.Errorf("RECORD self row must have empty hash and size")
			}
			continue
		}
		fileContent, err := readZipFile(file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(fileContent)
		expectedHash := "sha256=" + base64.RawURLEncoding.EncodeToString(sum[:])
		if hashField != expectedHash {
			return fmt.Errorf("RECORD hash mismatch for %s", name)
		}
		if sizeField != strconv.Itoa(len(fileContent)) {
			return fmt.Errorf("RECORD size mismatch for %s", name)
		}
	}
	if len(seen) != len(entries) {
		names := make([]string, 0, len(entries))
		for name := range entries {
			if _, ok := seen[name]; !ok {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		return fmt.Errorf("RECORD missing entries: %s", strings.Join(names, ", "))
	}
	return nil
}

func verifyLocalPythonConsumer(recordsBySuffix map[string]wheelRecord) error {
	target, err := currentTarget()
	if err != nil {
		return nil
	}
	record, ok := recordsBySuffix[target.PlatformSuffix]
	if !ok {
		return fmt.Errorf("missing local platform python wheel for %s", target.PlatformSuffix)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("python3 is required for local Python wheel smoke: %w", err)
	}
	consumer, err := os.MkdirTemp("", "proofkit-python-consumer-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(consumer)
	if output, err := runCommand("", python, "-m", "venv", consumer); err != nil {
		return fmt.Errorf("create Python consumer venv: %w\n%s", err, output)
	}
	venvPython := filepath.Join(consumer, "bin", "python")
	if runtime.GOOS == "windows" {
		venvPython = filepath.Join(consumer, "Scripts", "python.exe")
	}
	wheelPath, err := filepath.Abs(filepath.Join("artifacts", "pypi", record.Filename))
	if err != nil {
		return err
	}
	if output, err := runCommand("", venvPython, "-m", "pip", "install", "--no-index", wheelPath); err != nil {
		return fmt.Errorf("install local Python wheel: %w\n%s", err, output)
	}
	output, err := runCommand("", venvPython, "-m", "agentic_proofkit", "--help")
	if err != nil {
		return fmt.Errorf("python module CLI smoke failed: %w\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("CLI/JSON is the public cross-language contract")) {
		return fmt.Errorf("python module CLI smoke did not expose CLI contract")
	}
	binPath := filepath.Join(consumer, "bin", "agentic-proofkit")
	if runtime.GOOS == "windows" {
		binPath = filepath.Join(consumer, "Scripts", "agentic-proofkit.exe")
	}
	output, err = runCommand("", binPath, "--help")
	if err != nil {
		return fmt.Errorf("python console script smoke failed: %w\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("CLI/JSON is the public cross-language contract")) {
		return fmt.Errorf("python console script smoke did not expose CLI contract")
	}
	return nil
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func runCommand(dir string, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	if dir != "" {
		command.Dir = dir
	}
	return command.CombinedOutput()
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
