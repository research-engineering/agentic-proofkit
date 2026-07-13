package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/macho"
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

const (
	zipDataDescriptorFlag          = 0x8
	machoBuildVersionCommand       = 0x32
	machoBuildVersionCommandSize   = 24
	machoMinimumVersionCommand     = 0x24
	machoMinimumVersionCommandSize = 16
	machoPlatformMacOS             = 1
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
	license, err := readLicenseFile()
	if err != nil {
		return err
	}
	return verifyWheelContents(wheelPath, manifest, target, record.BinarySha256, license)
}

func verifyWheelContents(path string, manifest packageJSON, target target, expectedBinarySHA256 string, expectedLicense []byte) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()
	entries := map[string]*zip.File{}
	for _, file := range reader.File {
		if file.Flags&zipDataDescriptorFlag != 0 {
			return fmt.Errorf("%s entry %s uses a ZIP data descriptor", path, file.Name)
		}
		if _, exists := entries[file.Name]; exists {
			return fmt.Errorf("%s contains duplicate entry %s", path, file.Name)
		}
		entries[file.Name] = file
	}
	distInfo := distInfoDir(manifest.Version)
	licensePath := distInfo + "/licenses/" + licenseFilename
	required := []string{
		"agentic_proofkit/__init__.py",
		"agentic_proofkit/__main__.py",
		"agentic_proofkit/cli.py",
		"agentic_proofkit/bin/agentic-proofkit",
		distInfo + "/METADATA",
		distInfo + "/WHEEL",
		distInfo + "/entry_points.txt",
		licensePath,
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
	metadataContent, err := readZipFile(entries[distInfo+"/METADATA"])
	if err != nil {
		return err
	}
	if string(metadataContent) != metadata(manifest) {
		return fmt.Errorf("%s METADATA mismatch", path)
	}
	licenseContent, err := readZipFile(entries[licensePath])
	if err != nil {
		return err
	}
	if !bytes.Equal(licenseContent, expectedLicense) {
		return fmt.Errorf("%s embedded %s mismatch", path, licenseFilename)
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
	embeddedBinary, err := readZipFile(entries["agentic_proofkit/bin/agentic-proofkit"])
	if err != nil {
		return err
	}
	embeddedBinarySHA256 := sha256.Sum256(embeddedBinary)
	if fmt.Sprintf("%x", embeddedBinarySHA256[:]) != expectedBinarySHA256 {
		return fmt.Errorf("%s embedded binary sha256 mismatch", path)
	}
	if err := verifyDarwinWheelMinimum(target, embeddedBinary); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return verifyRecord(entries, distInfo+"/RECORD")
}

func verifyDarwinWheelMinimum(target target, content []byte) error {
	if target.GOOS != "darwin" {
		return nil
	}
	wheelMinimum, err := macOSPlatformTagMinimum(target.PlatformTag)
	if err != nil {
		return err
	}
	binaryMinimum, err := machoMinimumMacOS(content)
	if err != nil {
		return fmt.Errorf("decode embedded Mach-O minimum macOS: %w", err)
	}
	if wheelMinimum < binaryMinimum {
		return fmt.Errorf(
			"wheel tag %s advertises macOS %s but embedded Mach-O requires macOS %s",
			target.PlatformTag,
			formatMachOVersion(wheelMinimum),
			formatMachOVersion(binaryMinimum),
		)
	}
	return nil
}

func macOSPlatformTagMinimum(platformTag string) (uint32, error) {
	const prefix = "macosx_"
	if !strings.HasPrefix(platformTag, prefix) {
		return 0, fmt.Errorf("darwin platform tag must start with %s: %s", prefix, platformTag)
	}
	parts := strings.SplitN(strings.TrimPrefix(platformTag, prefix), "_", 3)
	if len(parts) != 3 || parts[2] == "" {
		return 0, fmt.Errorf("invalid Darwin platform tag %s", platformTag)
	}
	major, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || major < 10 {
		return 0, fmt.Errorf("invalid Darwin platform tag major version in %s", platformTag)
	}
	minor, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid Darwin platform tag minor version in %s", platformTag)
	}
	return uint32(major)<<16 | uint32(minor)<<8, nil
}

func machoMinimumMacOS(content []byte) (uint32, error) {
	file, err := macho.NewFile(bytes.NewReader(content))
	if err != nil {
		return 0, fmt.Errorf("parse Mach-O: %w", err)
	}
	var minimum uint32
	found := false
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return 0, fmt.Errorf("truncated Mach-O load command")
		}
		command := file.ByteOrder.Uint32(raw[:4])
		switch command {
		case machoBuildVersionCommand:
			if found {
				return 0, fmt.Errorf("multiple Mach-O minimum macOS commands")
			}
			if len(raw) < machoBuildVersionCommandSize {
				return 0, fmt.Errorf("truncated Mach-O LC_BUILD_VERSION command")
			}
			platform := file.ByteOrder.Uint32(raw[8:12])
			if platform != machoPlatformMacOS {
				return 0, fmt.Errorf("Mach-O LC_BUILD_VERSION platform is %d, want macOS", platform)
			}
			minimum = file.ByteOrder.Uint32(raw[12:16])
			found = true
		case machoMinimumVersionCommand:
			if found {
				return 0, fmt.Errorf("multiple Mach-O minimum macOS commands")
			}
			if len(raw) < machoMinimumVersionCommandSize {
				return 0, fmt.Errorf("truncated Mach-O LC_VERSION_MIN_MACOSX command")
			}
			minimum = file.ByteOrder.Uint32(raw[8:12])
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("missing Mach-O minimum macOS command")
	}
	return minimum, nil
}

func formatMachOVersion(version uint32) string {
	major := version >> 16
	minor := version >> 8 & 0xff
	patch := version & 0xff
	if patch == 0 {
		return fmt.Sprintf("%d.%d", major, minor)
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
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
