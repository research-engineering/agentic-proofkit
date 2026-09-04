package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

const (
	zipDataDescriptorFlag          = 0x8
	maximumWheelArchiveBytes       = 96 << 20
	maximumWheelBinaryBytes        = 64 << 20
	maximumWheelEntryCount         = 16
	maximumWheelTextEntryBytes     = 1 << 20
	machoBuildVersionCommand       = 0x32
	machoBuildVersionCommandSize   = 24
	machoMinimumVersionCommand     = 0x24
	machoMinimumVersionCommandSize = 16
	machoPlatformMacOS             = 1
	installedResourceReadTimeout   = 10 * time.Second
	pythonPackageProcessTimeout    = 2 * time.Minute
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
	contract, err := os.ReadFile(sourceCLIContractPath)
	if err != nil {
		return fmt.Errorf("read source CLI contract: %w", err)
	}
	return verifyWheelContents(wheelPath, manifest, target, record.BinarySha256, license, contract)
}

func verifyWheelContents(path string, manifest packageJSON, target target, expectedBinarySHA256 string, expectedLicense []byte, expectedCLIContract []byte) error {
	content, err := artifactfile.ReadBounded(filepath.Dir(path), filepath.Base(path), maximumWheelArchiveBytes)
	if err != nil {
		return fmt.Errorf("read bounded wheel %s: %w", path, err)
	}
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return fmt.Errorf("decode wheel %s: %w", path, err)
	}
	if len(reader.File) > maximumWheelEntryCount {
		return fmt.Errorf("%s exceeds wheel entry count limit", path)
	}
	entries := map[string]*zip.File{}
	for _, file := range reader.File {
		if file.Flags&zipDataDescriptorFlag != 0 {
			return fmt.Errorf("%s entry %s uses a ZIP data descriptor", path, file.Name)
		}
		if file.CompressedSize64 > uint64(maximumWheelArchiveBytes) {
			return fmt.Errorf("%s entry %s exceeds compressed resource limit", path, file.Name)
		}
		if _, exists := entries[file.Name]; exists {
			return fmt.Errorf("%s contains duplicate entry %s", path, file.Name)
		}
		if !file.Mode().IsRegular() {
			return fmt.Errorf("%s entry %s must be a regular file", path, file.Name)
		}
		if file.UncompressedSize64 > uint64(maximumWheelEntryBytes(file.Name)) {
			return fmt.Errorf("%s entry %s exceeds resource limit", path, file.Name)
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
		embeddedCLIContractPath,
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
	contractContent, err := readZipFile(entries[embeddedCLIContractPath])
	if err != nil {
		return err
	}
	if !bytes.Equal(contractContent, expectedCLIContract) {
		return fmt.Errorf("%s embedded CLI contract mismatch", path)
	}
	if _, err := installedclicontract.Admit(contractContent); err != nil {
		return fmt.Errorf("%s embedded CLI contract is invalid: %w", path, err)
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
	if err := verifyEmbeddedBinaryTarget(target, embeddedBinary); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := verifyDarwinWheelMinimum(target, embeddedBinary); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return verifyRecord(entries, distInfo+"/RECORD")
}

func verifyEmbeddedBinaryTarget(target target, content []byte) error {
	switch target.GOOS {
	case "darwin":
		file, err := macho.NewFile(bytes.NewReader(content))
		if err != nil {
			return fmt.Errorf("decode embedded Mach-O: %w", err)
		}
		expected := map[string]macho.Cpu{
			"amd64": macho.CpuAmd64,
			"arm64": macho.CpuArm64,
		}[target.GOARCH]
		if expected == 0 || file.Cpu != expected {
			return fmt.Errorf("embedded Mach-O architecture %s does not match target %s", file.Cpu, target.GOARCH)
		}
	case "linux":
		file, err := elf.NewFile(bytes.NewReader(content))
		if err != nil {
			return fmt.Errorf("decode embedded ELF: %w", err)
		}
		expected := map[string]elf.Machine{
			"amd64": elf.EM_X86_64,
			"arm64": elf.EM_AARCH64,
		}[target.GOARCH]
		if expected == elf.EM_NONE || file.Machine != expected {
			return fmt.Errorf("embedded ELF architecture %s does not match target %s", file.Machine, target.GOARCH)
		}
	default:
		return fmt.Errorf("unsupported embedded binary target OS %s", target.GOOS)
	}
	return nil
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
	environment := pythonVerificationEnvironment(os.Environ(), nil)
	if output, err := runCommandWithEnvironment("", environment, python, "-m", "venv", consumer); err != nil {
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
	expectedContract, err := artifactfile.ReadBounded(".", sourceCLIContractPath, installedclicontract.MaximumContractBytes)
	if err != nil {
		return fmt.Errorf("read source CLI contract for installed wheel proof: %w", err)
	}
	expectedBinary, err := artifactfile.ReadBounded(".", filepath.ToSlash(target.BinaryPath), maximumWheelBinaryBytes)
	if err != nil {
		return fmt.Errorf("read source binary for installed wheel proof: %w", err)
	}
	return verifyInstalledPythonWheel(consumer, venvPython, wheelPath, expectedContract, expectedBinary, environment)
}

func verifyInstalledPythonWheel(consumer string, venvPython string, wheelPath string, expectedContract []byte, expectedBinary []byte, environment []string) error {
	environment = pythonVerificationEnvironment(environment, nil)
	if err := installPythonWheel(venvPython, wheelPath, environment); err != nil {
		return err
	}
	renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, venvPython)
	if err != nil {
		return fmt.Errorf("construct installed Python module renderer: %w", err)
	}
	if _, err := verifyInstalledPythonCarrier(consumer, environment, renderer, expectedContract, expectedBinary); err != nil {
		return err
	}
	output, err := runCommandWithEnvironment("", environment, venvPython, "-m", "agentic_proofkit", "--help")
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
	output, err = runCommandWithEnvironment("", environment, binPath, "--help")
	if err != nil {
		return fmt.Errorf("python console script smoke failed: %w\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("CLI/JSON is the public cross-language contract")) {
		return fmt.Errorf("python console script smoke did not expose CLI contract")
	}
	if err := verifyInstalledWorkflowSmoke(consumer, environment, venvPython, "-m", "agentic_proofkit"); err != nil {
		return fmt.Errorf("python module agent-workflow smoke failed: %w", err)
	}
	if err := verifyInstalledWorkflowSmoke(consumer, environment, binPath); err != nil {
		return fmt.Errorf("python console script agent-workflow smoke failed: %w", err)
	}
	if err := verifyInstalledPythonPresetContinuation(consumer, venvPython, expectedContract, environment); err != nil {
		return err
	}
	_, err = verifyInstalledPythonCarrier(consumer, environment, renderer, expectedContract, expectedBinary)
	return err
}

func pipInstallArguments(wheelPath string) []string {
	return []string{"-m", "pip", "--isolated", "install", "--no-index", "--no-deps", "--no-input", wheelPath}
}

func installPythonWheel(venvPython string, wheelPath string, environment []string) error {
	output, err := runCommandWithEnvironment("", pythonVerificationEnvironment(environment, nil), venvPython, pipInstallArguments(wheelPath)...)
	if err != nil {
		return fmt.Errorf("install local Python wheel: %w\n%s", err, output)
	}
	return nil
}

func verifyInstalledWorkflowSmoke(dir string, environment []string, executable string, prefix ...string) error {
	return workflowsmoke.VerifyProcess(context.Background(), workflowsmoke.ProcessCarrier{
		Directory:   dir,
		Executable:  executable,
		Environment: environment,
		Prefix:      append([]string(nil), prefix...),
	})
}

func verifyInstalledPythonPresetContinuation(consumer string, venvPython string, expectedContract []byte, baseEnvironment []string) error {
	emptyPath := filepath.Join(consumer, "empty-path")
	if err := os.Mkdir(emptyPath, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create npm-free PATH: %w", err)
	}
	environment := pythonVerificationEnvironment(baseEnvironment, map[string]string{
		"PATH":                              emptyPath,
		cliexec.LauncherProfileEnvironment:  cliexec.ProfilePath,
		cliexec.PythonExecutableEnvironment: filepath.Join(consumer, "wrong-python"),
	})
	executableOutput, err := runCommandWithEnvironment("", environment, venvPython, "-c", "import sys; print(sys.executable)")
	if err != nil {
		return fmt.Errorf("resolve installed Python wheel interpreter identity: %w\n%s", err, executableOutput)
	}
	pythonExecutable := strings.TrimSpace(string(executableOutput))
	if pythonExecutable == "" || !filepath.IsAbs(pythonExecutable) ||
		string(executableOutput) != pythonExecutable+"\n" {
		return fmt.Errorf("installed Python wheel interpreter identity must be one absolute newline-terminated path, got %q", executableOutput)
	}
	output, err := runCommandWithEnvironment("", environment, pythonExecutable, "-m", "agentic_proofkit", "stack-preset", "--preset", "agentic_runtime_repo")
	if err != nil {
		return fmt.Errorf("installed Python wheel stack preset failed with npm absent from PATH: %w\n%s", err, output)
	}
	commands, err := installedPythonPresetSuggestedCommands(output, "agentic_runtime_repo")
	if err != nil {
		return err
	}
	renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, pythonExecutable)
	if err != nil {
		return fmt.Errorf("construct expected Python module renderer: %w", err)
	}
	prefix := renderer.DisplayCommand() + " "
	for index, command := range commands {
		if !strings.HasPrefix(command, prefix) {
			return fmt.Errorf("installed Python wheel suggestedCommands[%d]=%q must use exact interpreter module prefix %q", index, command, prefix)
		}
	}
	expectedSelfContinuation := renderer.DisplayCommand("stack-preset", "--preset", "agentic_runtime_repo")
	if commands[0] != expectedSelfContinuation {
		return fmt.Errorf("installed Python wheel first suggested command must be exact self-continuation %q", expectedSelfContinuation)
	}
	output, err = runArgvWithEnvironment(consumer, environment, renderer.Argv("stack-preset", "--preset", "agentic_runtime_repo"))
	if err != nil {
		return fmt.Errorf("installed Python wheel self-continuation failed with npm absent from PATH: %w\n%s", err, output)
	}
	if err := requirePythonPassedJSON(output, "installed Python wheel self-continuation"); err != nil {
		return err
	}
	return verifyInstalledPythonHelpAndAgentRouteContinuity(consumer, environment, renderer, expectedContract)
}

func verifyInstalledPythonHelpAndAgentRouteContinuity(consumer string, environment []string, renderer cliexec.Renderer, expectedContract []byte) error {
	contractContent, err := readInstalledPythonCLIContract(consumer, environment, renderer, expectedContract)
	if err != nil {
		return err
	}
	contract, err := installedclicontract.Admit(contractContent)
	if err != nil {
		return fmt.Errorf("admit installed Python wheel CLI contract: %w", err)
	}
	contractCommandIDsByRoute := contract.CommandIDsByRoute()

	rootHelp, err := runArgvWithEnvironment(consumer, environment, renderer.Argv("help"))
	if err != nil {
		return fmt.Errorf("installed Python wheel root help route failed: %w\n%s", err, rootHelp)
	}
	familiesCommand := renderer.DisplayCommand("help", "families")
	if !strings.Contains(string(rootHelp), "Discover command families:\n  "+familiesCommand+"\n") {
		return fmt.Errorf("installed Python wheel root help does not expose exact family route %q", familiesCommand)
	}
	familiesHelp, err := runArgvWithEnvironment(consumer, environment, renderer.Argv("help", "families"))
	if err != nil {
		return fmt.Errorf("installed Python wheel family discovery route failed: %w\n%s", err, familiesHelp)
	}
	familyPrefix := renderer.DisplayCommand() + " help family "
	familyIDs, err := exactDisplayedRouteOperands(familiesHelp, familyPrefix, "installed Python wheel family routes")
	if err != nil {
		return err
	}
	leafPrefix := renderer.DisplayCommand() + " help "
	observedRoutes := make(map[string]string, len(contractCommandIDsByRoute))
	familyByRoute := make(map[string]string, len(contractCommandIDsByRoute))
	for _, familyID := range familyIDs {
		familyRoute := renderer.DisplayCommand("help", "family", familyID)
		familyHelp, err := runArgvWithEnvironment(consumer, environment, renderer.Argv("help", "family", familyID))
		if err != nil {
			return fmt.Errorf("installed Python wheel family route %q failed: %w\n%s", familyRoute, err, familyHelp)
		}
		leafRoutes, err := exactDisplayedCommandRoutes(familyHelp, leafPrefix, "installed Python wheel leaf routes", contract)
		if err != nil {
			return err
		}
		for _, leafRouteText := range leafRoutes {
			commandID, exists := contractCommandIDsByRoute[leafRouteText]
			if !exists {
				return fmt.Errorf("installed Python wheel family %s exposes route %q absent from its embedded CLI contract", familyID, leafRouteText)
			}
			if priorFamily, exists := familyByRoute[leafRouteText]; exists {
				return fmt.Errorf("installed Python wheel route %q is exposed by both %s and %s", leafRouteText, priorFamily, familyID)
			}
			familyByRoute[leafRouteText] = familyID
			helpArgs := append([]string{"help"}, strings.Split(leafRouteText, " ")...)
			leafRoute := renderer.DisplayCommand(helpArgs...)
			leafHelp, err := runArgvWithEnvironment(consumer, environment, renderer.Argv(helpArgs...))
			if err != nil {
				return fmt.Errorf("installed Python wheel leaf help route %q for command %s failed: %w", leafRoute, commandID, err)
			}
			helpIdentity, err := contract.AdmitHelpIdentity(leafHelp)
			if err != nil {
				return fmt.Errorf("installed Python wheel leaf help route %q has invalid identity: %w", leafRoute, err)
			}
			if helpIdentity.Route != leafRouteText {
				return fmt.Errorf("installed Python wheel leaf help route=%q, want %q", helpIdentity.Route, leafRouteText)
			}
			observedRoutes[helpIdentity.Route] = helpIdentity.CommandID
		}
	}
	if err := requireInstalledPythonCommandRouteBijection(observedRoutes, contractCommandIDsByRoute); err != nil {
		return err
	}

	requirementSourceRef := "requirements.v1.json"
	requirementSourcePath := filepath.Join(consumer, requirementSourceRef)
	requirementSource := map[string]any{
		"schemaVersion":    1,
		"sourceId":         "proofkit.python.consumer.requirements",
		"specPackagePath":  "docs/specs/python-consumer",
		"overviewPath":     "docs/specs/python-consumer/overview.md",
		"requirementsPath": "docs/specs/python-consumer/requirements.v1.json",
		"nonClaims":        []string{"Installed Python consumer fixture does not execute native witnesses."},
		"requirements": []any{map[string]any{
			"claimLevel":       "blocking",
			"deferral":         nil,
			"invariant":        "Installed Python consumer routes preserve the active launcher.",
			"lifecycle":        map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"},
			"nonClaimRefs":     []any{},
			"nonClaims":        []string{"Installed Python consumer route does not prove publication."},
			"ownerId":          "proofkit.python.consumer",
			"proofBindingRefs": []string{"proofkit/requirement-bindings.json"},
			"requirementId":    "REQ-PROOFKIT-PYTHON-CONSUMER-001",
			"riskClass":        "medium",
			"updatePolicy": map[string]any{
				"requiresImpactDeclaration":  true,
				"requiresProofBindingReview": true,
				"reviewOwnerId":              "proofkit.python.consumer",
			},
		}},
	}
	if err := writeJSONFixture(requirementSourcePath, requirementSource); err != nil {
		return err
	}
	agentRoutePath := filepath.Join(consumer, "agent-route.json")
	agentRoute := map[string]any{
		"schemaVersion": 1,
		"routeId":       "proofkit.python.consumer.route",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{"kind": "requirement_source", "ref": requirementSourceRef},
		},
	}
	if err := writeJSONFixture(agentRoutePath, agentRoute); err != nil {
		return err
	}
	if err := verifyInstalledPythonAgentRouteEnvelopeModes(consumer, environment, renderer, agentRoutePath); err != nil {
		return err
	}
	routeOutput, err := runArgvWithEnvironment(consumer, environment, renderer.Argv("agent-route", "--input", agentRoutePath))
	if err != nil {
		return fmt.Errorf("installed Python wheel agent route failed: %w\n%s", err, routeOutput)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(routeOutput), 8<<20)
	if err != nil {
		return fmt.Errorf("installed Python wheel agent route output must be one JSON value: %w", err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("installed Python wheel agent route output must be an object")
	}
	rawCommands, ok := record["nextCommands"].([]any)
	if !ok || len(rawCommands) != 1 {
		return fmt.Errorf("installed Python wheel agent route must expose exactly one next command")
	}
	command, ok := rawCommands[0].(map[string]any)
	if !ok {
		return fmt.Errorf("installed Python wheel next command must be an object")
	}
	argv, err := exactStringArray(command["argv"], "installed Python wheel next command argv")
	if err != nil {
		return err
	}
	prefix := renderer.Argv()
	if len(argv) < len(prefix) || !equalStrings(argv[:len(prefix)], prefix) {
		return fmt.Errorf("installed Python wheel next command argv does not use the active launcher prefix")
	}
	commandOutput, err := runArgvWithEnvironment(consumer, environment, argv)
	if err != nil {
		return fmt.Errorf("installed Python wheel emitted agent-route argv failed: %w\n%s", err, commandOutput)
	}
	return requirePythonPassedJSON(commandOutput, "installed Python wheel emitted agent-route argv")
}

func readInstalledPythonCLIContract(consumer string, environment []string, renderer cliexec.Renderer, expectedContract []byte) ([]byte, error) {
	launcher := renderer.Argv()
	if len(launcher) != 3 || launcher[1] != "-m" || launcher[2] != "agentic_proofkit" {
		return nil, fmt.Errorf("installed Python wheel contract reader requires the Python module launcher")
	}
	content, err := readInstalledPythonPackageResource(
		consumer,
		environment,
		launcher[0],
		"proofkit/cli-contract.v2.json",
		installedclicontract.MaximumContractBytes,
		"bytes",
	)
	if err != nil {
		return nil, fmt.Errorf("read installed Python wheel CLI contract: %w", err)
	}
	if !bytes.Equal(content, expectedContract) {
		return nil, fmt.Errorf("installed Python wheel CLI contract differs from the exact source contract")
	}
	if _, err := installedclicontract.Admit(content); err != nil {
		return nil, fmt.Errorf("admit installed Python wheel CLI contract resource: %w", err)
	}
	return content, nil
}

func verifyInstalledPythonCarrier(consumer string, environment []string, renderer cliexec.Renderer, expectedContract []byte, expectedBinary []byte) ([]byte, error) {
	contract, err := readInstalledPythonCLIContract(consumer, environment, renderer, expectedContract)
	if err != nil {
		return nil, err
	}
	launcher := renderer.Argv()
	if len(launcher) != 3 {
		return nil, fmt.Errorf("installed Python carrier requires the Python module launcher")
	}
	if err := verifyInstalledPythonBinary(consumer, environment, launcher[0], expectedBinary); err != nil {
		return nil, err
	}
	return contract, nil
}

func verifyInstalledPythonBinary(consumer string, environment []string, pythonExecutable string, expectedBinary []byte) error {
	digestText, err := readInstalledPythonPackageResource(
		consumer,
		environment,
		pythonExecutable,
		"bin/agentic-proofkit",
		maximumWheelBinaryBytes,
		"sha256",
	)
	if err != nil {
		return fmt.Errorf("read installed Python wheel binary: %w", err)
	}
	expectedDigest := sha256.Sum256(expectedBinary)
	if string(digestText) != fmt.Sprintf("%x\n", expectedDigest) {
		return fmt.Errorf("installed Python wheel binary differs from the exact wheel source binary")
	}
	return nil
}

func readInstalledPythonPackageResource(consumer string, environment []string, pythonExecutable string, relativePath string, maximumBytes int64, outputMode string) ([]byte, error) {
	if relativePath == "" || strings.HasPrefix(relativePath, "/") || strings.Contains(relativePath, "\\") {
		return nil, fmt.Errorf("installed Python package resource path is invalid")
	}
	for _, component := range strings.Split(relativePath, "/") {
		if component == "" || component == "." || component == ".." {
			return nil, fmt.Errorf("installed Python package resource path is invalid")
		}
	}
	if maximumBytes <= 0 {
		return nil, fmt.Errorf("installed Python package resource limit is invalid")
	}
	if outputMode != "bytes" && outputMode != "sha256" {
		return nil, fmt.Errorf("installed Python package resource output mode is invalid")
	}
	script := `
import hashlib
import os
import stat
import sys
from importlib.resources import files

relative_path = sys.argv[1]
limit = int(sys.argv[2])
output_mode = sys.argv[3]
resource = files("agentic_proofkit")
for component in relative_path.split("/"):
    resource = resource.joinpath(component)
path = os.path.abspath(os.fspath(resource))
prefix_path = os.path.abspath(sys.prefix)
prefix = os.path.realpath(prefix_path)
if os.path.commonpath((prefix_path, path)) == prefix_path:
    relative = os.path.relpath(path, prefix_path)
elif os.path.commonpath((prefix, path)) == prefix:
    relative = os.path.relpath(path, prefix)
else:
    raise SystemExit("installed package resource is outside the active environment")
components = relative.split(os.path.sep)
if not components or any(component in ("", ".", "..") for component in components):
    raise SystemExit("installed package resource path is invalid")
directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
directory_fd = os.open(prefix, directory_flags)
try:
    for component in components[:-1]:
        next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
        os.close(directory_fd)
        directory_fd = next_fd
    fd = os.open(components[-1], flags, dir_fd=directory_fd)
finally:
    os.close(directory_fd)
with os.fdopen(fd, "rb", closefd=True) as stream:
    before = os.fstat(stream.fileno())
    if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > limit:
        raise SystemExit("installed package resource is not a bounded regular file")
    total = 0
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(min(65536, limit + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise SystemExit("installed package resource exceeds its byte limit")
        if output_mode == "bytes":
            sys.stdout.buffer.write(chunk)
        else:
            digest.update(chunk)
    after = os.fstat(stream.fileno())
    if total != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise SystemExit("installed package resource changed during the read")
    if output_mode == "sha256":
        sys.stdout.write(digest.hexdigest() + "\n")
`
	maximumOutputBytes := int(maximumBytes)
	if outputMode == "sha256" {
		maximumOutputBytes = sha256.Size*2 + 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), installedResourceReadTimeout)
	defer cancel()
	result, err := workflowsmoke.RunProcessWithOutputLimits(ctx, workflowsmoke.ProcessCarrier{
		Directory:   consumer,
		Executable:  pythonExecutable,
		Prefix:      []string{"-I", "-c", script, relativePath, strconv.FormatInt(maximumBytes, 10), outputMode},
		Environment: pythonVerificationEnvironment(environment, nil),
	}, workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinMustRemainUnread}, workflowsmoke.ProcessOutputLimits{
		MaximumStdoutBytes: maximumOutputBytes,
		MaximumStderrBytes: 64 << 10,
	})
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("installed Python package resource reader exited with code %d: %s", result.ExitCode, result.Stderr)
	}
	return result.Stdout, nil
}

func requireInstalledPythonCommandRouteBijection(observed map[string]string, expected map[string]string) error {
	if len(observed) != len(expected) {
		return fmt.Errorf("installed Python wheel family routes=%d embedded contract routes=%d", len(observed), len(expected))
	}
	for route, commandID := range expected {
		observedCommandID, exists := observed[route]
		if !exists {
			return fmt.Errorf("installed Python wheel family navigation omitted embedded contract route %q", route)
		}
		if observedCommandID != commandID {
			return fmt.Errorf("installed Python wheel route %q command id=%q, want %q", route, observedCommandID, commandID)
		}
	}
	return nil
}

func verifyInstalledPythonAgentRouteEnvelopeModes(consumer string, environment []string, renderer cliexec.Renderer, inputPath string) error {
	bareBrief, err := runArgvWithEnvironment(consumer, environment, renderer.Argv("agent-route", "--input", inputPath, "--agent-envelope"))
	if err != nil {
		return fmt.Errorf("installed Python wheel bare agent-route brief failed: %w\n%s", err, bareBrief)
	}
	if err := verifyInstalledPythonAgentRouteBrief(bareBrief); err != nil {
		return fmt.Errorf("installed Python wheel bare agent-route brief is invalid: %w", err)
	}
	explicitBrief, err := runArgvWithEnvironment(consumer, environment, renderer.Argv("agent-route", "--input", inputPath, "--agent-envelope", "--agent-envelope-mode", "brief"))
	if err != nil {
		return fmt.Errorf("installed Python wheel explicit agent-route brief failed: %w\n%s", err, explicitBrief)
	}
	if err := verifyInstalledPythonAgentRouteBrief(explicitBrief); err != nil {
		return fmt.Errorf("installed Python wheel explicit agent-route brief is invalid: %w", err)
	}
	if !bytes.Equal(bareBrief, explicitBrief) {
		return fmt.Errorf("installed Python wheel bare and explicit agent-route brief outputs differ")
	}
	full, err := runArgvWithEnvironment(consumer, environment, renderer.Argv("agent-route", "--input", inputPath, "--agent-envelope", "--agent-envelope-mode", "full"))
	if err != nil {
		return fmt.Errorf("installed Python wheel full agent-route envelope failed: %w\n%s", err, full)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(full), 8<<20)
	if err != nil {
		return fmt.Errorf("installed Python wheel full agent-route envelope must be one strict JSON value: %w", err)
	}
	envelope, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("installed Python wheel full agent-route envelope must be an object")
	}
	if envelope["envelopeId"] != "proofkit.python.consumer.route.agent-envelope" {
		return fmt.Errorf("installed Python wheel full agent-route envelope has unexpected identity")
	}
	if _, ok := envelope["actionPlan"].([]any); !ok {
		return fmt.Errorf("installed Python wheel full agent-route envelope actionPlan must be an array")
	}
	if _, brief := envelope["packetKind"]; brief {
		return fmt.Errorf("installed Python wheel full agent-route envelope uses the brief packet root")
	}
	return nil
}

func verifyInstalledPythonAgentRouteBrief(output []byte) error {
	value, err := admission.DecodeJSON(bytes.NewReader(output), 1<<20)
	if err != nil {
		return fmt.Errorf("output must be one strict JSON value: %w", err)
	}
	packet, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("output must be an object")
	}
	if packet["packetKind"] != "proofkit.agent-route.brief" || packet["state"] != "routed" {
		return fmt.Errorf("output has unexpected brief identity or state")
	}
	if _, ok := packet["nextAction"].(map[string]any); !ok {
		return fmt.Errorf("output nextAction must be an object")
	}
	if len(output) > 3072 {
		return fmt.Errorf("output is %d bytes, want at most 3072", len(output))
	}
	return nil
}

func exactDisplayedRouteOperands(output []byte, prefix string, context string) ([]string, error) {
	return exactDisplayedRouteSuffixes(output, prefix, context, func(value string) bool {
		tokens, ok := commandroute.Parse(value)
		return ok && len(tokens) == 1
	})
}

func exactDisplayedCommandRoutes(output []byte, prefix string, context string, contract installedclicontract.Contract) ([]string, error) {
	return exactDisplayedRouteSuffixes(output, prefix, context, func(value string) bool {
		_, err := contract.AdmitRouteText(value)
		return err == nil
	})
}

func exactDisplayedRouteSuffixes(output []byte, prefix string, context string, admit func(string) bool) ([]string, error) {
	decoded, err := unicodepolicy.DecodeUTF8(output)
	if err != nil {
		return nil, fmt.Errorf("installed Python wheel route output is not valid UTF-8")
	}
	operands := []string{}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(strings.TrimSuffix(decoded, "\n"), "\n") {
		route, admitted := strings.CutPrefix(line, "    ")
		if !admitted {
			continue
		}
		if !strings.HasPrefix(route, prefix) {
			continue
		}
		operand := strings.TrimPrefix(route, prefix)
		if !admit(operand) || route != prefix+operand {
			return nil, fmt.Errorf("%s contain non-canonical route %q", context, route)
		}
		if _, duplicate := seen[operand]; duplicate {
			return nil, fmt.Errorf("%s contain duplicate route operand %q", context, operand)
		}
		seen[operand] = struct{}{}
		operands = append(operands, operand)
	}
	if len(operands) == 0 {
		return nil, fmt.Errorf("%s are empty", context)
	}
	sort.Strings(operands)
	return operands, nil
}

func writeJSONFixture(path string, value any) error {
	content, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal installed Python consumer fixture: %w", err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		return fmt.Errorf("write installed Python consumer fixture: %w", err)
	}
	return nil
}

func exactStringArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty array", context)
	}
	result := make([]string, 0, len(values))
	for _, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok || value == "" {
			return nil, fmt.Errorf("%s must contain non-empty strings", context)
		}
		result = append(result, value)
	}
	return result, nil
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func installedPythonPresetSuggestedCommands(output []byte, presetID string) ([]string, error) {
	value, err := admission.DecodeJSON(bytes.NewReader(output), 8<<20)
	if err != nil {
		return nil, fmt.Errorf("installed Python wheel stack preset %s stdout must be one JSON value: %w", presetID, err)
	}
	record, ok := value.(map[string]any)
	if !ok || record["state"] != "passed" {
		return nil, fmt.Errorf("installed Python wheel stack preset %s state is not passed", presetID)
	}
	diagnostics, ok := record["diagnostics"].([]any)
	if !ok {
		return nil, fmt.Errorf("installed Python wheel stack preset %s output must expose diagnostics", presetID)
	}
	var presetValue map[string]any
	presetDiagnosticCount := 0
	for _, rawDiagnostic := range diagnostics {
		diagnostic, ok := rawDiagnostic.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("installed Python wheel stack preset %s diagnostics must contain objects", presetID)
		}
		if diagnostic["key"] != "preset" {
			continue
		}
		presetDiagnosticCount++
		presetValue, ok = diagnostic["value"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("installed Python wheel stack preset %s preset diagnostic must contain an object value", presetID)
		}
	}
	if presetDiagnosticCount != 1 {
		return nil, fmt.Errorf("installed Python wheel stack preset %s must expose exactly one preset diagnostic", presetID)
	}
	rawCommands, ok := presetValue["suggestedCommands"].([]any)
	if !ok || len(rawCommands) == 0 {
		return nil, fmt.Errorf("installed Python wheel stack preset %s must expose non-empty suggestedCommands", presetID)
	}
	commands := make([]string, 0, len(rawCommands))
	for index, rawCommand := range rawCommands {
		command, ok := rawCommand.(string)
		if !ok || command == "" {
			return nil, fmt.Errorf("installed Python wheel stack preset %s suggestedCommands[%d] must be a non-empty string", presetID, index)
		}
		commands = append(commands, command)
	}
	return commands, nil
}

func requirePythonPassedJSON(output []byte, label string) error {
	value, err := admission.DecodeJSON(bytes.NewReader(output), 8<<20)
	if err != nil {
		return fmt.Errorf("%s stdout must be one JSON value: %w", label, err)
	}
	record, ok := value.(map[string]any)
	if !ok || record["state"] != "passed" {
		return fmt.Errorf("%s state is not passed", label)
	}
	return nil
}

func environmentWithOverrides(environment []string, overrides map[string]string) []string {
	result := make([]string, 0, len(environment)+len(overrides))
	for _, item := range environment {
		name, _, ok := strings.Cut(item, "=")
		if _, replaced := overrides[name]; ok && replaced {
			continue
		}
		result = append(result, item)
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		result = append(result, name+"="+overrides[name])
	}
	return result
}

func pythonVerificationEnvironment(environment []string, overrides map[string]string) []string {
	filtered := make([]string, 0, len(environment)+len(overrides)+2)
	for _, item := range environment {
		name, _, ok := strings.Cut(item, "=")
		if ok && strings.HasPrefix(strings.ToUpper(name), "PYTHON") {
			continue
		}
		filtered = append(filtered, item)
	}
	safeOverrides := make(map[string]string, len(overrides)+2)
	for name, value := range overrides {
		if !strings.HasPrefix(strings.ToUpper(name), "PYTHON") {
			safeOverrides[name] = value
		}
	}
	safeOverrides["PYTHONNOUSERSITE"] = "1"
	safeOverrides["PYTHONSAFEPATH"] = "1"
	return environmentWithOverrides(filtered, safeOverrides)
}

func readZipFile(file *zip.File) ([]byte, error) {
	maximumBytes := maximumWheelEntryBytes(file.Name)
	if file.UncompressedSize64 > uint64(maximumBytes) {
		return nil, fmt.Errorf("wheel entry %s exceeds resource limit", file.Name)
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximumBytes || uint64(len(content)) != file.UncompressedSize64 {
		return nil, fmt.Errorf("wheel entry %s exceeds or contradicts its admitted size", file.Name)
	}
	return content, nil
}

func maximumWheelEntryBytes(name string) int64 {
	if name == "agentic_proofkit/bin/agentic-proofkit" {
		return maximumWheelBinaryBytes
	}
	return maximumWheelTextEntryBytes
}

func runCommandWithEnvironment(dir string, environment []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pythonPackageProcessTimeout)
	defer cancel()
	result, err := workflowsmoke.RunProcess(ctx, workflowsmoke.ProcessCarrier{
		Directory:   dir,
		Environment: environment,
		Executable:  name,
	}, workflowsmoke.Invocation{Args: args, StdinClass: workflowsmoke.StdinBytes})
	if err != nil {
		return nil, err
	}
	output := append(append([]byte(nil), result.Stdout...), result.Stderr...)
	if result.ExitCode != 0 {
		return output, fmt.Errorf("process exited with code %d", result.ExitCode)
	}
	return output, nil
}

func runArgvWithEnvironment(dir string, environment []string, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("run argv requires at least one token")
	}
	return runCommandWithEnvironment(dir, environment, argv[0], argv[1:]...)
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
