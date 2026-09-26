package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
	"github.com/research-engineering/agentic-proofkit/internal/tools/repositorysnapshot"
)

const (
	minimumPipVersion = "26.0.1"
	minimumPipFile    = "pip-26.0.1-py3-none-any.whl"
	minimumPipSHA256  = "bdb1b08f4274833d62c1aa29e20907365a2ceb950410df15fc9521bad440122b"
	minimumPipURL     = "https://files.pythonhosted.org/packages/de/f0/c81e05b613866b76d2d1066490adf1a3dbc4ee9d9c839961c3fc8a6997af/pip-26.0.1-py3-none-any.whl"
	minimumPython     = "3.9.0"
	minimumTimeout    = 5 * time.Minute
)

type minimumSnapshot struct {
	SourceRevision string            `json:"sourceRevision"`
	SourceDigest   string            `json:"sourceDigest"`
	Architecture   string            `json:"architecture"`
	Wheel          wheelRecord       `json:"wheel"`
	Files          map[string]string `json:"files"`
}

type minimumReceipt struct {
	Snapshot          minimumSnapshot `json:"snapshot"`
	Image             string          `json:"image"`
	Python            string          `json:"python"`
	Pip               string          `json:"pip"`
	PreparationMillis int64           `json:"preparationMillis"`
	ExecutionMillis   int64           `json:"executionMillis"`
	TotalMillis       int64           `json:"totalMillis"`
	Cleanup           string          `json:"cleanup"`
	ImageCachePolicy  string          `json:"imageCachePolicy"`
	NonClaims         []string        `json:"nonClaims"`
}

func minimumImage(architecture string) (string, error) {
	switch architecture {
	case "arm64":
		return "python@sha256:4836b32c5536098f6b42d1b30252af2bf9735fe581a82479024c8884a13a97b4", nil
	case "amd64":
		return "python@sha256:12b7deafe25f6b34a66d8fb03bfc0ff5e86464fd49100fc2a64d0a98371ec4e1", nil
	default:
		return "", fmt.Errorf("minimum Python smoke requires native Linux arm64 or amd64")
	}
}

func minimumDaemonArchitecture(identity, hostArchitecture string) (string, error) {
	architectures := map[string]string{"linux/aarch64": "arm64", "linux/arm64": "arm64", "linux/x86_64": "amd64", "linux/amd64": "amd64"}
	architecture := architectures[strings.TrimSpace(identity)]
	if architecture == "" || architecture != hostArchitecture {
		return "", fmt.Errorf("minimum Python smoke requires Docker Linux architecture to match the host; emulation is not admitted")
	}
	return architecture, nil
}

func minimumTarget(architecture string) (target, error) {
	for _, candidate := range releaseTargets() {
		if candidate.GOOS == "linux" && candidate.GOARCH == architecture {
			return candidate, nil
		}
	}
	return target{}, fmt.Errorf("minimum smoke has no native Linux release target")
}

func minimumSelectWheel(manifest packageJSON, set packageSet, native target) (wheelRecord, error) {
	if set.ArtifactKind != artifactKind || set.SchemaVersion != schemaVersion || set.PackageName != packageName || set.PackageVersion != manifest.Version || len(set.Packages) != len(releaseTargets()) {
		return wheelRecord{}, fmt.Errorf("minimum smoke requires the exact current release wheel set")
	}
	seen := map[string]bool{}
	var selected wheelRecord
	for _, record := range set.Packages {
		target, ok := releaseplatform.TargetByPlatformSuffix(record.PlatformSuffix)
		if !ok || seen[record.PlatformSuffix] || record.Filename != wheelFilename(manifest.Version, target) || record.Name != packageName || record.Version != manifest.Version {
			return wheelRecord{}, fmt.Errorf("minimum smoke wheel set identity is invalid")
		}
		seen[record.PlatformSuffix] = true
		if record.PlatformSuffix == native.PlatformSuffix {
			selected = record
		}
	}
	if selected.Filename == "" {
		return wheelRecord{}, fmt.Errorf("minimum smoke native wheel is missing")
	}
	return selected, nil
}

func minimumHash(content []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(content))
}

func minimumCheckDigest(content []byte, expected string) error {
	if len(expected) != sha256.Size*2 || minimumHash(content) != expected {
		return fmt.Errorf("minimum smoke snapshot checksum mismatch")
	}
	return nil
}

// Every input is public and readable by UID 65534 on Linux bind mounts, even
// when the host umask is 077. The private parent is never mounted.
func minimumWriteInput(root, path string, content []byte, executable bool) error {
	if !filepath.IsLocal(path) {
		return fmt.Errorf("minimum smoke input path is not local")
	}
	directory := root
	for _, component := range strings.Split(filepath.ToSlash(filepath.Dir(path)), "/") {
		if component != "." {
			directory = filepath.Join(directory, component)
		}
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			return err
		}
	}
	mode := os.FileMode(0o644)
	if executable {
		mode = 0o755
	}
	file := filepath.Join(root, path)
	if err := os.WriteFile(file, content, mode); err != nil {
		return err
	}
	return os.Chmod(file, mode)
}

func minimumDownloadPip(ctx context.Context) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("minimum installer download does not admit redirects")
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, minimumPipURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("minimum installer download failed")
	}
	defer response.Body.Close()
	const limit = 2 << 20
	if response.StatusCode != http.StatusOK || response.ContentLength > limit {
		return nil, fmt.Errorf("minimum installer download status or size is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(content) > limit {
		return nil, fmt.Errorf("minimum installer download exceeds its bound or failed")
	}
	if err := minimumCheckDigest(content, minimumPipSHA256); err != nil {
		return nil, err
	}
	return content, nil
}

func verifyMinimumPython() error {
	started := time.Now()
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, minimumTimeout)
	defer cancel()
	receipt, err := runMinimumPython(ctx)
	if err != nil {
		return err
	}
	receipt.TotalMillis = time.Since(started).Milliseconds()
	receipt.Cleanup = "passed"
	return json.NewEncoder(os.Stdout).Encode(receipt)
}

func runMinimumPython(ctx context.Context) (receipt minimumReceipt, err error) {
	started := time.Now()
	root, err := os.Getwd()
	if err != nil {
		return receipt, err
	}
	revision, sourceDigest, err := packageartifactrecord.SourceSnapshot(root)
	if err != nil {
		return receipt, err
	}
	identity, err := minimumCommand(ctx, "", nil, "docker", "info", "--format", "{{.OSType}}/{{.Architecture}}")
	if err != nil {
		return receipt, err
	}
	architecture, err := minimumDaemonArchitecture(string(identity), runtime.GOARCH)
	if err != nil {
		return receipt, err
	}
	native, err := minimumTarget(architecture)
	if err != nil {
		return receipt, err
	}
	image, err := minimumImage(architecture)
	if err != nil {
		return receipt, err
	}
	work, err := os.MkdirTemp("", "proofkit-python-minimum-*")
	if err != nil {
		return receipt, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }()
	input := filepath.Join(work, "input")
	if err := os.Mkdir(input, 0o755); err != nil {
		return receipt, err
	}
	if err := os.Chmod(input, 0o755); err != nil {
		return receipt, err
	}
	snapshot := minimumSnapshot{SourceRevision: revision, SourceDigest: sourceDigest, Architecture: architecture, Files: map[string]string{}}
	put := func(path string, content []byte, executable bool) error {
		if err := minimumWriteInput(input, path, content, executable); err != nil {
			return err
		}
		snapshot.Files[path] = minimumHash(content)
		return nil
	}
	sources := []string{"package.json", "LICENSE", sourceCLIContractPath, "python/agentic_proofkit/__init__.py", "python/agentic_proofkit/__main__.py", "python/agentic_proofkit/cli.py", "artifacts/pypi/python-packages.json"}
	for _, path := range sources {
		content, err := artifactfile.ReadBounded(root, path, 1<<20)
		if err != nil {
			return receipt, err
		}
		if err := put(path, content, false); err != nil {
			return receipt, err
		}
	}
	manifest, err := readAdmittedJSON[packageJSON](filepath.Join(input, "package.json"))
	if err != nil {
		return receipt, err
	}
	set, err := readPackageSet(filepath.Join(input, "artifacts/pypi/python-packages.json"))
	if err != nil {
		return receipt, err
	}
	snapshot.Wheel, err = minimumSelectWheel(manifest, set, native)
	if err != nil {
		return receipt, err
	}
	wheelPath := "artifacts/pypi/" + snapshot.Wheel.Filename
	wheel, err := artifactfile.ReadBounded(root, wheelPath, maximumWheelArchiveBytes)
	if err != nil {
		return receipt, err
	}
	if err := minimumCheckDigest(wheel, snapshot.Wheel.Sha256); err != nil {
		return receipt, err
	}
	if err := put(wheelPath, wheel, false); err != nil {
		return receipt, err
	}
	buildEnvironment := environmentWithOverrides(os.Environ(), map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": architecture, "GOMAXPROCS": "2"})
	for _, build := range []struct{ path, packagePath string }{{native.BinaryPath, "./cmd/agentic-proofkit"}, {"runner", "./internal/tools/pythonpackage"}} {
		output := filepath.Join(work, "build-output")
		if _, err := minimumCommand(ctx, root, buildEnvironment, "go", "build", "-p=2", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", output, build.packagePath); err != nil {
			return receipt, err
		}
		content, err := artifactfile.ReadBounded(work, "build-output", maximumWheelBinaryBytes)
		if err != nil {
			return receipt, err
		}
		if build.path == native.BinaryPath {
			if err := minimumCheckDigest(content, snapshot.Wheel.BinarySha256); err != nil {
				return receipt, fmt.Errorf("wheel binary differs from the current source build: %w", err)
			}
		}
		if err := put(build.path, content, true); err != nil {
			return receipt, err
		}
	}
	pip, err := minimumDownloadPip(ctx)
	if err != nil {
		return receipt, err
	}
	if err := put(minimumPipFile, pip, false); err != nil {
		return receipt, err
	}
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		return receipt, err
	}
	if err := minimumValidateSnapshot(snapshot); err != nil {
		return receipt, err
	}
	if err := minimumWriteInput(input, "snapshot.json", snapshotBytes, false); err != nil {
		return receipt, err
	}
	if err := minimumCheckSnapshot(input, snapshot); err != nil {
		return receipt, err
	}
	receipt.PreparationMillis = time.Since(started).Milliseconds()
	execution := time.Now()
	if err := minimumDockerSmoke(ctx, input, architecture, image); err != nil {
		return receipt, err
	}
	receipt.ExecutionMillis = time.Since(execution).Milliseconds()
	if err := minimumCheckSnapshot(input, snapshot); err != nil {
		return receipt, err
	}
	afterRevision, afterDigest, err := packageartifactrecord.SourceSnapshot(root)
	if err != nil {
		return receipt, err
	}
	if afterRevision != revision || afterDigest != sourceDigest {
		return receipt, fmt.Errorf("minimum smoke source snapshot changed during execution")
	}
	receipt.Snapshot, receipt.Image, receipt.Python, receipt.Pip = snapshot, image, minimumPython, minimumPipVersion
	receipt.ImageCachePolicy = "retain_shared_image"
	receipt.NonClaims = []string{"Finite native Linux installed-carrier minimum only, not all Python versions, commands or platforms.", "Local source-bound execution, not registry, hosted CI, branch protection, release or interpreter security proof.", "The pinned interpreter image is retained as shared Docker cache. Cleanup covers only the owned container and temporary workdir, not cache reclamation or exclusive image ownership."}
	return receipt, nil
}

func minimumCheckSnapshot(root string, snapshot minimumSnapshot) error {
	for path, digest := range snapshot.Files {
		content, err := artifactfile.ReadBounded(root, path, maximumWheelArchiveBytes)
		if err != nil {
			return err
		}
		if err := minimumCheckDigest(content, digest); err != nil {
			return err
		}
	}
	return nil
}

func minimumValidateSnapshot(snapshot minimumSnapshot) error {
	native, err := minimumTarget(snapshot.Architecture)
	if err != nil {
		return err
	}
	if !repositorysnapshot.ValidRevision(snapshot.SourceRevision) || len(snapshot.SourceDigest) != 64 ||
		snapshot.Wheel.PlatformSuffix != native.PlatformSuffix || snapshot.Wheel.Filename != wheelFilename(snapshot.Wheel.Version, native) {
		return fmt.Errorf("minimum snapshot source or native wheel identity is invalid")
	}
	if _, err := hex.DecodeString(snapshot.SourceDigest); err != nil {
		return fmt.Errorf("minimum snapshot source digest is invalid")
	}
	paths := []string{"package.json", "LICENSE", sourceCLIContractPath, "python/agentic_proofkit/__init__.py", "python/agentic_proofkit/__main__.py", "python/agentic_proofkit/cli.py", "artifacts/pypi/python-packages.json", "artifacts/pypi/" + snapshot.Wheel.Filename, native.BinaryPath, "runner", minimumPipFile}
	if len(snapshot.Files) != len(paths) {
		return fmt.Errorf("minimum snapshot input inventory is incomplete")
	}
	for _, path := range paths {
		value := snapshot.Files[path]
		if len(value) != 64 {
			return fmt.Errorf("minimum snapshot input digest is missing")
		}
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("minimum snapshot input digest is invalid")
		}
	}
	if snapshot.Files["artifacts/pypi/"+snapshot.Wheel.Filename] != snapshot.Wheel.Sha256 || snapshot.Files[native.BinaryPath] != snapshot.Wheel.BinarySha256 || snapshot.Files[minimumPipFile] != minimumPipSHA256 {
		return fmt.Errorf("minimum snapshot digests disagree with wheel or installer pins")
	}
	return nil
}

func minimumCheckWheelWrappers(wheel []byte, sourceRoot string) error {
	archive, err := zip.NewReader(bytes.NewReader(wheel), int64(len(wheel)))
	if err != nil {
		return err
	}
	for _, name := range []string{"__init__.py", "__main__.py", "cli.py"} {
		expected, err := artifactfile.ReadBounded(sourceRoot, "python/agentic_proofkit/"+name, maximumWheelTextEntryBytes)
		if err != nil {
			return err
		}
		matches := 0
		for _, entry := range archive.File {
			if entry.Name != "agentic_proofkit/"+name {
				continue
			}
			content, err := readZipFile(entry)
			if err != nil || !bytes.Equal(content, expected) {
				return fmt.Errorf("minimum wheel wrapper differs from current source")
			}
			matches++
		}
		if matches != 1 {
			return fmt.Errorf("minimum wheel wrapper must occur exactly once")
		}
	}
	return nil
}

func minimumDecode[T any](content []byte) (T, error) {
	return admission.DecodeTypedJSON[T](bytes.NewReader(content), int64(len(content)))
}
