package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
	"github.com/research-engineering/agentic-proofkit/internal/tools/sbomsubjects"
)

const maxReleaseArtifactBytes int64 = 512 << 20
const sbomArtifactPath = "artifacts/release/sbom.cdx.json"

func releaseArtifactByteLimit(path string) int64 {
	if filepath.ToSlash(path) == sbomArtifactPath {
		return sbomsubjects.MaxBytes
	}
	return maxReleaseArtifactBytes
}

type releaseArtifactSnapshot struct {
	root     string
	bySource map[string]releaseArtifact
	carriers carrierIdentity
}

type releaseArtifact struct {
	filename  string
	integrity string
	sha1      string
	sha256    string
	size      int64
}

func newReleaseArtifactSnapshot(localRecords []packRecord, pythonPackages *pythonPackageSet) (*releaseArtifactSnapshot, error) {
	packagePaths, err := optionalGlob(filepath.Join("artifacts", "package", "*.tgz"))
	if err != nil {
		return nil, err
	}
	if err := requireExactPathSet(packagePaths, expectedPackageArtifactPaths(localRecords, nil), "release package artifact"); err != nil {
		return nil, err
	}
	wheelPaths, err := optionalGlob(filepath.Join("artifacts", "pypi", "*.whl"))
	if err != nil {
		return nil, err
	}
	if err := requireExactPathSet(wheelPaths, expectedPythonWheelPaths(pythonPackages), "release Python wheel artifact"); err != nil {
		return nil, err
	}
	sourcePaths := expectedPackageArtifactPaths(localRecords, pythonPackages)
	if len(sourcePaths) == 0 {
		return nil, fmt.Errorf("release assets require at least one package artifact")
	}
	sourcePaths = append(sourcePaths, filepath.FromSlash(sbomArtifactPath))
	sort.Strings(sourcePaths)
	root, err := os.MkdirTemp("", "proofkit-release-artifacts-")
	if err != nil {
		return nil, fmt.Errorf("create release artifact snapshot: %w", err)
	}
	snapshot := &releaseArtifactSnapshot{root: root, bySource: make(map[string]releaseArtifact, len(sourcePaths))}
	filenames := make(map[string]struct{}, len(sourcePaths))
	for _, sourcePath := range sourcePaths {
		filename := filepath.Base(sourcePath)
		if _, duplicate := filenames[filename]; duplicate {
			return nil, errors.Join(fmt.Errorf("release assets contain duplicate flattened filenames"), snapshot.Close())
		}
		filenames[filename] = struct{}{}
		artifact, err := snapshotReleaseArtifact(root, sourcePath)
		if err != nil {
			return nil, errors.Join(err, snapshot.Close())
		}
		snapshot.bySource[sourcePath] = artifact
	}
	return snapshot, nil
}

func (snapshot *releaseArtifactSnapshot) Close() error {
	if snapshot == nil || snapshot.root == "" {
		return nil
	}
	if err := os.RemoveAll(snapshot.root); err != nil {
		return fmt.Errorf("remove release artifact snapshot: %w", err)
	}
	snapshot.root = ""
	snapshot.bySource = nil
	snapshot.carriers = carrierIdentity{}
	return nil
}

func (snapshot *releaseArtifactSnapshot) VerifyCrossCarrierBinaryIdentity(localRecords []packRecord, pythonPackages *pythonPackageSet) error {
	if err := snapshot.requireOpen(); err != nil {
		return err
	}
	snapshot.carriers = carrierIdentity{}
	identity, err := verifyCrossCarrierBinaryIdentity(
		filepath.Join(snapshot.root, "artifacts", "package"),
		filepath.Join(snapshot.root, "artifacts", "pypi"),
		localRecords,
		pythonPackages,
	)
	if err != nil {
		return err
	}
	if pythonPackages != nil {
		if len(identity.wheelsByName) != len(pythonPackages.Packages) {
			return fmt.Errorf("python wheel identity decoder lacks exact package closure")
		}
		for _, record := range pythonPackages.Packages {
			wheel, ok := identity.wheelsByName[record.Filename]
			if !ok {
				return fmt.Errorf("python wheel identity decoder lacks an expected package")
			}
			artifact, ok := snapshot.bySource[filepath.Join("artifacts", "pypi", record.Filename)]
			if !ok {
				return fmt.Errorf("release artifact snapshot lacks an expected Python wheel")
			}
			wheel.wheelSHA256 = artifact.sha256
			if record.Sha256 != wheel.wheelSHA256 || record.BinarySha256 != wheel.binarySHA256 {
				return fmt.Errorf("python package-set digest claims do not match immutable wheel bytes")
			}
			identity.wheelsByName[record.Filename] = wheel
		}
	}
	snapshot.carriers = identity
	return nil
}

func (snapshot *releaseArtifactSnapshot) AdmittedPythonPackageSet(pythonPackages *pythonPackageSet) (*pythonPackageSet, error) {
	if err := snapshot.requireOpen(); err != nil {
		return nil, err
	}
	if pythonPackages == nil {
		return nil, nil
	}
	if len(snapshot.carriers.wheelsByName) != len(pythonPackages.Packages) {
		return nil, fmt.Errorf("python wheel bytes have not passed exact immutable identity admission")
	}
	admitted := *pythonPackages
	admitted.Packages = append([]pythonWheelRecord(nil), pythonPackages.Packages...)
	for index := range admitted.Packages {
		identity, ok := snapshot.carriers.wheelsByName[admitted.Packages[index].Filename]
		if !ok {
			return nil, fmt.Errorf("python wheel identity admission lacks an expected package")
		}
		admitted.Packages[index].Sha256 = identity.wheelSHA256
		admitted.Packages[index].BinarySha256 = identity.binarySHA256
	}
	return &admitted, nil
}

func (snapshot *releaseArtifactSnapshot) AdmittedNPMRecords(records []packRecord) ([]packRecord, error) {
	if err := snapshot.requireOpen(); err != nil {
		return nil, err
	}
	admitted := append([]packRecord(nil), records...)
	for index := range admitted {
		artifact, ok := snapshot.bySource[filepath.Join("artifacts", "package", admitted[index].Filename)]
		if !ok {
			return nil, fmt.Errorf("release artifact snapshot lacks an expected npm tarball")
		}
		if admitted[index].Shasum != artifact.sha1 || admitted[index].Integrity != artifact.integrity {
			return nil, fmt.Errorf("npm pack digest claims do not match immutable tarball bytes")
		}
		admitted[index].Shasum = artifact.sha1
		admitted[index].Integrity = artifact.integrity
	}
	return admitted, nil
}

func (snapshot *releaseArtifactSnapshot) ReleaseEvidence(version string) ([]assetEvidence, []string, []string, error) {
	if err := snapshot.requireOpen(); err != nil {
		return nil, nil, nil, err
	}
	sbomPath := filepath.FromSlash(sbomArtifactPath)
	sbomArtifact, ok := snapshot.bySource[sbomPath]
	if !ok || sbomArtifact.size > sbomsubjects.MaxBytes {
		return nil, nil, nil, fmt.Errorf("release artifact snapshot requires a bounded SBOM")
	}
	assetPaths := make([]string, 0, len(snapshot.bySource))
	for sourcePath := range snapshot.bySource {
		assetPaths = append(assetPaths, sourcePath)
	}
	sort.Strings(assetPaths)
	assets := make([]assetEvidence, 0, len(assetPaths))
	checksums := make([]string, 0, len(assetPaths))
	subjectChecksums := make([]string, 0, len(assetPaths)-1)
	binaryPaths := releaseplatform.BinaryPaths()
	expectedSubjects := make(map[string]string, len(assetPaths)-1+len(binaryPaths))
	for _, sourcePath := range assetPaths {
		artifact := snapshot.bySource[sourcePath]
		assets = append(assets, assetEvidence{Filename: artifact.filename, Sha256: artifact.sha256})
		line := fmt.Sprintf("%s  %s", artifact.sha256, artifact.filename)
		checksums = append(checksums, line)
		if sourcePath != sbomPath {
			expectedSubjects[filepath.ToSlash(sourcePath)] = artifact.sha256
			subjectChecksums = append(subjectChecksums, line)
		}
	}
	for _, binaryPath := range binaryPaths {
		digest, ok := snapshot.carriers.binariesByPath[binaryPath]
		if !ok {
			return nil, nil, nil, fmt.Errorf("release artifact snapshot lacks an admitted carrier binary for %q", binaryPath)
		}
		expectedSubjects[binaryPath] = digest
	}
	sbom, err := os.Open(filepath.Join(snapshot.root, sbomPath))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open release SBOM snapshot: %w", err)
	}
	defer sbom.Close()
	content, err := io.ReadAll(io.LimitReader(sbom, sbomsubjects.MaxBytes+1))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read release SBOM snapshot: %w", err)
	}
	if int64(len(content)) != sbomArtifact.size || fmt.Sprintf("%x", sha256.Sum256(content)) != sbomArtifact.sha256 {
		return nil, nil, nil, fmt.Errorf("release SBOM bytes differ from the admitted snapshot digest")
	}
	if err := sbomsubjects.Admit(content, expectedSubjects, version); err != nil {
		return nil, nil, nil, err
	}
	return assets, checksums, subjectChecksums, nil
}

func (snapshot *releaseArtifactSnapshot) RevalidateSources() error {
	if err := snapshot.requireOpen(); err != nil {
		return err
	}
	paths := make([]string, 0, len(snapshot.bySource))
	for path := range snapshot.bySource {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		actual, err := stableReleaseArtifactIdentity(path)
		if err != nil {
			return err
		}
		expected := snapshot.bySource[path]
		if actual.size != expected.size || actual.sha256 != expected.sha256 {
			return fmt.Errorf("release artifact source changed after immutable admission")
		}
	}
	return nil
}

func (snapshot *releaseArtifactSnapshot) requireOpen() error {
	if snapshot == nil || snapshot.root == "" || snapshot.bySource == nil {
		return fmt.Errorf("release artifact snapshot is closed")
	}
	return nil
}

func snapshotReleaseArtifact(snapshotRoot string, sourcePath string) (releaseArtifact, error) {
	clean, err := admittedReleaseArtifactPath(sourcePath)
	if err != nil {
		return releaseArtifact{}, err
	}
	source, before, root, err := openStableReleaseArtifact(clean)
	if err != nil {
		return releaseArtifact{}, err
	}
	defer root.Close()
	defer source.Close()
	destination := filepath.Join(snapshotRoot, clean)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return releaseArtifact{}, fmt.Errorf("create release snapshot directory: %w", err)
	}
	target, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return releaseArtifact{}, fmt.Errorf("create release snapshot file: %w", err)
	}
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	sha512Hash := sha512.New()
	limit := releaseArtifactByteLimit(clean)
	written, copyErr := io.Copy(io.MultiWriter(target, sha1Hash, sha256Hash, sha512Hash), io.LimitReader(source, limit+1))
	syncErr := target.Sync()
	closeErr := target.Close()
	if copyErr != nil {
		return releaseArtifact{}, fmt.Errorf("copy release artifact snapshot: %w", copyErr)
	}
	if syncErr != nil {
		return releaseArtifact{}, fmt.Errorf("sync release artifact snapshot: %w", syncErr)
	}
	if closeErr != nil {
		return releaseArtifact{}, fmt.Errorf("close release artifact snapshot: %w", closeErr)
	}
	if written > limit {
		return releaseArtifact{}, fmt.Errorf("release artifact exceeds the byte limit")
	}
	after, err := source.Stat()
	pathAfter, pathErr := root.Lstat(clean)
	directoryErr := admitReleaseArtifactDirectories(root, clean)
	if err != nil || pathErr != nil || directoryErr != nil || pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) || !os.SameFile(after, pathAfter) || before.Size() != after.Size() || after.Size() != written || !before.ModTime().Equal(after.ModTime()) {
		return releaseArtifact{}, fmt.Errorf("release artifact changed during immutable admission")
	}
	return releaseArtifact{
		filename:  filepath.Base(clean),
		integrity: "sha512-" + base64.StdEncoding.EncodeToString(sha512Hash.Sum(nil)),
		sha1:      hex.EncodeToString(sha1Hash.Sum(nil)),
		sha256:    hex.EncodeToString(sha256Hash.Sum(nil)),
		size:      written,
	}, nil
}

func stableReleaseArtifactIdentity(sourcePath string) (releaseArtifact, error) {
	clean, err := admittedReleaseArtifactPath(sourcePath)
	if err != nil {
		return releaseArtifact{}, err
	}
	file, before, root, err := openStableReleaseArtifact(clean)
	if err != nil {
		return releaseArtifact{}, err
	}
	defer root.Close()
	defer file.Close()
	hash := sha256.New()
	limit := releaseArtifactByteLimit(clean)
	size, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return releaseArtifact{}, fmt.Errorf("revalidate release artifact: %w", err)
	}
	if size > limit {
		return releaseArtifact{}, fmt.Errorf("release artifact exceeds the byte limit")
	}
	after, err := file.Stat()
	pathAfter, pathErr := root.Lstat(clean)
	directoryErr := admitReleaseArtifactDirectories(root, clean)
	if err != nil || pathErr != nil || directoryErr != nil || pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) || !os.SameFile(after, pathAfter) || before.Size() != after.Size() || after.Size() != size || !before.ModTime().Equal(after.ModTime()) {
		return releaseArtifact{}, fmt.Errorf("release artifact changed during revalidation")
	}
	return releaseArtifact{sha256: hex.EncodeToString(hash.Sum(nil)), size: size}, nil
}

func admittedReleaseArtifactPath(path string) (string, error) {
	clean := filepath.Clean(path)
	if clean == "." || !filepath.IsLocal(clean) || clean != path {
		return "", fmt.Errorf("release artifact path must be normalized and repository-relative")
	}
	return clean, nil
}

func openStableReleaseArtifact(path string) (*os.File, fs.FileInfo, *os.Root, error) {
	root, err := os.OpenRoot(".")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open release artifact root: %w", err)
	}
	if err := admitReleaseArtifactDirectories(root, path); err != nil {
		root.Close()
		return nil, nil, nil, err
	}
	before, err := root.Lstat(path)
	if err != nil {
		root.Close()
		return nil, nil, nil, fmt.Errorf("inspect release artifact: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > releaseArtifactByteLimit(path) {
		root.Close()
		return nil, nil, nil, fmt.Errorf("release artifact must be a bounded regular non-symlink file")
	}
	file, err := rootpath.OpenRegularFile(root, filepath.ToSlash(path))
	if err != nil {
		root.Close()
		return nil, nil, nil, fmt.Errorf("open release artifact: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		file.Close()
		root.Close()
		return nil, nil, nil, fmt.Errorf("release artifact changed before admission")
	}
	return file, opened, root, nil
}

func admitReleaseArtifactDirectories(root *os.Root, path string) error {
	for current := filepath.Dir(path); current != "."; current = filepath.Dir(current) {
		info, err := root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("release artifact path traverses an inadmissible directory")
		}
	}
	return nil
}
