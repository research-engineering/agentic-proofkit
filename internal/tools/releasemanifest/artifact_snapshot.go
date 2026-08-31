package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

const maxReleaseArtifactBytes int64 = 512 << 20

type releaseArtifactSnapshot struct {
	root                  string
	bySource              map[string]releaseArtifact
	pythonWheelIdentities map[string]pythonWheelIdentity
}

type releaseArtifact struct {
	filename string
	sha256   string
	size     int64
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
	sourcePaths = append(sourcePaths, filepath.Join("artifacts", "release", "sbom.cdx.json"))
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
	snapshot.pythonWheelIdentities = nil
	return nil
}

func (snapshot *releaseArtifactSnapshot) VerifyCrossCarrierBinaryIdentity(localRecords []packRecord, pythonPackages *pythonPackageSet) error {
	if err := snapshot.requireOpen(); err != nil {
		return err
	}
	snapshot.pythonWheelIdentities = nil
	identities, err := verifyCrossCarrierBinaryIdentity(
		filepath.Join(snapshot.root, "artifacts", "package"),
		filepath.Join(snapshot.root, "artifacts", "pypi"),
		localRecords,
		pythonPackages,
	)
	if err != nil {
		return err
	}
	if pythonPackages == nil {
		snapshot.pythonWheelIdentities = nil
		return nil
	}
	if len(identities) != len(pythonPackages.Packages) {
		return fmt.Errorf("python wheel identity decoder lacks exact package closure")
	}
	for _, record := range pythonPackages.Packages {
		identity, ok := identities[record.Filename]
		if !ok {
			return fmt.Errorf("python wheel identity decoder lacks an expected package")
		}
		artifact, ok := snapshot.bySource[filepath.Join("artifacts", "pypi", record.Filename)]
		if !ok {
			return fmt.Errorf("release artifact snapshot lacks an expected Python wheel")
		}
		identity.wheelSHA256 = artifact.sha256
		if record.Sha256 != identity.wheelSHA256 || record.BinarySha256 != identity.binarySHA256 {
			return fmt.Errorf("python package-set digest claims do not match immutable wheel bytes")
		}
		identities[record.Filename] = identity
	}
	snapshot.pythonWheelIdentities = identities
	return nil
}

func (snapshot *releaseArtifactSnapshot) AdmittedPythonPackageSet(pythonPackages *pythonPackageSet) (*pythonPackageSet, error) {
	if err := snapshot.requireOpen(); err != nil {
		return nil, err
	}
	if pythonPackages == nil {
		return nil, nil
	}
	if len(snapshot.pythonWheelIdentities) != len(pythonPackages.Packages) {
		return nil, fmt.Errorf("python wheel bytes have not passed exact immutable identity admission")
	}
	admitted := *pythonPackages
	admitted.Packages = append([]pythonWheelRecord(nil), pythonPackages.Packages...)
	for index := range admitted.Packages {
		identity, ok := snapshot.pythonWheelIdentities[admitted.Packages[index].Filename]
		if !ok {
			return nil, fmt.Errorf("python wheel identity admission lacks an expected package")
		}
		admitted.Packages[index].Sha256 = identity.wheelSHA256
		admitted.Packages[index].BinarySha256 = identity.binarySHA256
	}
	return &admitted, nil
}

func (snapshot *releaseArtifactSnapshot) ReleaseEvidence(localRecords []packRecord, pythonPackages *pythonPackageSet) ([]assetEvidence, []string, []string, error) {
	if err := snapshot.requireOpen(); err != nil {
		return nil, nil, nil, err
	}
	subjectPaths := expectedPackageArtifactPaths(localRecords, pythonPackages)
	assetPaths := append([]string(nil), subjectPaths...)
	assetPaths = append(assetPaths, filepath.Join("artifacts", "release", "sbom.cdx.json"))
	sort.Strings(assetPaths)
	sort.Strings(subjectPaths)
	assets := make([]assetEvidence, 0, len(assetPaths))
	checksums := make([]string, 0, len(assetPaths))
	subjectChecksums := make([]string, 0, len(subjectPaths))
	for _, sourcePath := range assetPaths {
		artifact, ok := snapshot.bySource[sourcePath]
		if !ok {
			return nil, nil, nil, fmt.Errorf("release artifact snapshot lacks an expected asset")
		}
		assets = append(assets, assetEvidence{Filename: artifact.filename, Sha256: artifact.sha256})
		checksums = append(checksums, fmt.Sprintf("%s  %s", artifact.sha256, artifact.filename))
	}
	for _, sourcePath := range subjectPaths {
		artifact, ok := snapshot.bySource[sourcePath]
		if !ok {
			return nil, nil, nil, fmt.Errorf("release artifact snapshot lacks an expected SBOM subject")
		}
		subjectChecksums = append(subjectChecksums, fmt.Sprintf("%s  %s", artifact.sha256, artifact.filename))
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
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(target, hash), io.LimitReader(source, maxReleaseArtifactBytes+1))
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
	if written > maxReleaseArtifactBytes {
		return releaseArtifact{}, fmt.Errorf("release artifact exceeds the byte limit")
	}
	after, err := source.Stat()
	pathAfter, pathErr := root.Lstat(clean)
	directoryErr := admitReleaseArtifactDirectories(root, clean)
	if err != nil || pathErr != nil || directoryErr != nil || pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) || !os.SameFile(after, pathAfter) || before.Size() != after.Size() || after.Size() != written || !before.ModTime().Equal(after.ModTime()) {
		return releaseArtifact{}, fmt.Errorf("release artifact changed during immutable admission")
	}
	return releaseArtifact{
		filename: filepath.Base(clean),
		sha256:   hex.EncodeToString(hash.Sum(nil)),
		size:     written,
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
	size, err := io.Copy(hash, io.LimitReader(file, maxReleaseArtifactBytes+1))
	if err != nil {
		return releaseArtifact{}, fmt.Errorf("revalidate release artifact: %w", err)
	}
	if size > maxReleaseArtifactBytes {
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
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > maxReleaseArtifactBytes {
		root.Close()
		return nil, nil, nil, fmt.Errorf("release artifact must be a bounded regular non-symlink file")
	}
	file, err := root.Open(path)
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
