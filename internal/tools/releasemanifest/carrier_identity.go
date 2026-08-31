package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

const (
	maxCarrierArchiveBytes         = 256 << 20
	maxCarrierArchiveEntries       = 4096
	maxCarrierBinaryBytes    int64 = 64 << 20
	wheelBinaryEntry               = "agentic_proofkit/bin/agentic-proofkit"
)

func verifyCrossCarrierBinaryIdentity(packageDir string, pythonDir string, localRecords []packRecord, pythonPackages *pythonPackageSet) error {
	if pythonPackages == nil {
		return nil
	}
	if len(localRecords) != 1 {
		return fmt.Errorf("cross-carrier identity requires exactly one npm package artifact")
	}
	npmBinaries, err := readNPMCarrierBinaries(filepath.Join(packageDir, localRecords[0].Filename))
	if err != nil {
		return fmt.Errorf("decode npm package carrier: %w", err)
	}
	wheelsBySuffix := make(map[string]pythonWheelRecord, len(pythonPackages.Packages))
	for _, record := range pythonPackages.Packages {
		if _, exists := wheelsBySuffix[record.PlatformSuffix]; exists {
			return fmt.Errorf("cross-carrier identity contains a duplicate Python platform suffix")
		}
		wheelsBySuffix[record.PlatformSuffix] = record
	}
	targets := releaseplatform.Targets()
	if len(wheelsBySuffix) != len(targets) {
		return fmt.Errorf("cross-carrier identity requires exact release-platform wheel closure")
	}
	for _, target := range targets {
		npmBinary, exists := npmBinaries[target.PlatformSuffix]
		if !exists {
			return fmt.Errorf("npm package carrier is missing a release-platform binary")
		}
		wheel, exists := wheelsBySuffix[target.PlatformSuffix]
		if !exists {
			return fmt.Errorf("python package carrier is missing a release-platform wheel")
		}
		wheelBinary, err := readWheelCarrierBinary(filepath.Join(pythonDir, wheel.Filename))
		if err != nil {
			return fmt.Errorf("decode python wheel carrier: %w", err)
		}
		if !bytes.Equal(npmBinary, wheelBinary) {
			return fmt.Errorf("npm and python package carriers contain different release-platform binary bytes")
		}
	}
	return nil
}

func readNPMCarrierBinaries(path string) (map[string][]byte, error) {
	file, err := openBoundedCarrier(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	expected := make(map[string]string, len(releaseplatform.Targets()))
	for _, target := range releaseplatform.Targets() {
		expected[target.PackageTarEntry] = target.PlatformSuffix
	}
	binaries := make(map[string][]byte, len(expected))
	var totalSize int64
	entryCount := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entryCount++
		if entryCount > maxCarrierArchiveEntries {
			return nil, fmt.Errorf("npm package carrier exceeds the entry limit")
		}
		if header.Size < 0 || header.Size > maxCarrierArchiveBytes-totalSize {
			return nil, fmt.Errorf("npm package carrier exceeds the uncompressed byte limit")
		}
		totalSize += header.Size
		platformSuffix, wanted := expected[header.Name]
		if !wanted {
			continue
		}
		if _, duplicate := binaries[platformSuffix]; duplicate {
			return nil, fmt.Errorf("npm package carrier duplicates a release-platform binary")
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("npm package carrier release-platform binary is not a regular file")
		}
		content, err := readBoundedCarrierMember(tarReader, header.Size)
		if err != nil {
			return nil, err
		}
		binaries[platformSuffix] = content
	}
	if len(binaries) != len(expected) {
		return nil, fmt.Errorf("npm package carrier lacks exact release-platform binary closure")
	}
	return binaries, nil
}

func readWheelCarrierBinary(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCarrierArchiveBytes {
		return nil, fmt.Errorf("python wheel carrier is not an admitted regular archive")
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	if len(reader.File) > maxCarrierArchiveEntries {
		return nil, fmt.Errorf("python wheel carrier exceeds the entry limit")
	}
	seen := map[string]struct{}{}
	var binary []byte
	for _, entry := range reader.File {
		if _, duplicate := seen[entry.Name]; duplicate {
			return nil, fmt.Errorf("python wheel carrier contains duplicate entries")
		}
		seen[entry.Name] = struct{}{}
		if entry.Name != wheelBinaryEntry {
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 || !entry.FileInfo().Mode().IsRegular() {
			return nil, fmt.Errorf("python wheel carrier binary is not a regular file")
		}
		if entry.UncompressedSize64 > uint64(maxCarrierBinaryBytes) {
			return nil, fmt.Errorf("python wheel carrier binary exceeds the byte limit")
		}
		member, err := entry.Open()
		if err != nil {
			return nil, err
		}
		binary, err = readBoundedCarrierMember(member, int64(entry.UncompressedSize64))
		closeErr := member.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	if binary == nil {
		return nil, fmt.Errorf("python wheel carrier lacks its embedded binary")
	}
	return binary, nil
}

func openBoundedCarrier(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCarrierArchiveBytes {
		file.Close()
		return nil, fmt.Errorf("package carrier is not an admitted regular archive")
	}
	return file, nil
}

func readBoundedCarrierMember(reader io.Reader, declaredSize int64) ([]byte, error) {
	if declaredSize < 0 || declaredSize > maxCarrierBinaryBytes {
		return nil, fmt.Errorf("package carrier binary exceeds the byte limit")
	}
	content, err := io.ReadAll(io.LimitReader(reader, maxCarrierBinaryBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != declaredSize {
		return nil, fmt.Errorf("package carrier binary size differs from its archive header")
	}
	return content, nil
}
