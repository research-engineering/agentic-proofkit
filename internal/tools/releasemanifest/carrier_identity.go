package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

type pythonWheelIdentity struct {
	binarySHA256 string
	wheelSHA256  string
}

func verifyCrossCarrierBinaryIdentity(packageDir string, pythonDir string, localRecords []packRecord, pythonPackages *pythonPackageSet) (identities map[string]pythonWheelIdentity, returnErr error) {
	if pythonPackages == nil {
		return nil, nil
	}
	if len(localRecords) != 1 {
		return nil, fmt.Errorf("cross-carrier identity requires exactly one npm package artifact")
	}
	scratch, err := os.MkdirTemp("", "proofkit-carrier-binaries-")
	if err != nil {
		return nil, fmt.Errorf("create cross-carrier scratch directory: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, os.RemoveAll(scratch))
	}()
	npmBinaries, err := extractNPMCarrierBinaries(filepath.Join(packageDir, localRecords[0].Filename), scratch)
	if err != nil {
		return nil, fmt.Errorf("decode npm package carrier: %w", err)
	}
	wheelsBySuffix := make(map[string]pythonWheelRecord, len(pythonPackages.Packages))
	for _, record := range pythonPackages.Packages {
		if _, exists := wheelsBySuffix[record.PlatformSuffix]; exists {
			return nil, fmt.Errorf("cross-carrier identity contains a duplicate Python platform suffix")
		}
		wheelsBySuffix[record.PlatformSuffix] = record
	}
	targets := releaseplatform.Targets()
	if len(wheelsBySuffix) != len(targets) {
		return nil, fmt.Errorf("cross-carrier identity requires exact release-platform wheel closure")
	}
	identities = make(map[string]pythonWheelIdentity, len(targets))
	for _, target := range targets {
		npmBinary, exists := npmBinaries[target.PlatformSuffix]
		if !exists {
			return nil, fmt.Errorf("npm package carrier is missing a release-platform binary")
		}
		wheel, exists := wheelsBySuffix[target.PlatformSuffix]
		if !exists {
			return nil, fmt.Errorf("python package carrier is missing a release-platform wheel")
		}
		equal, binarySHA256, err := wheelCarrierBinaryEquals(filepath.Join(pythonDir, wheel.Filename), npmBinary)
		if err != nil {
			return nil, fmt.Errorf("decode python wheel carrier: %w", err)
		}
		if !equal {
			return nil, fmt.Errorf("npm and python package carriers contain different release-platform binary bytes")
		}
		identities[wheel.Filename] = pythonWheelIdentity{binarySHA256: binarySHA256}
	}
	return identities, nil
}

type extractedCarrierBinary struct {
	path string
	size int64
}

func extractNPMCarrierBinaries(path string, scratch string) (map[string]extractedCarrierBinary, error) {
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
	binaries := make(map[string]extractedCarrierBinary, len(expected))
	seenNames := make(map[string]struct{})
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
		if _, duplicate := seenNames[header.Name]; duplicate {
			return nil, fmt.Errorf("npm package carrier contains duplicate entries")
		}
		seenNames[header.Name] = struct{}{}
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
		if header.Size > maxCarrierBinaryBytes {
			return nil, fmt.Errorf("package carrier binary exceeds the byte limit")
		}
		destination := filepath.Join(scratch, platformSuffix)
		binary, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		written, copyErr := io.CopyN(binary, tarReader, header.Size)
		closeErr := binary.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return nil, err
		}
		if written != header.Size {
			return nil, fmt.Errorf("package carrier binary size differs from its archive header")
		}
		binaries[platformSuffix] = extractedCarrierBinary{path: destination, size: written}
	}
	if len(binaries) != len(expected) {
		return nil, fmt.Errorf("npm package carrier lacks exact release-platform binary closure")
	}
	return binaries, nil
}

func wheelCarrierBinaryEquals(path string, expected extractedCarrierBinary) (bool, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCarrierArchiveBytes {
		return false, "", fmt.Errorf("python wheel carrier is not an admitted regular archive")
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return false, "", err
	}
	defer reader.Close()
	if len(reader.File) > maxCarrierArchiveEntries {
		return false, "", fmt.Errorf("python wheel carrier exceeds the entry limit")
	}
	seen := map[string]struct{}{}
	found := false
	equal := false
	binarySHA256 := ""
	for _, entry := range reader.File {
		if _, duplicate := seen[entry.Name]; duplicate {
			return false, "", fmt.Errorf("python wheel carrier contains duplicate entries")
		}
		seen[entry.Name] = struct{}{}
		if entry.Name != wheelBinaryEntry {
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 || !entry.FileInfo().Mode().IsRegular() {
			return false, "", fmt.Errorf("python wheel carrier binary is not a regular file")
		}
		if entry.UncompressedSize64 > uint64(maxCarrierBinaryBytes) {
			return false, "", fmt.Errorf("python wheel carrier binary exceeds the byte limit")
		}
		if found {
			return false, "", fmt.Errorf("python wheel carrier contains duplicate embedded binaries")
		}
		found = true
		if int64(entry.UncompressedSize64) != expected.size {
			continue
		}
		member, err := entry.Open()
		if err != nil {
			return false, "", err
		}
		expectedFile, err := os.Open(expected.path)
		if err != nil {
			member.Close()
			return false, "", err
		}
		hash := sha256.New()
		equal, err = equalCarrierStreams(io.TeeReader(member, hash), expectedFile)
		memberCloseErr := member.Close()
		expectedCloseErr := expectedFile.Close()
		if err != nil {
			return false, "", err
		}
		if memberCloseErr != nil {
			return false, "", memberCloseErr
		}
		if expectedCloseErr != nil {
			return false, "", expectedCloseErr
		}
		if equal {
			binarySHA256 = hex.EncodeToString(hash.Sum(nil))
		}
	}
	if !found {
		return false, "", fmt.Errorf("python wheel carrier lacks its embedded binary")
	}
	return equal, binarySHA256, nil
}

func equalCarrierStreams(left io.Reader, right io.Reader) (bool, error) {
	leftBuffer := make([]byte, 64*1024)
	rightBuffer := make([]byte, len(leftBuffer))
	for {
		leftCount, leftErr := io.ReadFull(left, leftBuffer)
		rightCount, rightErr := io.ReadFull(right, rightBuffer)
		if leftCount != rightCount || !bytes.Equal(leftBuffer[:leftCount], rightBuffer[:rightCount]) {
			return false, nil
		}
		leftDone := leftErr == io.EOF || leftErr == io.ErrUnexpectedEOF
		rightDone := rightErr == io.EOF || rightErr == io.ErrUnexpectedEOF
		if leftDone || rightDone {
			if !leftDone || !rightDone {
				return false, nil
			}
			return true, nil
		}
		if leftErr != nil {
			return false, leftErr
		}
		if rightErr != nil {
			return false, rightErr
		}
	}
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
