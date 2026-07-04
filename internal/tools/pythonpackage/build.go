package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type wheelEntry struct {
	Content []byte
	Mode    os.FileMode
	Path    string
}

const maxZip32Size = uint64(^uint32(0))

func buildPythonPackages() error {
	return buildPythonPackagesForTargets(releaseTargets())
}

func buildCurrentPythonPackage() error {
	current, err := currentTarget()
	if err != nil {
		return err
	}
	return buildPythonPackagesForTargets([]target{current})
}

func buildPythonPackagesForTargets(selectedTargets []target) error {
	manifest, err := readPackageJSON()
	if err != nil {
		return err
	}
	outputDir := filepath.Join("artifacts", "pypi")
	if err := os.RemoveAll(outputDir); err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	records := make([]wheelRecord, 0, len(selectedTargets))
	for _, target := range selectedTargets {
		record, err := buildWheel(outputDir, manifest, target)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(left int, right int) bool {
		return records[left].Filename < records[right].Filename
	})
	packageSet := packageSet{
		ArtifactKind:   artifactKind,
		SchemaVersion:  schemaVersion,
		PackageName:    packageName,
		PackageVersion: manifest.Version,
		Packages:       records,
		NonClaims: []string{
			"These wheels are local candidate artifacts until a PyPI release workflow publishes them through an admitted channel.",
			"The Python package is a package-manager wrapper over the same Go CLI; it does not create a Python SDK contract.",
			"Consumer adoption, proof freshness, merge policy, and rollout policy remain consumer-owned.",
		},
	}
	content, err := json.MarshalIndent(packageSet, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "python-packages.json"), append(content, '\n'), 0o644)
}

func buildWheel(outputDir string, manifest packageJSON, target target) (wheelRecord, error) {
	binary, err := os.ReadFile(target.BinaryPath)
	if err != nil {
		return wheelRecord{}, fmt.Errorf("read platform binary %s: %w", target.BinaryPath, err)
	}
	entries, err := wheelEntries(manifest, target, binary)
	if err != nil {
		return wheelRecord{}, err
	}
	filename := wheelFilename(manifest.Version, target)
	path := filepath.Join(outputDir, filename)
	if err := writeWheel(path, entries); err != nil {
		return wheelRecord{}, err
	}
	sha, err := fileSHA256(path)
	if err != nil {
		return wheelRecord{}, err
	}
	binarySha := sha256.Sum256(binary)
	return wheelRecord{
		AbiTag:         abiTag,
		BinarySha256:   hex.EncodeToString(binarySha[:]),
		Filename:       filename,
		Name:           packageName,
		PlatformSuffix: target.PlatformSuffix,
		PlatformTag:    target.PlatformTag,
		PythonTag:      pythonTag,
		Sha256:         sha,
		Version:        manifest.Version,
		WheelTag:       target.WheelTag,
	}, nil
}

func wheelEntries(manifest packageJSON, target target, binary []byte) ([]wheelEntry, error) {
	distInfo := distInfoDir(manifest.Version)
	sourceFiles := []string{
		"python/agentic_proofkit/__init__.py",
		"python/agentic_proofkit/__main__.py",
		"python/agentic_proofkit/cli.py",
	}
	entries := make([]wheelEntry, 0, len(sourceFiles)+5)
	for _, source := range sourceFiles {
		content, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		entries = append(entries, wheelEntry{
			Content: content,
			Mode:    0o644,
			Path:    strings.TrimPrefix(source, "python/"),
		})
	}
	entries = append(entries,
		wheelEntry{
			Content: binary,
			Mode:    0o755,
			Path:    "agentic_proofkit/bin/agentic-proofkit",
		},
		wheelEntry{
			Content: []byte(metadata(manifest)),
			Mode:    0o644,
			Path:    distInfo + "/METADATA",
		},
		wheelEntry{
			Content: []byte(wheelMetadata(target)),
			Mode:    0o644,
			Path:    distInfo + "/WHEEL",
		},
		wheelEntry{
			Content: []byte(entryPoints()),
			Mode:    0o644,
			Path:    distInfo + "/entry_points.txt",
		},
	)
	sort.Slice(entries, func(left int, right int) bool {
		return entries[left].Path < entries[right].Path
	})
	entries = append(entries, wheelEntry{
		Content: recordContent(entries, distInfo+"/RECORD"),
		Mode:    0o644,
		Path:    distInfo + "/RECORD",
	})
	return entries, nil
}

func metadata(manifest packageJSON) string {
	return strings.Join([]string{
		"Metadata-Version: 2.1",
		"Name: " + packageName,
		"Version: " + manifest.Version,
		"Summary: " + manifest.Description,
		"License: " + manifest.License,
		"Requires-Python: >=3.9",
		"Project-URL: Source, " + strings.TrimPrefix(manifest.Repository.URL, "git+"),
		"",
		"Package-manager wrapper for the agentic-proofkit Go CLI.",
		"",
	}, "\n")
}

func wheelMetadata(target target) string {
	return strings.Join([]string{
		"Wheel-Version: 1.0",
		"Generator: agentic-proofkit",
		"Root-Is-Purelib: false",
		"Tag: " + target.WheelTag,
		"",
	}, "\n")
}

func entryPoints() string {
	return "[console_scripts]\nagentic-proofkit = agentic_proofkit.cli:main\n"
}

func recordContent(entries []wheelEntry, recordPath string) []byte {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	for _, entry := range entries {
		sum := sha256.Sum256(entry.Content)
		hash := base64.RawURLEncoding.EncodeToString(sum[:])
		_ = writer.Write([]string{
			entry.Path,
			"sha256=" + hash,
			strconv.Itoa(len(entry.Content)),
		})
	}
	_ = writer.Write([]string{recordPath, "", ""})
	writer.Flush()
	return buffer.Bytes()
}

func writeWheel(path string, entries []wheelEntry) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	defer writer.Close()
	for _, entry := range entries {
		if uint64(len(entry.Content)) > maxZip32Size {
			return fmt.Errorf("wheel entry %s exceeds ZIP32 size limit", entry.Path)
		}
		compressed, err := deflateContent(entry.Content)
		if err != nil {
			return err
		}
		if uint64(len(compressed)) > maxZip32Size {
			return fmt.Errorf("compressed wheel entry %s exceeds ZIP32 size limit", entry.Path)
		}
		header := &zip.FileHeader{
			Name:               entry.Path,
			Method:             zip.Deflate,
			Modified:           time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC),
			CRC32:              crc32.ChecksumIEEE(entry.Content),
			CompressedSize:     uint32(len(compressed)),
			CompressedSize64:   uint64(len(compressed)),
			UncompressedSize:   uint32(len(entry.Content)),
			UncompressedSize64: uint64(len(entry.Content)),
		}
		header.SetMode(entry.Mode)
		entryWriter, err := writer.CreateRaw(header)
		if err != nil {
			return err
		}
		if _, err := entryWriter.Write(compressed); err != nil {
			return err
		}
	}
	return nil
}

func deflateContent(content []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer, err := flate.NewWriter(&buffer, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
