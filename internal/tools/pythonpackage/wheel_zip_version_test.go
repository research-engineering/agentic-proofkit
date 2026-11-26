package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestWheelDeflateReaderVersions(t *testing.T) {
	const version = "1.2.3"
	target := releaseTargets()[0]
	payload := macho64WithMinimumMacOS(13, 0, 0)
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheelWithBinary(t, path, version, wheelMetadata(target), payload)
	wheel, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Resolve the second entry's local header from its central directory
	// record, not by searching for signatures in compressed data.
	end := len(wheel) - 22
	zip32End := wheel[end:]
	if binary.LittleEndian.Uint32(zip32End) != 0x06054b50 {
		t.Fatal("fixture must end with an unadorned ZIP32 directory footer")
	}
	first := int(binary.LittleEndian.Uint32(zip32End[16:]))
	header := wheel[first : first+46]
	second := first + 46 + int(binary.LittleEndian.Uint16(header[28:])) +
		int(binary.LittleEndian.Uint16(header[30:])) + int(binary.LittleEndian.Uint16(header[32:]))
	if binary.LittleEndian.Uint32(wheel[second:]) != 0x02014b50 {
		t.Fatal("fixture must have a second central header")
	}
	local := int(binary.LittleEndian.Uint32(wheel[second+42:]))
	if binary.LittleEndian.Uint32(wheel[local:]) != 0x04034b50 {
		t.Fatal("second central entry must resolve to a local header")
	}
	verify := func(data []byte) error {
		return verifyWheelArchive(path, data, testPackageManifest(version), target, binarySHA256(payload),
			[]byte(testLicenseContent), []byte(testCLIContractContent))
	}
	if err := verify(wheel); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{"local", local + 4},
		{"central", second + 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := binary.LittleEndian.Uint16(wheel[tc.offset:]); got != 20 {
				t.Fatalf("Deflate extraction version = %d, want ZIP 2.0", got)
			}
			mutant := bytes.Clone(wheel)
			binary.LittleEndian.PutUint16(mutant[tc.offset:], 0)
			if err := verify(mutant); err == nil || !strings.Contains(err.Error(), tc.name+" ZIP extraction version") {
				t.Fatalf("verify modified %s header: %v", tc.name, err)
			}
		})
	}
	t.Run("inconsistent directory footer", func(t *testing.T) {
		mutant := bytes.Clone(wheel)
		binary.LittleEndian.PutUint16(mutant[end+8:], 0)
		if err := verify(mutant); err == nil || !strings.Contains(err.Error(), "invalid wheel ZIP32 header layout") {
			t.Fatalf("verify inconsistent per-disk record count: %v", err)
		}
	})
	t.Run("local size does not use ZIP32", func(t *testing.T) {
		mutant := bytes.Clone(wheel)
		binary.LittleEndian.PutUint32(mutant[local+18:], ^uint32(0))
		if err := verify(mutant); err == nil || !strings.Contains(err.Error(), "wheel ZIP32 entry sizes") {
			t.Fatalf("verify local size encoding: %v", err)
		}
	})
	t.Run("equal decoded size does not justify ZIP64", func(t *testing.T) {
		mutant := bytes.Clone(wheel)
		record := mutant[second:]
		compressedSize := binary.LittleEndian.Uint32(record[20:])
		nameLength := int(binary.LittleEndian.Uint16(record[28:]))
		extraLength := binary.LittleEndian.Uint16(record[30:])
		extra := binary.LittleEndian.AppendUint64([]byte{1, 0, 8, 0}, uint64(compressedSize))
		binary.LittleEndian.PutUint32(record[20:], ^uint32(0))
		binary.LittleEndian.PutUint16(record[30:], extraLength+uint16(len(extra)))
		directorySize := binary.LittleEndian.Uint32(mutant[end+12:])
		binary.LittleEndian.PutUint32(mutant[end+12:], directorySize+uint32(len(extra)))
		mutant = slices.Insert(mutant, second+46+nameLength, extra...)
		if err := verify(mutant); err == nil || !strings.Contains(err.Error(), "wheel ZIP32 entry sizes") {
			t.Fatalf("verify central size encoding: %v", err)
		}
	})
}
