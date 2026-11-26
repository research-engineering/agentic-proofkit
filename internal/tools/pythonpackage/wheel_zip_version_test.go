package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
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
}
