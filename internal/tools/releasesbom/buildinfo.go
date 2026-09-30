package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"io"
	"runtime/debug"
)

// The release toolchain emits inline build info in a dedicated ELF/Mach-O
// section. Read may silently drop damaged framing or unknown records; compare
// the entire section with the linker's canonical encoding of its decoded data.
func completeBinaryBuildInfo(reader io.ReaderAt, info *debug.BuildInfo) bool {
	if info.Path == "" {
		return false
	}
	for _, dep := range info.Deps {
		if dep.Path == "" || (dep.Replace != nil && dep.Replace.Path == "") {
			return false
		}
	}
	body := *info
	body.GoVersion = ""
	framed := "\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6" + body.String() +
		"\xf9\x32\x43\x31\x86\x18\x20\x72\x00\x82\x42\x10\x41\x16\xd8\xf2"
	expected := make([]byte, 32)
	copy(expected, "\xff Go buildinf:")
	expected[14], expected[15] = 8, 2 // Supported targets: 64-bit, little-endian, inline.
	expected = binary.AppendUvarint(expected, uint64(len(info.GoVersion)))
	expected = append(expected, info.GoVersion...)
	expected = binary.AppendUvarint(expected, uint64(len(framed)))
	expected = append(expected, framed...)
	for len(expected)%16 != 0 {
		expected = append(expected, 0)
	}

	section, size := binaryBuildInfoSection(reader)
	if section == nil || size != uint64(len(expected)) {
		return false
	}
	actual := make([]byte, len(expected))
	_, err := io.ReadFull(section, actual)
	return err == nil && bytes.Equal(actual, expected)
}

func binaryBuildInfoSection(reader io.ReaderAt) (io.Reader, uint64) {
	var magic [4]byte
	if _, err := reader.ReadAt(magic[:], 0); err != nil {
		return nil, 0
	}
	if string(magic[:]) == "\x7fELF" {
		file, err := elf.NewFile(reader)
		if err != nil {
			return nil, 0
		}
		var selected *elf.Section
		for _, section := range file.Sections {
			if section.Name == ".go.buildinfo" {
				if selected != nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_COMPRESSED != 0 {
					return nil, 0
				}
				selected = section
			}
		}
		if selected != nil {
			return selected.Open(), selected.Size
		}
	} else if binary.LittleEndian.Uint32(magic[:]) == macho.Magic64 {
		file, err := macho.NewFile(reader)
		if err != nil {
			return nil, 0
		}
		var selected *macho.Section
		for _, section := range file.Sections {
			if section.Name == "__go_buildinfo" {
				if selected != nil {
					return nil, 0
				}
				selected = section
			}
		}
		if selected != nil {
			return selected.Open(), selected.Size
		}
	}
	return nil, 0
}
