package main

import (
	"archive/zip"
	"encoding/binary"
	"errors"
)

// PKWARE APPNOTE 4.4.3 requires ZIP 2.0 for a ZIP32 Deflate entry.
const zipDeflateReaderVersion = 20

// archive/zip exposes the central version but does not verify the local one.
// Follow the central records' offsets in the wheel writer's ZIP32 layout.
func verifyWheelZIPVersions(content []byte, files []*zip.File) error {
	const (
		endSize     = 22
		centralSize = 46
		localSize   = 30
	)
	invalidLayout := errors.New("invalid wheel ZIP32 header layout")
	end := len(content) - endSize
	if end < 0 || binary.LittleEndian.Uint32(content[end:]) != 0x06054b50 {
		return invalidLayout
	}
	start := int64(binary.LittleEndian.Uint32(content[end+16:]))
	size := int64(binary.LittleEndian.Uint32(content[end+12:]))
	if start+size != int64(end) {
		return invalidLayout
	}
	directory := content[start:end]
	for _, file := range files {
		if len(directory) < centralSize || binary.LittleEndian.Uint32(directory) != 0x02014b50 {
			return invalidLayout
		}
		if file.Method != zip.Deflate || file.ReaderVersion != zipDeflateReaderVersion {
			return errors.New("invalid central ZIP extraction version or compression method")
		}
		local := int64(binary.LittleEndian.Uint32(directory[42:]))
		if local+localSize > start || binary.LittleEndian.Uint32(content[local:]) != 0x04034b50 {
			return invalidLayout
		}
		if binary.LittleEndian.Uint16(content[local+4:]) != zipDeflateReaderVersion ||
			binary.LittleEndian.Uint16(content[local+8:]) != zip.Deflate {
			return errors.New("invalid local ZIP extraction version or compression method")
		}
		recordSize := centralSize +
			int(binary.LittleEndian.Uint16(directory[28:])) +
			int(binary.LittleEndian.Uint16(directory[30:])) +
			int(binary.LittleEndian.Uint16(directory[32:]))
		if recordSize > len(directory) {
			return invalidLayout
		}
		directory = directory[recordSize:]
	}
	if len(directory) != 0 {
		return invalidLayout
	}
	return nil
}
