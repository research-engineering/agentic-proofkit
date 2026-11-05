package packagearchive

import (
	"archive/zip"
	"fmt"
)

// AdmitZIPEntries checks all effective paths before a consumer selects a body.
// It does not decompress members or verify their contents.
func AdmitZIPEntries(files []*zip.File, maximumEntries int) (map[string]*zip.File, error) {
	if maximumEntries <= 0 || len(files) > maximumEntries {
		return nil, fmt.Errorf("package archive exceeds entry count limit")
	}
	entries := make(map[string]*zip.File, len(files))
	for _, file := range files {
		if !canonicalEntryPath(file.Name) || !file.Mode().IsRegular() {
			return nil, fmt.Errorf("package archive requires canonical regular ZIP entries")
		}
		if _, exists := entries[file.Name]; exists {
			return nil, fmt.Errorf("package archive contains duplicate ZIP entries")
		}
		entries[file.Name] = file
	}
	if err := verifyFileTree(entries); err != nil {
		return nil, err
	}
	return entries, nil
}
