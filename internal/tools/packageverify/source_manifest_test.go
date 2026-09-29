package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestCurrentSourceManifestFitsArchiveBoundary(t *testing.T) {
	content := mustReadBytes(t, filepath.Join("..", "..", "..", "package.json"))
	var manifest packageManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	archive := writePackageTarball(t, map[string]string{"package/package.json": string(content)})
	artifact := rootPackageArtifact{Content: mustReadBytes(t, archive), Record: packRecord{Version: manifest.Version}}
	if err := verifyRootManifestBoundary(artifact); err != nil {
		t.Fatalf("current source manifest cannot pass its archive boundary: %v", err)
	}
}
