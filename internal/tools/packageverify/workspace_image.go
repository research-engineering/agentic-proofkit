package main

import (
	"bytes"
	"fmt"
	"image/png"
)

const (
	workspaceImageEntry     = "package/docs/images/workspace.png"
	maxWorkspaceImageBytes  = 2 << 20
	maxWorkspaceImageWidth  = 2048
	maxWorkspaceImageHeight = 1536
)

func verifyPackedWorkspaceImage(artifact rootPackageArtifact) error {
	content, err := readTarFileFromBytes(artifact.Content, workspaceImageEntry)
	if err != nil {
		return err
	}
	return verifyWorkspaceImage(content)
}

func verifyWorkspaceImage(content []byte) error {
	if len(content) == 0 || len(content) > maxWorkspaceImageBytes {
		return fmt.Errorf("root package workspace image exceeds its byte bounds")
	}
	config, err := png.DecodeConfig(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("root package workspace image has invalid PNG metadata")
	}
	// Dimensions bound allocation independently of the compressed byte count.
	if config.Width < 1 || config.Width > maxWorkspaceImageWidth || config.Height < 1 || config.Height > maxWorkspaceImageHeight {
		return fmt.Errorf("root package workspace image exceeds its dimension bounds")
	}
	if _, err := png.Decode(bytes.NewReader(content)); err != nil {
		return fmt.Errorf("root package workspace image is not a complete PNG")
	}
	return nil
}
