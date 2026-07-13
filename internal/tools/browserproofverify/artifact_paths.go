package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	browserArtifactsDirectory        = "artifacts"
	browserProofDirectory            = "artifacts/proofkit"
	browserProofCandidateName        = "browser-runtime-proof.candidate.json"
	browserRunDirectoryEnvironment   = "PROOFKIT_BROWSER_RUN_DIRECTORY"
	browserProofCandidateEnvironment = "PROOFKIT_BROWSER_PROOF_CANDIDATE_PATH"
)

type browserProofRunPaths struct {
	CandidatePath string
	RunDirectory  string
}

func prepareBrowserProofRun(root string) (browserProofRunPaths, error) {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return browserProofRunPaths{}, fmt.Errorf("open browser proof repository root: %w", err)
	}
	defer rootFS.Close()
	if err := ensureRootedDirectory(rootFS, browserArtifactsDirectory, 0o755); err != nil {
		return browserProofRunPaths{}, err
	}
	if err := ensureRootedDirectory(rootFS, browserProofDirectory, 0o755); err != nil {
		return browserProofRunPaths{}, err
	}
	if err := admitRootedDestination(rootFS, proofPath); err != nil {
		return browserProofRunPaths{}, err
	}
	for attempt := 0; attempt < 16; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return browserProofRunPaths{}, fmt.Errorf("create browser proof run nonce: %w", err)
		}
		runDirectory := filepath.Join(browserArtifactsDirectory, "browser-run-"+hex.EncodeToString(nonce[:]))
		if err := rootFS.Mkdir(runDirectory, 0o700); errors.Is(err, fs.ErrExist) {
			continue
		} else if err != nil {
			return browserProofRunPaths{}, fmt.Errorf("create confined browser proof run directory: %w", err)
		}
		return browserProofRunPaths{
			CandidatePath: filepath.ToSlash(filepath.Join(runDirectory, browserProofCandidateName)),
			RunDirectory:  filepath.ToSlash(runDirectory),
		}, nil
	}
	return browserProofRunPaths{}, fmt.Errorf("create browser proof run directory: exhausted collision budget")
}

func cleanupBrowserProofRun(root, runDirectory string) error {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootFS.Close()
	return rootFS.RemoveAll(filepath.FromSlash(runDirectory))
}

func readRootedJSON(root, path string, maxBytes int64) (any, error) {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer rootFS.Close()
	localPath := filepath.FromSlash(path)
	if err := admitRootedRegularFile(rootFS, localPath); err != nil {
		return nil, err
	}
	file, err := rootFS.Open(localPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return admission.DecodeJSON(file, maxBytes)
}

func writeRootedJSON(root, path string, value any) error {
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutPretty)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootFS.Close()
	localPath := filepath.FromSlash(path)
	if err := ensureRootedDirectory(rootFS, filepath.Dir(localPath), 0o755); err != nil {
		return err
	}
	if err := admitRootedDestination(rootFS, localPath); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporaryPath := localPath + "." + hex.EncodeToString(nonce[:]) + ".tmp"
	temporary, err := rootFS.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = rootFS.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := rootFS.Rename(temporaryPath, localPath); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func ensureRootedDirectory(rootFS *os.Root, path string, mode fs.FileMode) error {
	cleanPath := filepath.Clean(path)
	if cleanPath == "." || !filepath.IsLocal(cleanPath) {
		return fmt.Errorf("browser proof artifact directory must stay repository-relative")
	}
	current := ""
	for _, part := range strings.Split(cleanPath, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := rootFS.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := rootFS.Mkdir(current, mode); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("browser proof artifact directory traverses a symlink or non-directory")
		}
	}
	return nil
}

func admitRootedDestination(rootFS *os.Root, path string) error {
	info, err := rootFS.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("browser proof artifact destination must be a regular non-symlink file")
	}
	return nil
}

func admitRootedRegularFile(rootFS *os.Root, path string) error {
	cleanPath := filepath.Clean(path)
	if cleanPath == "." || !filepath.IsLocal(cleanPath) {
		return fmt.Errorf("browser proof artifact path must stay repository-relative")
	}
	current := ""
	parts := strings.Split(cleanPath, string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := rootFS.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("browser proof artifact path traverses a symlink")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("browser proof artifact path traverses a non-directory")
		}
		if index == len(parts)-1 && !info.Mode().IsRegular() {
			return fmt.Errorf("browser proof artifact must be a regular file")
		}
	}
	return nil
}
