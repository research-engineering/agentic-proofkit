package repositoryinventory

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

type candidate struct {
	info os.FileInfo
	item catalogItem
}

type scanPolicy struct {
	maximumAggregateBytes int64
	maximumFileBytes      int64
	maximumRootEntries    int
}

type directoryEntryReader interface {
	ReadDir(int) ([]os.DirEntry, error)
}

type repositoryRootOpener func(string) (*os.Root, error)
type candidateContentReader func(*os.Root, candidate, int64, int64) ([]byte, error)

type rootInventory struct {
	catalogItems      []catalogItem
	rootEntryCount    int
	unrecognizedCount int
}

var defaultScanPolicy = scanPolicy{
	maximumAggregateBytes: MaximumAggregateBytes,
	maximumFileBytes:      MaximumFileBytes,
	maximumRootEntries:    MaximumRootEntries,
}

func Scan(ctx context.Context, repositoryRoot string) (Snapshot, error) {
	return scanForPlatform(ctx, repositoryRoot, runtime.GOOS, os.OpenRoot)
}

func scanForPlatform(ctx context.Context, repositoryRoot, goos string, openRoot repositoryRootOpener) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := requireScannerPlatform(goos); err != nil {
		return Snapshot{}, err
	}
	root, err := openRoot(repositoryRoot)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open repository root")
	}
	snapshot, scanErr := scanRoot(ctx, root, defaultScanPolicy)
	if closeErr := root.Close(); scanErr == nil && closeErr != nil {
		return Snapshot{}, fmt.Errorf("close repository root")
	}
	return snapshot, scanErr
}

func requireScannerPlatform(goos string) error {
	if goos != "darwin" && goos != "linux" {
		return fmt.Errorf("repository inventory scanning is unsupported on this platform")
	}
	return nil
}

func scanRoot(ctx context.Context, root *os.Root, policy scanPolicy) (Snapshot, error) {
	return scanRootWithCandidateReader(ctx, root, policy, readCandidate)
}

func scanRootWithCandidateReader(ctx context.Context, root *os.Root, policy scanPolicy, readContent candidateContentReader) (Snapshot, error) {
	directory, err := root.Open(".")
	if err != nil {
		return Snapshot{}, fmt.Errorf("open repository root directory")
	}
	inventory, readErr := readRootInventory(ctx, directory, policy.maximumRootEntries)
	closeErr := directory.Close()
	if readErr != nil {
		return Snapshot{}, readErr
	}
	if closeErr != nil {
		return Snapshot{}, fmt.Errorf("close repository root directory")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	candidates := make([]candidate, 0, len(inventory.catalogItems))
	omissions := Omissions{
		RootEntryCount:    inventory.rootEntryCount,
		UnrecognizedCount: inventory.unrecognizedCount,
	}
	preflightAggregateBytes := int64(0)
	for _, item := range inventory.catalogItems {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		info, err := root.Lstat(item.Path)
		if err != nil {
			return Snapshot{}, fmt.Errorf("inspect recognized repository entry")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return Snapshot{}, fmt.Errorf("recognized repository entry must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return Snapshot{}, fmt.Errorf("recognized repository entry must be a regular file")
		}
		if info.Size() > policy.maximumFileBytes {
			omissions.OmittedRecognized = append(omissions.OmittedRecognized, OmittedRecognizedEntry{Path: item.Path, Reason: OmissionOversize})
			continue
		}
		if info.Size() < 0 || preflightAggregateBytes > policy.maximumAggregateBytes-info.Size() {
			return Snapshot{}, fmt.Errorf("recognized repository entries exceed aggregate byte limit")
		}
		preflightAggregateBytes += info.Size()
		candidates = append(candidates, candidate{info: info, item: item})
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].item.Path < candidates[right].item.Path })

	observed := make([]Entry, 0, len(candidates))
	actualAggregateBytes := int64(0)
	for _, item := range candidates {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		content, err := readContent(root, item, policy.maximumFileBytes, policy.maximumAggregateBytes-actualAggregateBytes)
		if err != nil {
			return Snapshot{}, err
		}
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		actualAggregateBytes += int64(len(content))
		if !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
			omissions.OmittedRecognized = append(omissions.OmittedRecognized, OmittedRecognizedEntry{Path: item.item.Path, Reason: OmissionNonText})
			continue
		}
		observed = append(observed, Entry{
			ByteLength:    len(content),
			ContentSHA256: digest.SHA256BytesRef(content),
			Path:          item.item.Path,
			Role:          item.item.Role,
			SyntaxState:   "not_evaluated",
		})
	}
	sort.Slice(omissions.OmittedRecognized, func(left, right int) bool {
		return omissions.OmittedRecognized[left].Path < omissions.OmittedRecognized[right].Path
	})
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return finalize(Snapshot{Entries: observed, Omissions: omissions})
}

func readRootInventory(ctx context.Context, directory directoryEntryReader, maximum int) (rootInventory, error) {
	const batchLimit = 256
	result := rootInventory{catalogItems: make([]catalogItem, 0, len(rootCatalog))}
	seenCatalogPaths := make(map[string]struct{}, len(rootCatalog))
	for result.rootEntryCount <= maximum {
		if err := ctx.Err(); err != nil {
			return rootInventory{}, err
		}
		remaining := maximum + 1 - result.rootEntryCount
		if remaining > batchLimit {
			remaining = batchLimit
		}
		batch, err := directory.ReadDir(remaining)
		for _, entry := range batch {
			result.rootEntryCount++
			if result.rootEntryCount > maximum {
				return rootInventory{}, fmt.Errorf("repository root exceeds entry limit")
			}
			role, recognized := catalogRole(entry.Name())
			if !recognized {
				result.unrecognizedCount++
				continue
			}
			if _, duplicate := seenCatalogPaths[entry.Name()]; duplicate {
				return rootInventory{}, fmt.Errorf("repository root contains a duplicate catalog entry")
			}
			seenCatalogPaths[entry.Name()] = struct{}{}
			result.catalogItems = append(result.catalogItems, catalogItem{Path: entry.Name(), Role: role})
		}
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return rootInventory{}, fmt.Errorf("read repository root directory")
		}
		if len(batch) == 0 {
			return rootInventory{}, fmt.Errorf("read repository root directory made no progress")
		}
	}
	return rootInventory{}, fmt.Errorf("repository root exceeds entry limit")
}

func readCandidate(root *os.Root, value candidate, maximumFileBytes int64, maximumAggregateRemaining int64) (content []byte, returnErr error) {
	file, err := openCandidateFile(root, value.item.Path)
	if err != nil {
		return nil, fmt.Errorf("open recognized repository entry")
	}
	defer func() {
		if closeErr := file.Close(); returnErr == nil && closeErr != nil {
			content = nil
			returnErr = fmt.Errorf("close recognized repository entry")
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(value.info, opened) {
		return nil, fmt.Errorf("recognized repository entry changed before reading")
	}
	if opened.Size() < 0 || opened.Size() > maximumFileBytes {
		return nil, fmt.Errorf("recognized repository entry exceeds file byte limit")
	}
	if opened.Size() > maximumAggregateRemaining {
		return nil, fmt.Errorf("recognized repository entries exceed aggregate byte limit")
	}
	readLimit := maximumFileBytes
	if maximumAggregateRemaining < readLimit {
		readLimit = maximumAggregateRemaining
	}
	content, err = io.ReadAll(io.LimitReader(file, readLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read recognized repository entry within byte limit")
	}
	if int64(len(content)) > maximumFileBytes {
		return nil, fmt.Errorf("recognized repository entry exceeds file byte limit")
	}
	if int64(len(content)) > maximumAggregateRemaining {
		return nil, fmt.Errorf("recognized repository entries exceed aggregate byte limit")
	}
	afterHandle, err := file.Stat()
	if err != nil || !os.SameFile(opened, afterHandle) || afterHandle.Size() != int64(len(content)) {
		return nil, fmt.Errorf("recognized repository entry changed while reading")
	}
	afterPath, err := root.Lstat(value.item.Path)
	if err != nil || afterPath.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, afterPath) || afterPath.Size() != int64(len(content)) {
		return nil, fmt.Errorf("recognized repository entry changed after reading")
	}
	return content, nil
}
