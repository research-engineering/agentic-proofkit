package repositorytransaction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
)

const maximumControlObservationBytes = MaximumAggregateBytes * 4

var (
	errControlObservationBound = errors.New("repository transaction control observation exceeds its bound")
	errControlObservationShape = errors.New("repository transaction control observation contains an unsupported shape")
)

type controlObservation struct {
	Digest  string
	Entries []fs.DirEntry
	Invalid bool
}

func observeControlNamespace(ctx context.Context, root *os.Root) (controlObservation, error) {
	entries, err := readInspectionEntries(root, ControlDirectory, 3)
	if err != nil {
		return controlObservation{}, err
	}
	remaining := int64(maximumControlObservationBytes)
	values := make([]any, 0, len(entries))
	invalid := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return controlObservation{}, fmt.Errorf("inspect repository transaction control state cancelled: %w", err)
		}
		value, entryInvalid, err := observeControlEntry(ctx, root, ControlDirectory, entry, true, &remaining)
		if err != nil {
			return controlObservation{}, err
		}
		invalid = invalid || entryInvalid
		values = append(values, value)
	}
	value := map[string]any{
		"controlObservationKind": "proofkit.repository-control-observation",
		"entries":                values,
		"schemaVersion":          json.Number("1"),
	}
	observationID, err := digest.StableJSONSHA256Ref(value)
	if err != nil {
		return controlObservation{}, fmt.Errorf("derive repository transaction control observation: %w", err)
	}
	return controlObservation{Digest: observationID, Entries: entries, Invalid: invalid}, nil
}

func observeControlEntry(ctx context.Context, root *os.Root, directory string, entry fs.DirEntry, descend bool, remaining *int64) (map[string]any, bool, error) {
	relativePath := directory + "/" + entry.Name()
	nameKey, err := pathidentity.Key(entry.Name())
	if err != nil {
		return nil, false, errControlObservationShape
	}
	info, err := root.Lstat(filepath.FromSlash(relativePath))
	if err != nil {
		return nil, false, fmt.Errorf("inspect repository transaction control entry")
	}
	entryKind := "other"
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		entryKind = "symlink"
	case info.IsDir():
		entryKind = "directory"
	case info.Mode().IsRegular():
		entryKind = "regular"
	}
	value := map[string]any{
		"kind":   entryKind,
		"nameId": digest.SHA256TextRef(nameKey),
	}
	invalid := false
	switch entryKind {
	case "regular":
		value["mode"] = json.Number(strconv.FormatUint(uint64(info.Mode().Perm()), 10))
		value["size"] = json.Number(strconv.FormatInt(info.Size(), 10))
		if info.Size() < 0 || info.Size() > MaximumFileBytes || info.Size() > *remaining {
			return nil, false, errControlObservationBound
		}
		contentID, err := inspectControlFileDigest(ctx, root, relativePath, info, min(MaximumFileBytes, *remaining))
		if err != nil {
			return nil, false, err
		}
		*remaining -= info.Size()
		value["contentId"] = contentID
	case "directory":
		if !descend {
			return nil, false, errControlObservationShape
		}
		value["mode"] = json.Number(strconv.FormatUint(uint64(info.Mode().Perm()), 10))
		limit := MaximumOperations*2 + MaximumOperations*pathidentity.MaximumComponents + 10
		children, err := readInspectionEntries(root, relativePath, limit)
		if err != nil {
			return nil, false, err
		}
		childValues := make([]any, 0, len(children))
		for _, child := range children {
			childValue, childInvalid, err := observeControlEntry(ctx, root, relativePath, child, false, remaining)
			if err != nil {
				return nil, false, err
			}
			invalid = invalid || childInvalid
			childValues = append(childValues, childValue)
		}
		value["entries"] = childValues
	case "symlink":
		target, err := root.Readlink(filepath.FromSlash(relativePath))
		if err != nil {
			return nil, false, ErrControlStateChanged
		}
		current, err := root.Lstat(filepath.FromSlash(relativePath))
		if err != nil || current.Mode()&os.ModeSymlink == 0 || !os.SameFile(info, current) || current.Size() != info.Size() {
			return nil, false, ErrControlStateChanged
		}
		value["targetId"] = digest.SHA256TextRef(target)
		invalid = true
	default:
		return nil, false, errControlObservationShape
	}
	return value, invalid, nil
}

func readInspectionEntries(root *os.Root, relativePath string, maximum int) (entries []fs.DirEntry, returnErr error) {
	directory, err := root.Open(filepath.FromSlash(relativePath))
	if err != nil {
		return nil, fmt.Errorf("open repository transaction control directory")
	}
	defer func() {
		if closeErr := closeReadResource(directory, "control directory"); closeErr != nil {
			entries = nil
			returnErr = closeErr
		}
	}()
	entries, err = directory.ReadDir(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read repository transaction control directory")
	}
	if len(entries) > maximum {
		return nil, errControlObservationBound
	}
	if err := sortInspectionEntries(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func sortInspectionEntries(entries []fs.DirEntry) error {
	keys := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, err := pathidentity.Key(entry.Name())
		if err != nil {
			return errControlObservationShape
		}
		keys[entry.Name()] = key
	}
	sort.Slice(entries, func(left, right int) bool { return keys[entries[left].Name()] < keys[entries[right].Name()] })
	for index := 1; index < len(entries); index++ {
		if keys[entries[index-1].Name()] == keys[entries[index].Name()] {
			return errControlObservationShape
		}
	}
	return nil
}

func inspectControlFileDigest(ctx context.Context, root *os.Root, relativePath string, routeInfo fs.FileInfo, maximum int64) (string, error) {
	return inspectControlFileDigestWithHook(ctx, root, relativePath, routeInfo, maximum, nil)
}

func inspectControlFileDigestWithHook(ctx context.Context, root *os.Root, relativePath string, routeInfo fs.FileInfo, maximum int64, beforeRouteRecheck func()) (contentID string, returnErr error) {
	if maximum < 0 || routeInfo.Size() < 0 || routeInfo.Size() > maximum {
		return "", fmt.Errorf("repository transaction control file exceeds its read bound")
	}
	file, err := openNoFollow(root, filepath.FromSlash(relativePath))
	if err != nil {
		return "", fmt.Errorf("open repository transaction control file")
	}
	defer func() {
		if closeErr := closeReadResource(file, "control file"); closeErr != nil {
			contentID = ""
			returnErr = closeErr
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(routeInfo, opened) || opened.Size() != routeInfo.Size() || opened.Size() > maximum {
		return "", ErrControlStateChanged
	}
	content := make([]byte, 0, opened.Size())
	buffer := make([]byte, 32<<10)
	limited := io.LimitReader(file, maximum+1)
	for int64(len(content)) <= maximum {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("inspect repository transaction control state cancelled: %w", err)
		}
		count, readErr := limited.Read(buffer)
		if count > 0 {
			content = append(content, buffer[:count]...)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("read repository transaction control file")
		}
	}
	if int64(len(content)) > maximum {
		return "", ErrControlStateChanged
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(content)) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return "", ErrControlStateChanged
	}
	if beforeRouteRecheck != nil {
		beforeRouteRecheck()
	}
	current, err := root.Lstat(filepath.FromSlash(relativePath))
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) || current.Size() != int64(len(content)) {
		return "", ErrControlStateChanged
	}
	return digest.SHA256BytesRef(content), nil
}
