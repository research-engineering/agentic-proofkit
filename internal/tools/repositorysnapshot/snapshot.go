package repositorysnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxSnapshotFiles   = 20_000
	maxSnapshotBytes   = 512 << 20
	maxSourceFileBytes = 64 << 20
)

type Snapshot struct {
	Digest   string
	Paths    []string
	Revision string
}

func Capture(root string) (Snapshot, error) {
	return CaptureContext(context.Background(), root)
}

func CaptureContext(ctx context.Context, root string) (Snapshot, error) {
	paths, err := gitPaths(ctx, root)
	if err != nil {
		return Snapshot{}, err
	}
	digest, err := digestPaths(ctx, root, paths)
	if err != nil {
		return Snapshot{}, err
	}
	revision, err := sourceRevision(ctx, root, digest)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Digest: digest, Paths: append([]string(nil), paths...), Revision: revision}, nil
}

func Materialize(root, destination string) (Snapshot, error) {
	return MaterializeContext(context.Background(), root, destination)
}

func MaterializeContext(ctx context.Context, root, destination string) (Snapshot, error) {
	sourceRoot, err := os.OpenRoot(root)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open repository snapshot source failed")
	}
	defer sourceRoot.Close()
	destinationRoot, err := os.OpenRoot(destination)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open repository snapshot destination failed")
	}
	defer destinationRoot.Close()
	if err := admitEmptyDestination(root, destination, sourceRoot, destinationRoot); err != nil {
		return Snapshot{}, err
	}
	paths, err := gitPaths(ctx, root)
	if err != nil {
		return Snapshot{}, err
	}

	hash := sha256.New()
	totalBytes := int64(0)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, fmt.Errorf("repository snapshot operation canceled: %w", err)
		}
		normalized, err := normalizedPath(path)
		if err != nil {
			return Snapshot{}, err
		}
		info, content, err := readSourceFile(sourceRoot, normalized)
		if err != nil {
			return Snapshot{}, err
		}
		totalBytes += int64(len(content))
		if totalBytes > maxSnapshotBytes {
			return Snapshot{}, fmt.Errorf("repository snapshot exceeds total byte limit")
		}
		if err := destinationRoot.MkdirAll(filepath.Dir(filepath.FromSlash(normalized)), 0o755); err != nil {
			return Snapshot{}, fmt.Errorf("create materialized snapshot directory failed")
		}
		file, err := destinationRoot.OpenFile(filepath.FromSlash(normalized), os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			return Snapshot{}, fmt.Errorf("create materialized snapshot file failed")
		}
		if _, err := file.Write(content); err != nil {
			file.Close()
			return Snapshot{}, fmt.Errorf("write materialized snapshot file failed")
		}
		if err := file.Chmod(info.Mode().Perm()); err != nil {
			file.Close()
			return Snapshot{}, fmt.Errorf("set materialized snapshot file mode failed")
		}
		if err := file.Close(); err != nil {
			return Snapshot{}, fmt.Errorf("close materialized snapshot file failed")
		}
		writeDigestField(hash, []byte(normalized))
		writeDigestField(hash, []byte("regular"))
		writeDigestField(hash, []byte(normalizedMode(info.Mode())))
		writeDigestField(hash, content)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	revision, err := sourceRevision(ctx, root, digest)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Digest: digest, Paths: append([]string(nil), paths...), Revision: revision}, nil
}

func ValidateMaterialized(root string, snapshot Snapshot) error {
	return ValidateMaterializedContext(context.Background(), root, snapshot)
}

func ValidateMaterializedContext(ctx context.Context, root string, snapshot Snapshot) error {
	if len(snapshot.Paths) == 0 || !isSHA256(snapshot.Digest) || !ValidRevision(snapshot.Revision) {
		return fmt.Errorf("repository snapshot identity is incomplete")
	}
	paths, err := materializedPaths(ctx, root)
	if err != nil {
		return err
	}
	if !equalStrings(paths, snapshot.Paths) {
		return fmt.Errorf("materialized repository snapshot inventory is stale")
	}
	digest, err := digestPaths(ctx, root, snapshot.Paths)
	if err != nil {
		return err
	}
	if digest != snapshot.Digest {
		return fmt.Errorf("materialized repository snapshot digest is stale")
	}
	return nil
}

func ValidRevision(value string) bool {
	const dirtySeparator = "+worktree.sha256:"
	parts := strings.Split(value, dirtySeparator)
	if len(parts) > 2 || !isGitObjectID(parts[0]) {
		return false
	}
	return len(parts) == 1 || isSHA256(parts[1])
}

func isGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func EqualIdentity(left, right Snapshot) bool {
	return left.Revision == right.Revision && left.Digest == right.Digest && equalStrings(left.Paths, right.Paths)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
