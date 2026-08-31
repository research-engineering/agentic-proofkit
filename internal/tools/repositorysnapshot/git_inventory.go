package repositorysnapshot

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/processgroup"
)

const (
	maxGitOutputBytes = 16 << 20
	processWaitDelay  = 5 * time.Second
)

func gitPaths(ctx context.Context, root string) ([]string, error) {
	paths, err := gitNullPaths(ctx, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	deleted, err := gitNullPaths(ctx, root, "ls-files", "-z", "--deleted")
	if err != nil {
		return nil, err
	}
	deletedSet := make(map[string]struct{}, len(deleted))
	for _, path := range deleted {
		deletedSet[path] = struct{}{}
	}
	current := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, removed := deletedSet[path]; !removed {
			current = append(current, path)
		}
	}
	sort.Strings(current)
	if len(current) == 0 {
		return nil, fmt.Errorf("repository snapshot source inventory is empty")
	}
	if len(current) > maxSnapshotFiles {
		return nil, fmt.Errorf("repository snapshot exceeds file-count limit")
	}
	for index := 1; index < len(current); index++ {
		if current[index] == current[index-1] {
			return nil, fmt.Errorf("repository snapshot contains duplicate path")
		}
	}
	return current, nil
}

func gitNullPaths(ctx context.Context, root string, args ...string) ([]string, error) {
	output, err := gitOutput(ctx, root, args...)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(output, "\x00")
	paths := make([]string, 0, len(parts))
	for _, path := range parts {
		if path == "" {
			continue
		}
		normalized, err := normalizedPath(filepath.ToSlash(path))
		if err != nil {
			return nil, err
		}
		paths = append(paths, normalized)
	}
	return paths, nil
}

func sourceRevision(ctx context.Context, root, digest string) (string, error) {
	head, err := gitOutput(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	status, err := gitOutput(ctx, root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", err
	}
	revision := strings.TrimSpace(head)
	if !isGitObjectID(revision) {
		return "", fmt.Errorf("git revision identity is invalid")
	}
	if strings.TrimSpace(status) != "" {
		revision += "+worktree.sha256:" + digest
	}
	return revision, nil
}

func gitOutput(ctx context.Context, root string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = root
	command.WaitDelay = processWaitDelay
	processgroup.Configure(command)
	stdout := newBoundedBuffer()
	stderr := newBoundedBuffer()
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return "", fmt.Errorf("git %s failed to start", strings.Join(args, " "))
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	var waitErr error
	overflowed := false
	stdoutExceeded := stdout.Exceeded()
	stderrExceeded := stderr.Exceeded()
	contextDone := ctx.Done()
	waitComplete := false
	for !waitComplete {
		select {
		case waitErr = <-waitDone:
			waitComplete = true
		case <-stdoutExceeded:
			overflowed = true
			stdoutExceeded = nil
			_ = processgroup.Terminate(command)
		case <-stderrExceeded:
			overflowed = true
			stderrExceeded = nil
			_ = processgroup.Terminate(command)
		case <-contextDone:
			contextDone = nil
			_ = processgroup.Terminate(command)
		}
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("repository snapshot operation canceled: %w", ctx.Err())
	}
	if overflowed || stdout.Overflowed() || stderr.Overflowed() {
		return "", fmt.Errorf("git output exceeds resource limit")
	}
	if waitErr != nil {
		return "", fmt.Errorf("git %s failed", strings.Join(args, " "))
	}
	if len(stderr.content) != 0 {
		return "", fmt.Errorf("git %s emitted diagnostics", strings.Join(args, " "))
	}
	return string(stdout.content), nil
}

type boundedBuffer struct {
	content  []byte
	exceeded chan struct{}
	once     sync.Once
}

func newBoundedBuffer() *boundedBuffer {
	return &boundedBuffer{exceeded: make(chan struct{})}
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := maxGitOutputBytes - len(buffer.content)
	if remaining > 0 {
		count := len(value)
		if count > remaining {
			count = remaining
		}
		buffer.content = append(buffer.content, value[:count]...)
	}
	if len(value) > remaining {
		buffer.once.Do(func() { close(buffer.exceeded) })
	}
	return len(value), nil
}

func (buffer *boundedBuffer) Exceeded() <-chan struct{} { return buffer.exceeded }

func (buffer *boundedBuffer) Overflowed() bool {
	select {
	case <-buffer.exceeded:
		return true
	default:
		return false
	}
}
