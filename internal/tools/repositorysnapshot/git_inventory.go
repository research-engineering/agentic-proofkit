package repositorysnapshot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	command := exec.Command("git", args...)
	command.Dir = root
	stdout := newBoundedBuffer()
	stderr := newBoundedBuffer()
	out, err := command.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("git stdout pipe failed")
	}
	defer out.Close()
	defer command.Stdout.(*os.File).Close()
	errout, err := command.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("git stderr pipe failed")
	}
	defer errout.Close()
	defer command.Stderr.(*os.File).Close()
	child, err := processgroup.Start(ctx, command)
	if err != nil {
		return "", fmt.Errorf("git %s failed to start", strings.Join(args, " "))
	}
	outDone, errDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := io.Copy(stdout, out); outDone <- err }()
	go func() { _, err := io.Copy(stderr, errout); errDone <- err }()
	var streamErr error
	record := func(err error) {
		if err != nil {
			streamErr = errors.Join(streamErr, errors.New("git stream observation failed"))
			_ = child.Abort()
		}
	}
	stdoutExceeded := stdout.Exceeded()
	stderrExceeded := stderr.Exceeded()
	terminal, abort := child.Terminal(), child.Aborted()
	terminalSeen, aborted := false, false
	var timer *time.Timer
	var deadline <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	outClosed, erroutClosed := false, false
	closeOutput := func() {
		if !outClosed {
			outClosed = true
			record(out.Close())
		}
		if !erroutClosed {
			erroutClosed = true
			record(errout.Close())
		}
	}
	for outDone != nil || errDone != nil || (!terminalSeen && !aborted) {
		select {
		case err := <-outDone:
			outDone = nil
			if !(aborted && errors.Is(err, os.ErrClosed)) {
				record(err)
			}
		case err := <-errDone:
			errDone = nil
			if !(aborted && errors.Is(err, os.ErrClosed)) {
				record(err)
			}
		case <-terminal:
			terminalSeen, terminal = true, nil
			if !aborted {
				timer = time.NewTimer(processWaitDelay)
				deadline = timer.C
			}
		case <-stdoutExceeded:
			stdoutExceeded = nil
			_ = child.Abort()
		case <-stderrExceeded:
			stderrExceeded = nil
			_ = child.Abort()
		case <-abort:
			aborted, abort = true, nil
			if timer != nil {
				timer.Stop()
			}
			deadline = nil
			closeOutput()
		case <-deadline:
			deadline = nil
			if outDone != nil {
				select {
				case err := <-outDone:
					outDone = nil
					record(err)
				default:
				}
			}
			if errDone != nil {
				select {
				case err := <-errDone:
					errDone = nil
					record(err)
				default:
				}
			}
			if outDone != nil || errDone != nil {
				record(exec.ErrWaitDelay)
			}
		}
		if stdout.Overflowed() || stderr.Overflowed() {
			_ = child.Abort()
		}
	}
	closeOutput()
	waitErr, cleanupErr := child.Finish(processWaitDelay)
	outputOverflowed := stdout.Overflowed() || stderr.Overflowed()
	if cleanupErr != nil {
		switch {
		case ctx.Err() != nil:
			return "", fmt.Errorf("repository snapshot operation canceled and process cleanup failed: %w", errors.Join(ctx.Err(), cleanupErr))
		case outputOverflowed:
			return "", fmt.Errorf("git output exceeds resource limit and process cleanup failed: %w", cleanupErr)
		default:
			return "", fmt.Errorf("git process cleanup failed: %w", cleanupErr)
		}
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("repository snapshot operation canceled: %w", ctx.Err())
	}
	if outputOverflowed {
		return "", fmt.Errorf("git output exceeds resource limit")
	}
	if waitErr != nil {
		return "", fmt.Errorf("git %s failed", strings.Join(args, " "))
	}
	if streamErr != nil {
		return "", streamErr
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
