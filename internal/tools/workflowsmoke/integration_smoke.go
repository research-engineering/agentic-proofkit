package workflowsmoke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/agentintegration"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

// The in-process reference binds carrier equivalence to the current app. The
// separate native owner tests prove content and filesystem semantics; this smoke
// does not promote equivalence to independent proof of those semantics.
func integrationReference(ctx context.Context, args ...string) Result {
	var stdout, stderr bytes.Buffer
	code := app.Run(ctx, args, integrationUnreadReader{}, &stdout, &stderr)
	return Result{ExitCode: code, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
}

type integrationUnreadReader struct{}

func (integrationUnreadReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("integration must not read stdin")
}

func verifyIntegrations(ctx context.Context, run Runner) (returnErr error) {
	root, err := os.MkdirTemp("", "proofkit-integration-smoke-")
	if err != nil {
		return fmt.Errorf("create isolated integration repository")
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(root)) }()
	for _, tool := range agentintegration.Tools() {
		var source map[string]any
		for _, format := range []string{"json", "text"} {
			args := []string{"integration", "source", "--tool", tool, "--format", format}
			expected := integrationReference(ctx, args...)
			actual, err := invoke(ctx, run, "integration source "+format, unreadInvocation(args...))
			if err != nil {
				return err
			}
			if expected.ExitCode != 0 || len(expected.Stderr) != 0 || !bytes.Equal(actual.Stdout, expected.Stdout) {
				return fmt.Errorf("installed integration source differs from the current app")
			}
			if format == "json" {
				value, err := admission.DecodeJSON(bytes.NewReader(actual.Stdout), defaultMaximumStdoutBytes)
				if err != nil {
					return err
				}
				var ok bool
				source, ok = value.(map[string]any)
				if !ok {
					return fmt.Errorf("integration source must be an object")
				}
			}
		}
		if err := verifyIntegrationStates(ctx, run, root, tool, source); err != nil {
			return err
		}
		if err := verifyIntegrationLifecycle(ctx, run, tool, source); err != nil {
			return err
		}
	}
	return verifyFailure(ctx, run, "integration explicit tool", unreadInvocation("integration", "source"), "requires --tool")
}

func verifyIntegrationStates(ctx context.Context, run Runner, root, tool string, source map[string]any) error {
	content, contentOK := source["content"].(string)
	relative, pathOK := source["targetPath"].(string)
	if !contentOK || !pathOK || !filepath.IsLocal(relative) {
		return fmt.Errorf("integration source lacks its exact file projection")
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	for _, state := range []string{"missing", "current", "stale", "invalid"} {
		if state != "missing" {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			value := content
			if state == "stale" {
				value += "local edit\n"
			}
			if state == "invalid" {
				value = "\x00"
			}
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				return err
			}
		}
		before, err := integrationTree(root)
		if err != nil {
			return err
		}
		for _, format := range []string{"json", "text"} {
			args := []string{"integration", "check", "--tool", tool, "--repo-root", root, "--format", format}
			expected := integrationReference(ctx, args...)
			invocationContext, cancel := context.WithTimeout(ctx, invocationTimeout)
			actual, err := run(invocationContext, unreadInvocation(args...))
			cancel()
			if err != nil {
				return err
			}
			wantCode := 2
			if state == "current" {
				wantCode = 0
			}
			if expected.ExitCode != wantCode || actual.ExitCode != wantCode || len(expected.Stderr) != 0 || len(actual.Stderr) != 0 || !bytes.Equal(expected.Stdout, actual.Stdout) {
				return fmt.Errorf("installed integration check differs for %s/%s", state, format)
			}
		}
		after, err := integrationTree(root)
		if err != nil || !reflect.DeepEqual(before, after) {
			return fmt.Errorf("installed integration check changed repository entries")
		}
	}
	return nil
}

func integrationTree(root string) (map[string]string, error) {
	entries := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += ":" + digest.SHA256BytesRef(content)
		}
		entries[path] = value
		return nil
	})
	return entries, err
}
