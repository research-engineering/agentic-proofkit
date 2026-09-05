package agentintegration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
)

const maximumCheckBytes = 8 << 10

// CheckResult reports only generated-byte freshness, not host activation.
type CheckResult struct {
	document Document
	state    string
}

func (result CheckResult) State() string { return result.state }

func (result CheckResult) JSONValue() map[string]any {
	return map[string]any{
		"schemaVersion":         1,
		"kind":                  "proofkit.integration-check.v1",
		"tool":                  result.document.tool,
		"targetPath":            result.document.path,
		"integrationId":         result.document.identity,
		"expectedContentDigest": result.document.contentDigest,
		"state":                 result.state,
		"nonClaims":             checkNonClaims(),
	}
}

func (result CheckResult) Text() string {
	return fmt.Sprintf("Integration check: %s\nTool: %s\nTarget: %s\nCurrent means generated-byte freshness only; no installation, host activation, or post-return stability is proven.\n",
		result.state, result.document.tool, result.document.path)
}

func checkNonClaims() []any {
	return []any{
		"Current means exact generated-byte freshness only.",
		"No installation, update, removal, or host activation is performed or proven.",
		"No native verification or approved-launcher invocation is proven.",
		"Observed stability does not guarantee absence of mutations after return.",
	}
}

type checkDependencies struct {
	openFile   func(*repositorytransaction.InspectionLease, string) (repositorytransaction.InspectionFile, error)
	closeLease func(*repositorytransaction.InspectionLease) error
}

func nativeCheckDependencies() checkDependencies {
	return checkDependencies{
		openFile:   (*repositorytransaction.InspectionLease).OpenExactRegularFile,
		closeLease: (*repositorytransaction.InspectionLease).Close,
	}
}

// Check uses one read-only lease and two bounded observations of the selected
// descriptor-owned path. Neither operation authorizes filesystem mutation.
func Check(ctx context.Context, repositoryRoot string, document Document) (CheckResult, error) {
	return checkWithDependencies(ctx, repositoryRoot, document, nativeCheckDependencies())
}

func checkWithDependencies(ctx context.Context, repositoryRoot string, document Document, dependencies checkDependencies) (result CheckResult, returnErr error) {
	if ctx == nil {
		return CheckResult{}, checkOperationError("context is required")
	}
	// Cancellation and cleanup participate in every outcome, including errors.
	defer func() {
		if err := ctx.Err(); err != nil && !errors.Is(returnErr, err) {
			returnErr = errors.Join(returnErr, fmt.Errorf("integration check operation cancelled: %w", err))
		}
		if returnErr != nil {
			result = CheckResult{}
		}
	}()
	if ctx.Err() != nil {
		return CheckResult{}, nil
	}
	if document.tool == "" || document.path == "" || document.content == "" || document.identity == "" || document.contentDigest == "" || document.capabilityDigest == "" {
		return CheckResult{}, checkOperationError("source document is required")
	}
	if dependencies.openFile == nil || dependencies.closeLease == nil {
		return CheckResult{}, checkOperationError("inspection dependencies are incomplete")
	}
	lease, err := repositorytransaction.OpenInspectionLease(ctx, repositoryRoot)
	if err != nil {
		if errors.Is(err, repositorytransaction.ErrReadCleanup) || errors.Is(err, rootpath.ErrTraversalCleanup) {
			return CheckResult{}, checkCleanupError("open repository inspection lease")
		}
		return CheckResult{}, checkOperationError("open repository inspection lease")
	}
	defer func() {
		if err := dependencies.closeLease(lease); err != nil {
			returnErr = errors.Join(returnErr, checkCleanupError("close inspection lease"))
		}
	}()
	before, err := observeCheckFile(ctx, lease, document, dependencies.openFile)
	if err != nil {
		return CheckResult{}, err
	}
	after, err := observeCheckFile(ctx, lease, document, dependencies.openFile)
	if err != nil {
		return CheckResult{}, err
	}
	if !sameCheckObservation(before, after) {
		return CheckResult{}, checkOperationError("selected file changed during inspection")
	}
	if err := lease.VerifyRootIdentity(); err != nil {
		return CheckResult{}, checkOperationError("repository root changed during inspection")
	}
	return CheckResult{document: document, state: after.state}, nil
}

func checkOperationError(operation string) error {
	return fmt.Errorf("integration check operation failed: %s", operation)
}

func checkCleanupError(operation string) error {
	return fmt.Errorf("integration check operation failed: %s: %w", operation, repositorytransaction.ErrReadCleanup)
}

type checkObservation struct {
	state   string
	content []byte
	info    fs.FileInfo
}

func observeCheckFile(ctx context.Context, lease *repositorytransaction.InspectionLease, document Document, openFile func(*repositorytransaction.InspectionLease, string) (repositorytransaction.InspectionFile, error)) (observation checkObservation, returnErr error) {
	if err := ctx.Err(); err != nil {
		return checkObservation{}, fmt.Errorf("integration check operation cancelled: %w", err)
	}
	file, err := openFile(lease, document.path)
	switch {
	case errors.Is(err, repositorytransaction.ErrReadCleanup), errors.Is(err, rootpath.ErrTraversalCleanup):
		return checkObservation{}, checkCleanupError("open selected file")
	case errors.Is(err, repositorytransaction.ErrInspectionRouteChanged), errors.Is(err, rootpath.ErrAmbiguousRoute),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, fs.ErrPermission):
		return checkObservation{}, checkOperationError("open selected file")
	case errors.Is(err, fs.ErrNotExist):
		return checkObservation{state: "missing"}, nil
	case errors.Is(err, repositorytransaction.ErrUnsafeInspectionRoute):
		return checkObservation{state: "invalid"}, nil
	case err != nil:
		return checkObservation{}, checkOperationError("open selected file")
	}
	defer func() {
		if err := file.Close(); err != nil {
			observation = checkObservation{}
			returnErr = errors.Join(returnErr, checkCleanupError("close selected file"))
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return checkObservation{}, checkOperationError("inspect selected file")
	}
	if !opened.Mode().IsRegular() {
		return checkObservation{state: "invalid", info: opened}, nil
	}
	// Oversized files remain invalid, but their bounded prefix participates in
	// reobservation too. Never read more than the admitted 8 KiB per observation.
	content, err := io.ReadAll(io.LimitReader(file, maximumCheckBytes))
	if err != nil {
		return checkObservation{}, checkOperationError("read selected file")
	}
	after, err := file.Stat()
	if err != nil {
		return checkObservation{}, checkOperationError("reinspect selected file")
	}
	if !sameCheckFile(opened, after) || int64(len(content)) != min(opened.Size(), maximumCheckBytes) {
		return checkObservation{}, checkOperationError("selected file changed while reading")
	}
	state := "stale"
	switch {
	case opened.Size() > maximumCheckBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0:
		state = "invalid"
	case string(content) == document.content:
		state = "current"
	}
	return checkObservation{state: state, content: content, info: opened}, nil
}

func sameCheckObservation(before, after checkObservation) bool {
	if before.state != after.state || !bytes.Equal(before.content, after.content) {
		return false
	}
	if before.info == nil || after.info == nil {
		return before.info == nil && after.info == nil
	}
	return sameCheckFile(before.info, after.info)
}

func sameCheckFile(before, after fs.FileInfo) bool {
	return os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}
