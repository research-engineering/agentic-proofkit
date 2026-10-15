package workflowsmoke

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var (
	trajectoryRouteToken     = regexp.MustCompile(`\A[a-z][a-z0-9-]*\z`)
	trajectoryBootstrapRoute = regexp.MustCompile(`Run ([a-z][a-z0-9-]*) --repo-root <repository>`)
)

// trajectory carries one agent session. Its route ledger enforces the
// CLI-contained prompt invariant: every executed route, including each
// --help request, was named earlier by an actual CLI output of this session.
type trajectory struct {
	ctx    context.Context
	run    Runner
	root   string
	prefix string
	named  map[string]string
	trail  []string
}

func newTrajectory(ctx context.Context, run Runner, root string) *trajectory {
	// The install-time bootstrap generator is the only route assumed to exist.
	return &trajectory{ctx: ctx, run: run, root: root, named: map[string]string{"integration source": "install"}}
}

func trajectoryRoute(args []string) string {
	if len(args) >= 2 && args[0] == "--json-layout" {
		args = args[2:]
	}
	tokens := []string{}
	for _, token := range args {
		if !trajectoryRouteToken.MatchString(token) {
			break
		}
		tokens = append(tokens, token)
	}
	return strings.Join(tokens, " ")
}

func (t *trajectory) name(label string, route []string) {
	key := strings.Join(route, " ")
	if _, exists := t.named[key]; !exists && key != "" {
		t.named[key] = label
	}
}

// commandLines returns every route printed as an installed launcher command.
func (t *trajectory) commandLines(text []byte) []string {
	routes := []string{}
	for _, line := range strings.Split(string(text), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimLeft(line, " "), t.prefix+" ")
		if !ok || t.prefix == "" {
			continue
		}
		if route := trajectoryRoute(strings.Fields(rest)); route != "" {
			routes = append(routes, route)
		}
	}
	return routes
}

func (t *trajectory) observe(label string, text []byte) {
	for _, route := range t.commandLines(text) {
		t.name(label, strings.Fields(route))
	}
}

// requireNames proves that this exact output names each route, independently
// of which earlier output named it first.
func (t *trajectory) requireNames(label string, text []byte, routes ...string) error {
	printed := t.commandLines(text)
	for _, route := range routes {
		if !slices.Contains(printed, route) {
			return fmt.Errorf("%s does not name the next route %q", label, route)
		}
	}
	return nil
}

func (t *trajectory) call(label string, invocation Invocation) (Result, error) {
	route := trajectoryRoute(invocation.Args)
	if _, ok := t.named[route]; !ok {
		return Result{}, fmt.Errorf("%s: route %q was not named by an earlier CLI output", label, route)
	}
	invocationContext, cancel := context.WithTimeout(t.ctx, invocationTimeout)
	defer cancel()
	result, err := t.run(invocationContext, invocation)
	if err != nil {
		return Result{}, fmt.Errorf("%s carrier invocation: %w", label, err)
	}
	t.trail = append(t.trail, label)
	return result, nil
}

// help reads a named route's help and records the routes it names.
func (t *trajectory) help(route ...string) ([]byte, error) {
	label := strings.Join(route, " ") + " --help"
	result, err := t.call(label, unreadInvocation(append(append([]string{}, route...), "--help")...))
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 || !bytes.HasPrefix(result.Stdout, []byte("Usage:\n")) || bytes.Contains(result.Stdout, []byte("\x1b[")) {
		return nil, fmt.Errorf("%s must emit plain help with exit 0", label)
	}
	_, invocation, ok := strings.Cut(string(result.Stdout), "\nInstalled invocation:\n  ")
	line, _, _ := strings.Cut(invocation, "\n")
	index := strings.LastIndex(line, " "+strings.Join(route, " "))
	if !ok || index <= 0 {
		return nil, fmt.Errorf("%s does not identify its installed carrier", label)
	}
	if t.prefix == "" {
		t.prefix = line[:index]
	} else if line[:index] != t.prefix {
		return nil, fmt.Errorf("%s names a different installed carrier", label)
	}
	t.observe(label, result.Stdout)
	return result.Stdout, nil
}

// object runs one JSON-report command with an exact exit and empty stderr.
func (t *trajectory) object(label string, invocation Invocation, wantExit int) (map[string]any, []byte, error) {
	result, err := t.call(label, invocation)
	if err != nil {
		return nil, nil, err
	}
	if result.ExitCode != wantExit || len(result.Stderr) != 0 {
		return nil, nil, fmt.Errorf("%s exit=%d stderr=%q, want exit %d and empty stderr", label, result.ExitCode, firstLine(result.Stderr), wantExit)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), maximumProcessOutputBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%s stdout is not one strict JSON value: %w", label, err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%s stdout must be a JSON object", label)
	}
	return record, result.Stdout, nil
}

// refuse proves an input-admission denial: exit 1, no stdout, safe diagnostic.
func (t *trajectory) refuse(label string, invocation Invocation, fragment string) error {
	result, err := t.call(label, invocation)
	if err != nil {
		return err
	}
	if result.ExitCode != 1 || len(result.Stdout) != 0 || bytes.Contains(result.Stderr, []byte("\x1b[")) || !bytes.Contains(result.Stderr, []byte(fragment)) {
		return fmt.Errorf("%s must be refused with exit 1, empty stdout and %q; got exit=%d stderr=%q", label, fragment, result.ExitCode, firstLine(result.Stderr))
	}
	return nil
}

func firstLine(value []byte) string {
	line, _, _ := bytes.Cut(value, []byte("\n"))
	if len(line) > 240 {
		line = line[:240]
	}
	return string(line)
}

// expect compares JSON-pointer facts by canonical JSON bytes.
func expect(label string, record any, facts map[string]any) error {
	pointers := make([]string, 0, len(facts))
	for pointer := range facts {
		pointers = append(pointers, pointer)
	}
	slices.Sort(pointers)
	for _, pointer := range pointers {
		actual, ok := pointerValue(record, pointer)
		if !ok {
			return fmt.Errorf("%s lacks %s", label, pointer)
		}
		if !sameJSON(actual, facts[pointer]) {
			return fmt.Errorf("%s %s = %s, want %s", label, pointer, canonicalText(actual), canonicalText(facts[pointer]))
		}
	}
	return nil
}

func pointerValue(value any, pointer string) (any, bool) {
	if pointer == "" {
		return value, true
	}
	for _, segment := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch typed := value.(type) {
		case map[string]any:
			next, ok := typed[segment]
			if !ok {
				return nil, false
			}
			value = next
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			value = typed[index]
		default:
			return nil, false
		}
	}
	return value, true
}

func sameJSON(left, right any) bool {
	leftBytes, leftErr := stablejson.Marshal(left)
	rightBytes, rightErr := stablejson.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func canonicalText(value any) string {
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		return "<non-canonical>"
	}
	text := strings.TrimSuffix(string(encoded), "\n")
	if len(text) > 400 {
		text = text[:400] + "..."
	}
	return text
}

func canonicalBytes(value any) ([]byte, error) {
	return stablejson.MarshalLayout(value, stablejson.LayoutCompact)
}

// guideTemplate extracts the single JSON block of one help guide.
func guideTemplate(label string, help []byte) (any, error) {
	sections := bytes.Split(help, []byte("```json\n"))
	if len(sections) != 2 {
		return nil, fmt.Errorf("%s must contain exactly one JSON template", label)
	}
	body, _, closed := bytes.Cut(sections[1], []byte("\n```"))
	if !closed {
		return nil, fmt.Errorf("%s template is not closed", label)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(body), defaultMaximumStdoutBytes)
	if err != nil {
		return nil, fmt.Errorf("%s template is not strict JSON: %w", label, err)
	}
	return value, nil
}

// sameKeys proves that an input uses exactly the object keys a CLI template
// teaches; values remain caller-owned facts.
func sameKeys(label string, template, input any) error {
	left, leftOK := template.(map[string]any)
	right, rightOK := input.(map[string]any)
	if !leftOK || !rightOK {
		return fmt.Errorf("%s template and input must both be objects", label)
	}
	leftKeys, rightKeys := sortedKeys(left), sortedKeys(right)
	if !slices.Equal(leftKeys, rightKeys) {
		return fmt.Errorf("%s keys %v differ from the CLI template keys %v", label, rightKeys, leftKeys)
	}
	return nil
}

func sortedKeys(record map[string]any) []string {
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func encodeInput(value any) ([]byte, error) {
	return stablejson.Marshal(value)
}

func writeTrajectoryFiles(root string, files map[string]string) error {
	for path, content := range files {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}
