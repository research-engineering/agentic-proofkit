package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

type frozenStreamObservation struct {
	corpus       string
	Name         string   `json:"name"`
	Argv         []string `json:"argv"`
	Args         []string `json:"args"`
	Input        *string  `json:"input"`
	InputJSON    *string  `json:"inputJSON"`
	ExitCode     int      `json:"exitCode"`
	StdoutSHA256 string   `json:"stdoutSHA256"`
	StderrSHA256 string   `json:"stderrSHA256"`
}

// frozenSyntaxStreamObservations returns every frozen predecessor stream
// whose input is a JSON syntax rejection, from every native observation corpus.
func frozenSyntaxStreamObservations(t *testing.T) []frozenStreamObservation {
	t.Helper()
	paths, err := filepath.Glob("testdata/*-native-observations.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("native observation corpora = %v, %v", paths, err)
	}
	var result []frozenStreamObservation
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var corpus struct {
			Observations []json.RawMessage `json:"observations"`
		}
		if json.Unmarshal(content, &corpus) != nil {
			// Array corpora record decoded inputs and outputs, not streams.
			continue
		}
		for _, raw := range corpus.Observations {
			var row frozenStreamObservation
			if json.Unmarshal(raw, &row) != nil {
				// Rows with structured input values are valid JSON by construction.
				continue
			}
			row.corpus = filepath.Base(path)
			if row.Argv == nil && row.InputJSON != nil {
				// The bootstrap corpus records self-check arguments after --input -.
				row.Argv = append([]string{"self-check", "--input", "-"}, row.Args...)
				row.Input = row.InputJSON
			}
			if row.StderrSHA256 == "" || row.Input == nil || !slices.Contains(row.Argv, "-") {
				continue
			}
			if _, err := admission.DecodeJSON(strings.NewReader(*row.Input), maxInputBytes); errors.As(err, new(*admission.SyntaxError)) {
				result = append(result, row)
			}
		}
	}
	return result
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// Owners whose frozen corpora pin exact predecessor streams keep them byte for
// byte; the property set is exactly the commands those corpora pin.
func TestPredecessorStreamOwnersReplayFrozenSyntaxStreams(t *testing.T) {
	rows := frozenSyntaxStreamObservations(t)
	pinned := map[string]struct{}{}
	for _, row := range rows {
		pinned[row.Argv[0]] = struct{}{}
		var stdout, stderr bytes.Buffer
		status := Run(t.Context(), row.Argv, strings.NewReader(*row.Input), &stdout, &stderr)
		if status != row.ExitCode || sha256Hex(stdout.Bytes()) != row.StdoutSHA256 || sha256Hex(stderr.Bytes()) != row.StderrSHA256 {
			t.Fatalf("%s/%s = %d %q %q, want the frozen predecessor stream", row.corpus, row.Name, status, stdout.String(), stderr.String())
		}
	}
	var owners []string
	for _, descriptor := range commandDescriptors {
		if descriptor.preservesPredecessorStreams {
			owners = append(owners, descriptor.name)
			if descriptor.runner != commandRunnerGenericInput {
				t.Fatalf("%s preserves predecessor streams outside the generic input runner", descriptor.name)
			}
		}
	}
	want := make([]string, 0, len(pinned))
	for command := range pinned {
		want = append(want, command)
	}
	sort.Strings(want)
	sort.Strings(owners)
	if len(rows) != 13 || !slices.Equal(owners, want) {
		t.Fatalf("rows=%d owners=%v, want 13 frozen rows and owners %v", len(rows), owners, want)
	}
}

// Every other --input command reports the position; exit code and stdout of
// the rejection are unchanged, and the message prefix is the kernel text.
func TestInputSyntaxRejectionReportsLocationOutsidePredecessorOwners(t *testing.T) {
	cases := []struct{ input, message, location string }{
		{`{"x":1,"x":2}`, "invalid JSON input: duplicate object key", " at line 1, column 8 (byte offset 7)"},
		{`{"x":{"a":1,"a":2}}`, "invalid JSON input: duplicate object key", " at line 1, column 13 (byte offset 12)"},
		{"{} {}", "invalid JSON input: multiple JSON values", " at line 1, column 4 (byte offset 3)"},
		{"{", "invalid JSON input: unterminated object", " at line 1, column 2 (byte offset 1)"},
		{"", "invalid JSON input: unexpected end", " at line 1, column 1 (byte offset 0)"},
		{"{\n  \"\u00e9\u20ac\U0001F600\": [1 2]\n}", "invalid JSON input: array values must be separated by comma", " at line 2, column 13 (byte offset 20)"},
	}
	// A generic-runner command and a dedicated-runner command.
	for _, command := range [][]string{{"requirement-source-admission"}, {"change", "plan"}} {
		for _, item := range cases {
			var stdout, stderr bytes.Buffer
			status := Run(t.Context(), append(slices.Clone(command), "--input", "-"), strings.NewReader(item.input), &stdout, &stderr)
			want := item.message + item.location + "\n"
			if status != 1 || stdout.Len() != 0 || stderr.String() != want {
				t.Fatalf("%v %q = %d %q %q, want 1 empty %q", command, item.input, status, stdout.String(), stderr.String(), want)
			}
		}
	}
}
