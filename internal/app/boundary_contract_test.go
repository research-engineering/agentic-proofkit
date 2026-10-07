package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// These observations come from the exact predecessor 245af62, before the
// structural declarations existed. Never update them from the current builder.
func TestBoundaryCLIHistoricalWireAndTransports(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "boundary-native-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := admission.DecodeTypedJSON[[]struct {
		Command  string          `json:"command"`
		Case     string          `json:"case"`
		Input    json.RawMessage `json:"input"`
		Output   json.RawMessage `json:"output"`
		ExitCode int             `json:"exitCode"`
		Stderr   string          `json:"stderr"`
	}](bytes.NewReader(data), maxInputBytes)
	if err != nil || len(rows) != 18 {
		t.Fatalf("invalid predecessor corpus: rows=%d error=%v", len(rows), err)
	}
	for _, row := range rows {
		t.Run(row.Command+"/"+row.Case, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, row.Input, 0600); err != nil {
				t.Fatal(err)
			}
			for _, transport := range []struct {
				name, input string
				args        []string
			}{
				{"stdin", string(row.Input), []string{"--input", "-"}},
				{"file", "", []string{"--input", path}},
				{"pointer", `{"payload":` + string(row.Input) + `}`, []string{"--input", "-", "--input-pointer", "/payload"}},
			} {
				t.Run(transport.name, func(t *testing.T) {
					var stdout, stderr bytes.Buffer
					code := Run(t.Context(), append([]string{row.Command}, transport.args...), strings.NewReader(transport.input), &stdout, &stderr)
					if code != row.ExitCode || stderr.String() != row.Stderr {
						t.Fatalf("CLI result changed: exit=%d stderr=%q", code, stderr.String())
					}
					if row.Stderr != "" {
						if stdout.Len() != 0 {
							t.Fatal("admission failure emitted a report")
						}
						return
					}
					canonical := func(raw []byte) []byte {
						value, err := admission.DecodeJSON(bytes.NewReader(raw), maxInputBytes)
						if err != nil {
							t.Fatal(err)
						}
						encoded, err := stablejson.Marshal(value)
						if err != nil {
							t.Fatal(err)
						}
						return encoded
					}
					if !bytes.Equal(canonical(stdout.Bytes()), canonical(row.Output)) {
						t.Fatal("native report differs from the frozen predecessor")
					}
				})
			}
		})
	}
}
