package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestSpecTreeOutputContractsMatchNativeOwners(t *testing.T) {
	assertSourceStructure(t, "requirement-spec-tree", "output", "proofkit.requirement-spec-tree.output.v1.json-schema", requirementspectree.OutputStructure())
	assertSourceStructure(t, "requirement-spec-tree-view", "output", "proofkit.requirement-spec-tree-view.output.v2.json-schema", requirementspectree.ViewOutputStructure())
	for _, command := range readCLIContract(t).Commands {
		if command.Command != "requirement-spec-tree-view" {
			continue
		}
		output, ok := command.OutputContract.(map[string]any)
		if !ok {
			t.Fatal("spec tree JSON view output contract is absent")
		}
		selector, ok := output["nativeOutputWitnessSelector"].(map[string]any)
		if !ok {
			t.Fatal("spec tree JSON view output witness is absent")
		}
		valid := func(value map[string]any) bool {
			return len(value) == 4 &&
				value["path"] == "internal/command/requirementspectree/requirementspectree_test.go" &&
				value["test"] == "TestBuildViewJSONIsPermutationStable" &&
				value["command"] == "go test ./internal/command/requirementspectree -run '^TestBuildViewJSONIsPermutationStable$'" &&
				value["evidenceClass"] == "source_checkout"
		}
		if !valid(selector) {
			t.Fatal("spec tree JSON output must bind its direct native JSON witness")
		}
		previous := map[string]any{
			"path": selector["path"], "evidenceClass": selector["evidenceClass"],
			"test":    "TestBuildViewMarkdownAndHTMLAreDeterministicAndEscaped",
			"command": "go test ./internal/command/requirementspectree -run '^TestBuildViewMarkdownAndHTMLAreDeterministicAndEscaped$'",
		}
		if valid(previous) {
			t.Fatal("JSON witness oracle admitted the previous non-JSON selector")
		}
		return
	}
	t.Fatal("spec tree JSON view command is absent")
}

func TestSpecTreeCLIHistoricalWireAndTransports(t *testing.T) {
	data, err := os.ReadFile("testdata/spec-tree-native-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Case     string          `json:"case"`
		Kind     string          `json:"kind"`
		Input    json.RawMessage `json:"input"`
		Output   json.RawMessage `json:"output"`
		ExitCode int             `json:"exitCode"`
		Error    string          `json:"error"`
	}
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 8 {
		t.Fatalf("invalid pre-structure observation inventory: %v", err)
	}
	for _, row := range rows {
		t.Run(row.Kind+"/"+row.Case, func(t *testing.T) {
			command := "requirement-spec-tree"
			mode := []string{}
			if row.Kind == "view" {
				command = "requirement-spec-tree-view"
				mode = []string{"--format", "json"}
			} else if row.Kind != "report" {
				t.Fatal("unknown fixture kind")
			}
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
					args := append([]string{command}, mode...)
					args = append(args, transport.args...)
					var stdout, stderr bytes.Buffer
					code := Run(t.Context(), args, strings.NewReader(transport.input), &stdout, &stderr)
					if code != row.ExitCode {
						t.Fatalf("exit=%d want=%d stderr=%s", code, row.ExitCode, stderr.String())
					}
					if row.Error != "" {
						if stdout.Len() != 0 || stderr.String() != row.Error+"\n" {
							t.Fatalf("admission/view refusal changed: stdout=%s stderr=%s", stdout.String(), stderr.String())
						}
					} else if stderr.Len() != 0 || !bytes.Equal(canonicalSpecTreeJSON(t, stdout.Bytes()), canonicalSpecTreeJSON(t, row.Output)) {
						t.Fatalf("pre-structure wire changed: stdout=%s stderr=%s", stdout.String(), stderr.String())
					}
				})
			}
		})
	}
}

func canonicalSpecTreeJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	value, err := admission.DecodeJSON(bytes.NewReader(raw), maxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	data, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSpecTreeCLIExactDisplayOrderTokens(t *testing.T) {
	data, err := os.ReadFile("testdata/spec-tree-native-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Case, Kind string
		Input      json.RawMessage
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	var fixture json.RawMessage
	for _, row := range rows {
		if row.Case == "valid" && row.Kind == "report" {
			fixture = row.Input
		}
	}
	if len(fixture) == 0 {
		t.Fatal("missing independent input")
	}
	for _, token := range []string{"1", "9007199254740993", "9223372036854775807", "0", "1.0", "1e0", "9223372036854775808"} {
		for _, view := range []bool{false, true} {
			t.Run(token+"/"+map[bool]string{false: "report", true: "view"}[view], func(t *testing.T) {
				value, err := admission.DecodeJSON(bytes.NewReader(fixture), maxInputBytes)
				if err != nil {
					t.Fatal(err)
				}
				input := value.(map[string]any)
				for _, item := range input["nodes"].([]any) {
					item.(map[string]any)["displayOrder"] = json.Number(token)
				}
				encoded, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{"requirement-spec-tree", "--input", "-"}
				if view {
					args = []string{"requirement-spec-tree-view", "--format", "json", "--input", "-"}
				}
				var stdout, stderr bytes.Buffer
				code := Run(t.Context(), args, bytes.NewReader(encoded), &stdout, &stderr)
				valid := token == "1" || token == "9007199254740993" || token == "9223372036854775807"
				if !valid {
					if code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
						t.Fatal("noncanonical/out-of-domain integer did not fail closed")
					}
					return
				}
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("valid native integer rejected: %s", stderr.String())
				}
				result, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), maxInputBytes)
				if err != nil {
					t.Fatal(err)
				}
				output := result.(map[string]any)
				var nodes []any
				if view {
					nodes = output["nodes"].([]any)
				} else {
					nodes = output["diagnostics"].([]any)[4].(map[string]any)["value"].([]any)
				}
				if len(nodes) != 3 {
					t.Fatal("incomplete numeric observation")
				}
				for _, node := range nodes {
					if node.(map[string]any)["displayOrder"] != json.Number(token) {
						t.Fatal("exact integer token was lost")
					}
				}
			})
		}
	}
}
