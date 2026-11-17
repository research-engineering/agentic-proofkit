package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// The fixture declares synthetic caller facts; no named witness is executed.
// The projector's exact stdout, not a reconstructed DTO, enters the decision CLI.
func TestReceiptPathRolesSurviveWholeCLIProjectionAndDecision(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "app", "testdata", "receipt-path-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(map[string]any, string)
	}{
		{"currentness", func(input map[string]any, path string) {
			input["receiptCurrentnessScopeAdmission"].(map[string]any)["obligationReceipts"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{path}
		}},
		{"trust", func(input map[string]any, path string) {
			input["receiptTrustClassAdmission"].(map[string]any)["obligationReceipts"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{path}
		}},
		{"route", func(input map[string]any, path string) {
			input["commandRoutes"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{path}
		}},
		{"producer and selective evidence", func(input map[string]any, path string) {
			evidence := input["evidence"].(map[string]any)
			producer := evidence["producerAdmission"].(map[string]any)
			producer["producers"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{path}
			producer["receipts"].([]any)[0].(map[string]any)["evidenceRef"] = path
			evidence["receipts"].([]any)[0].(map[string]any)["evidenceRef"] = path
		}},
		{"artifacts", func(input map[string]any, path string) {
			evidence := input["evidence"].(map[string]any)
			evidence["producerAdmission"].(map[string]any)["receipts"].([]any)[0].(map[string]any)["artifactRefs"] = []any{path}
			evidence["receipts"].([]any)[0].(map[string]any)["artifactRefs"] = []any{path}
			input["receiptTrustClassAdmission"].(map[string]any)["obligationReceipts"].([]any)[0].(map[string]any)["artifactRefs"] = []any{path}
		}},
		{"provenance", func(input map[string]any, path string) {
			input["evidence"].(map[string]any)["producerAdmission"].(map[string]any)["receipts"].([]any)[0].(map[string]any)["provenanceRef"] = path
			input["receiptTrustClassAdmission"].(map[string]any)["obligationReceipts"].([]any)[0].(map[string]any)["provenanceRef"] = path
		}},
	}
	for _, item := range cases {
		for _, path := range []string{"artifacts/ordinary.json", "artifacts/task-requirements.json", "artifacts/run-sk-abcdefghij.log", " artifacts/task-requirements.json "} {
			t.Run(item.name+"/"+path, func(t *testing.T) {
				input := invocationProfileObject(t, invocationProfileJSON(t, string(source)))
				item.edit(input, path)
				for _, child := range []struct{ command, key string }{
					{"receipt-currentness-scope", "receiptCurrentnessScopeAdmission"},
					{"receipt-trust-class", "receiptTrustClassAdmission"},
				} {
					receiptPathCLISuccess(t, child.command, []byte(invocationProfileEncode(t, input[child.key])))
				}
				evidence := input["evidence"].(map[string]any)
				receiptPathCLISuccess(t, "receipt-producer-admission", []byte(invocationProfileEncode(t, evidence["producerAdmission"])))
				projection := receiptPathCLISuccess(t, "selective-gate-obligation-decision-input", []byte(invocationProfileEncode(t, input)))
				decisionBytes := receiptPathCLISuccess(t, "obligation-decision", projection)
				decision := invocationProfileObject(t, invocationProfileJSON(t, string(decisionBytes)))
				if decision["state"] != "passed" {
					t.Fatal("matching admitted caller facts did not remain a passed decision report")
				}
				rows := invocationProfileDiagnostic(t, decision, "decisions").([]any)
				if len(rows) != 1 || rows[0].(map[string]any)["decisionState"] != "satisfied" {
					t.Fatal("path role changed the declared decision algebra")
				}
				// Artifact/provenance are retained in their own carriers, not evidenceRefs.
				if item.name != "artifacts" && item.name != "provenance" {
					found := false
					for _, ref := range rows[0].(map[string]any)["evidenceRefs"].([]any) {
						found = found || ref == path
					}
					if !found {
						t.Fatal("projection or downstream admission changed exact reference bytes")
					}
				}
			})
		}
	}
}

func receiptPathCLISuccess(t *testing.T, command string, input []byte) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := RunWithRenderer(t.Context(), []string{command, "--input", "-"}, bytes.NewReader(input), &stdout, &stderr, cliexec.PathRenderer())
	if status != 0 || stderr.Len() != 0 || stdout.Len() == 0 {
		t.Fatalf("%s did not produce successful CLI JSON: exit=%d stderr=%q", command, status, stderr.String())
	}
	return bytes.Clone(stdout.Bytes())
}
