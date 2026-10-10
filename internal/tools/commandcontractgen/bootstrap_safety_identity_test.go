package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestBootstrapSafetyRejectsPredecessorSemanticIdentities(t *testing.T) {
	for _, row := range []struct{ command, previous, current string }{
		{"gradual-adoption-bootstrap", "proofkit.gradual-adoption-bootstrap.input.v1", "proofkit.gradual-adoption-bootstrap.input.v2"},
		{"adoption-contract-envelope", "proofkit.adoption-contract-envelope.input.v2", "proofkit.adoption-contract-envelope.input.v3"},
		{"scaffold-project-structure", "proofkit.scaffold-project-structure.input.v1", "proofkit.scaffold-project-structure.input.v2"},
	} {
		if err := admitBootstrapSafetyIdentity(row.command, "input", map[string]any{"contractId": row.current}); err != nil {
			t.Fatal(err)
		}
		for _, identity := range []any{row.previous, "proofkit.unrelated.input.v1", nil} {
			if err := admitBootstrapSafetyIdentity(row.command, "input", map[string]any{"contractId": identity}); err == nil {
				t.Fatal("retired input identity described new admission semantics")
			}
		}
		if err := admitBootstrapSafetyIdentity(row.command, "output", map[string]any{"contractId": "unchanged-output"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBootstrapSafetyGeneratorBoundaryRejectsRetiredIdentities(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	source, current, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := renderContract(root, source, current); err != nil {
		t.Fatalf("current identity positive control: %v", err)
	}
	for _, row := range []struct{ command, retired string }{
		{"gradual-adoption-bootstrap", "proofkit.gradual-adoption-bootstrap.input.v1"},
		{"adoption-contract-envelope", "proofkit.adoption-contract-envelope.input.v2"},
		{"scaffold-project-structure", "proofkit.scaffold-project-structure.input.v1"},
	} {
		t.Run(row.command, func(t *testing.T) {
			value, err := admission.DecodeJSON(bytes.NewReader(source), maxContractBytes)
			if err != nil {
				t.Fatal(err)
			}
			contract := value.(map[string]any)
			commandAt(contract, row.command)["inputContract"].(map[string]any)["contractId"] = row.retired
			_, _, err = renderContract(root, source, contract)
			if err == nil || !strings.Contains(err.Error(), row.command+" inputContract must use the bootstrap safety semantic identity") {
				t.Fatal("generator boundary accepted retired identity or refused for an unrelated reason")
			}
		})
	}
}
