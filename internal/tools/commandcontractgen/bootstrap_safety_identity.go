package main

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptioncontract"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/projectstructure"
)

func admitBootstrapSafetyIdentity(command, direction string, contract map[string]any) error {
	if direction != "input" {
		return nil
	}
	want := ""
	switch command {
	case "gradual-adoption-bootstrap":
		want = gradualadoption.BootstrapInputContractID
	case "adoption-contract-envelope":
		want = adoptioncontract.InputContractID
	case "scaffold-project-structure":
		want = projectstructure.InputContractID
	default:
		return nil
	}
	if contract["contractId"] != want {
		return fmt.Errorf("%s inputContract must use the bootstrap safety semantic identity %s", command, want)
	}
	return nil
}
