package gradualadoption

import (
	"bytes"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// The wire version stays 1; rejecting secret-shaped payloads changes admission.
const BootstrapInputContractID = "proofkit.gradual-adoption-bootstrap.input.v2"

func bootstrapSnapshot(raw map[string]any) (map[string]any, error) {
	// Clone before policy or projection so neither output nor decisions retain
	// caller containers. Strict JSON numbers retain their original spelling.
	encoded, err := stablejson.MarshalLayout(raw, stablejson.LayoutCompact)
	if err != nil {
		return nil, fmt.Errorf("gradual adoption bootstrap input must be JSON-serializable")
	}
	// A credential label plus an opaque value can be sensitive even when
	// neither string, considered separately, matches the secret taxonomy.
	if admit.ContainsSecretLikeValue(string(encoded)) {
		return nil, fmt.Errorf("gradual adoption bootstrap input must not contain secret-shaped keys or values")
	}
	snapshot, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return nil, fmt.Errorf("gradual adoption bootstrap input must be strict JSON")
	}
	findings, err := secretjson.Scan(snapshot, "bootstrap")
	if err != nil || len(findings) != 0 {
		return nil, fmt.Errorf("gradual adoption bootstrap input must not contain secret-shaped keys or values")
	}
	return snapshot.(map[string]any), nil
}
