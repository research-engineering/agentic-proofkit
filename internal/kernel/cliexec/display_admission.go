package cliexec

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

// SafeDisplayArgv admits the composed presentation, not command execution.
// Individually safe operands can form a protected signature when quoted/joined.
func SafeDisplayArgv(argv []string, context string) (string, error) {
	display := DisplayArgv(argv)
	if !unicodepolicy.ValidScalarString(display) || unicodepolicy.ContainsUnsafeScalar(display) || admit.ContainsSecretLikePathValue(display) {
		return "", fmt.Errorf("%s must render safe command text", context)
	}
	return display, nil
}
