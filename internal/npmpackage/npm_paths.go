// Package npmpackage owns Proofkit's npm file-membership policy, not archive
// authentication, filesystem admission, or the policy of other npm packages.
package npmpackage

import (
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

var requiredPaths = append([]string{
	"ADOPTION.md",
	"LICENSE",
	"NON_CLAIMS.md",
	"README.md",
	"SECURITY.md",
	"dist/agentic-proofkit",
	"docs/images/workspace.png",
	"docs/proofkit-contract-map.md",
	"docs/release-process.md",
	"package.json",
	"proofkit/cli-contract.v2.json",
	"proofkit/command-families.v1.json",
	"proofkit/receipt-producer-policy.json",
	"proofkit/requirement-bindings.json",
	"proofkit/witness-plan.json",
}, releaseplatform.BinaryPaths()...)

// RequiredPaths returns an independent slice in first-missing diagnostic order.
func RequiredPaths() []string {
	return slices.Clone(requiredPaths)
}

func IsAllowedPath(path string) bool {
	if slices.Contains(requiredPaths, path) {
		return true
	}
	switch path {
	case "docs/specs/proofkit-agent-workflow/overview.md",
		"docs/specs/proofkit-agent-workflow/requirements.v2.json",
		"docs/specs/proofkit-consumer-infra-retirement/overview.md",
		"docs/specs/proofkit-consumer-infra-retirement/requirements.v2.json",
		"docs/specs/proofkit-package-boundary/overview.md",
		"docs/specs/proofkit-package-boundary/requirements.v2.json",
		"docs/specs/proofkit-receipt-authority/overview.md",
		"docs/specs/proofkit-receipt-authority/requirements.v2.json",
		"docs/specs/proofkit-spec-proof-core/overview.md",
		"docs/specs/proofkit-spec-proof-core/requirements.v2.json",
		"docs/specs/proofkit-supply-chain-quality/overview.md",
		"docs/specs/proofkit-supply-chain-quality/requirements.v2.json":
		return true
	default:
		return false
	}
}

func IsForbiddenPath(path string) bool {
	for _, suffix := range []string{".d.ts", ".ts", ".map"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	switch path {
	case "bun.lock", "dist/cli.js", "dist/index.js", "proofkit/sdk-cli-parity.v1.json", "tsconfig.json":
		return true
	default:
		return false
	}
}
