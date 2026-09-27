package npmpackage

import (
	"slices"
	"testing"
)

var expectedRequiredPaths = []string{
	"ADOPTION.md", "LICENSE", "NON_CLAIMS.md", "README.md", "SECURITY.md",
	"dist/agentic-proofkit", "docs/images/workspace.png",
	"docs/proofkit-contract-map.md", "docs/release-process.md", "package.json",
	"proofkit/cli-contract.v2.json", "proofkit/command-families.v1.json",
	"proofkit/receipt-producer-policy.json", "proofkit/requirement-bindings.json", "proofkit/witness-plan.json",
	"dist/platform/darwin-arm64/agentic-proofkit", "dist/platform/darwin-x64/agentic-proofkit",
	"dist/platform/linux-arm64/agentic-proofkit", "dist/platform/linux-x64/agentic-proofkit",
}

func TestRequiredPathsPreserveExactInventoryAndReturnOwnership(t *testing.T) {
	paths := RequiredPaths()
	if !slices.Equal(paths, expectedRequiredPaths) {
		t.Fatalf("required paths/order changed: %v", paths)
	}
	paths[0] = "mutated"
	if !slices.Equal(RequiredPaths(), expectedRequiredPaths) || IsAllowedPath("mutated") || !IsAllowedPath("ADOPTION.md") {
		t.Fatal("returned slice mutated policy")
	}
}

func TestPathPolicyKeepsRequiredAllowedAndForbiddenDistinct(t *testing.T) {
	optional := []string{
		"docs/specs/proofkit-agent-workflow/overview.md", "docs/specs/proofkit-agent-workflow/requirements.v2.json",
		"docs/specs/proofkit-consumer-infra-retirement/overview.md", "docs/specs/proofkit-consumer-infra-retirement/requirements.v2.json",
		"docs/specs/proofkit-package-boundary/overview.md", "docs/specs/proofkit-package-boundary/requirements.v2.json",
		"docs/specs/proofkit-receipt-authority/overview.md", "docs/specs/proofkit-receipt-authority/requirements.v2.json",
		"docs/specs/proofkit-spec-proof-core/overview.md", "docs/specs/proofkit-spec-proof-core/requirements.v2.json",
		"docs/specs/proofkit-supply-chain-quality/overview.md", "docs/specs/proofkit-supply-chain-quality/requirements.v2.json",
	}
	for _, path := range append(slices.Clone(expectedRequiredPaths), optional...) {
		if !IsAllowedPath(path) || IsForbiddenPath(path) {
			t.Fatalf("allowed path rejected or forbidden: %s", path)
		}
	}
	for _, path := range optional {
		if slices.Contains(RequiredPaths(), path) {
			t.Fatalf("optional path became required: %s", path)
		}
	}
	for _, path := range []string{"bun.lock", "dist/cli.js", "dist/index.js", "proofkit/sdk-cli-parity.v1.json", "tsconfig.json", "src/a.ts", "types/a.d.ts", "dist/a.js.map"} {
		if !IsForbiddenPath(path) || IsAllowedPath(path) {
			t.Fatalf("forbidden classification changed: %s", path)
		}
	}
	for _, path := range []string{"AGENTS.md", "CONTRIBUTING.md", "internal/a.go", "src/index.go", "test/fixture.go", "docs/unknown.md", "dist/platform/unknown/agentic-proofkit", "readme.md", "package/README.md", "./README.md", "../README.md", "README.md/", "README.md ", "docs\\release-process.md", ""} {
		if IsAllowedPath(path) || IsForbiddenPath(path) {
			t.Fatalf("unexpected path classification changed: %q", path)
		}
	}
}
