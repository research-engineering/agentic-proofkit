package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestSupportedCommandsHaveExplicitCoverageRoutes(t *testing.T) {
	contract := readCLIContract(t)
	contractCommands := make(map[string]cliContractCommand, len(contract.Commands))
	for _, command := range contract.Commands {
		contractCommands[command.Command] = command
	}
	for command := range supportedCommands {
		contractCommand, ok := contractCommands[command]
		if !ok {
			t.Fatalf("supported command %s missing from CLI contract", command)
		}
		routes := commandCoverageRoutes[command]
		if len(routes) == 0 {
			t.Fatalf("supported command %s has no explicit coverage route", command)
		}
		for _, route := range routes {
			assertCommandCoverageRoute(t, command, contractCommand, route)
		}
	}
	for command := range commandCoverageRoutes {
		if _, ok := supportedCommands[command]; !ok {
			t.Fatalf("coverage route references unsupported command %s", command)
		}
	}
}

func TestCommandCoverageRejectsPackageRouteToAppSmokeTest(t *testing.T) {
	route := packageFalsifierRoute("internal/app/command_coverage_test.go", "TestNoInputCommandsHaveCommandSpecificBehavior", semanticRouteProof("test.unrelated_app_smoke"), "Unrelated app smoke must not satisfy package-level semantic coverage.")
	if problem := routeSemanticOwnerProblem("registry-consumer", route); problem == "" {
		t.Fatal("package-level semantic route to app smoke test was admitted")
	}
}

func TestCommandCoverageInventoryRejectsSemanticRouteOutsideOwnerScope(t *testing.T) {
	route := packageFalsifierRoute("internal/app/command_coverage_test.go", "TestNoInputCommandsHaveCommandSpecificBehavior", semanticRouteProof("test.unrelated_app_smoke"), "Unrelated app smoke must not satisfy package-level semantic coverage.")
	if _, err := commandCoverageInventoryFrom(map[string][]commandCoverageRoute{"registry-consumer": {route}}); err == nil {
		t.Fatal("production command coverage inventory builder admitted a semantic route outside the command owner scope")
	}
}

func TestCommandCoverageInventoryRejectsSameOwnerUnrelatedNonEmptyTest(t *testing.T) {
	route := packageFalsifierRoute(
		"internal/command/registryconsumer/registryconsumer_test.go",
		"TestRegistryConsumerAddsMandatoryBoundaryNonClaims",
		semanticRouteProof("registryconsumer.registry_consumer_accepts_registry_release_proof"),
		"Same-owner unrelated assertion must not satisfy registry-consumer release-proof semantic coverage.",
	)
	_, err := commandCoverageInventoryFrom(map[string][]commandCoverageRoute{"registry-consumer": {route}})
	if err == nil || !strings.Contains(err.Error(), "source oracle") {
		t.Fatalf("same-owner unrelated non-empty test was admitted: %v", err)
	}
}

func TestCommandCoverageRejectsPackageRouteToDifferentCommandPackage(t *testing.T) {
	route := packageFalsifierRoute("internal/command/externalconsumer/externalconsumer_test.go", "TestBuildAdmitsExternalConsumerProofAndRejectsWorkspaceLock", semanticRouteProof("test.unrelated_command_package"), "Unrelated command package must not satisfy registry-consumer semantic coverage.")
	if problem := routeSemanticOwnerProblem("registry-consumer", route); problem == "" {
		t.Fatal("package-level semantic route to unrelated command package was admitted")
	}
}

func TestCommandCoverageRejectsDirectRouteToDifferentAppCommand(t *testing.T) {
	route := directCLIRoute("internal/app/cli_abi_test.go", "TestRequirementBrowserServerSpecTreeCLIABI", semanticRouteProof("test.unrelated_app_cli_abi"), "Unrelated app CLI ABI test must not satisfy adoption-doctor semantic coverage.")
	if problem := routeSemanticOwnerProblem("adoption-doctor", route); problem == "" {
		t.Fatal("direct app semantic route to unrelated command was admitted")
	}
}

func TestCommandCoverageRejectsRouteWithoutDescriptorOwner(t *testing.T) {
	route := packageFalsifierRoute("internal/command/registryconsumer/registryconsumer_test.go", "TestRegistryConsumerAcceptsRegistryReleaseProof", semanticRouteProof("test.unsupported_descriptor_owner"), "Unsupported command must not satisfy package-level semantic coverage.")
	if problem := routeSemanticOwnerProblem("unsupported-command", route); problem == "" {
		t.Fatal("package-level semantic route without descriptor owner was admitted")
	}
}

func TestCommandCoverageRejectsSemanticRouteWithoutProofMetadata(t *testing.T) {
	route := commandCoverageRoute{
		file:      "internal/command/registryconsumer/registryconsumer_test.go",
		kind:      "package_level_falsifier",
		rationale: "Semantic command route must not be admitted without owner-declared proof identity.",
		testName:  "TestRegistryConsumerAcceptsRegistryReleaseProof",
	}
	if _, err := commandCoverageInventoryFrom(map[string][]commandCoverageRoute{"registry-consumer": {route}}); err == nil {
		t.Fatal("semantic route without proof metadata was admitted by production inventory builder")
	}
}

func TestCommandCoverageRejectsSemanticRouteWithoutExpectedOutcome(t *testing.T) {
	route := commandCoverageRoute{
		file:          "internal/command/registryconsumer/registryconsumer_test.go",
		kind:          "package_level_falsifier",
		semanticProof: semanticRouteProof("registryconsumer.accepts_registry_release_proof"),
		testName:      "TestRegistryConsumerAcceptsRegistryReleaseProof",
	}
	if _, err := commandCoverageInventoryFrom(map[string][]commandCoverageRoute{"registry-consumer": {route}}); err == nil {
		t.Fatal("semantic route without expected public outcome was admitted by production inventory builder")
	}
}

func TestCommandCoverageRejectsRouteIndexDerivedSemanticProofID(t *testing.T) {
	route := packageFalsifierRoute(
		"internal/command/registryconsumer/registryconsumer_test.go",
		"TestRegistryConsumerAcceptsRegistryReleaseProof",
		semanticRouteProof("registryconsumer.route_7"),
		"Semantic command route must not derive proof identity from route order.",
	)
	if _, err := commandCoverageInventoryFrom(map[string][]commandCoverageRoute{"registry-consumer": {route}}); err == nil {
		t.Fatal("route-index-derived semantic proof ID was admitted by production inventory builder")
	}
}

func TestCommandCoverageRejectsProseDerivedSemanticProofID(t *testing.T) {
	route := packageFalsifierRoute(
		"internal/command/registryconsumer/registryconsumer_test.go",
		"TestRegistryConsumerAcceptsRegistryReleaseProof",
		semanticRouteProof("Registry consumer accepts release proof"),
		"Semantic command route must not derive proof identity from prose.",
	)
	if _, err := commandCoverageInventoryFrom(map[string][]commandCoverageRoute{"registry-consumer": {route}}); err == nil {
		t.Fatal("prose-derived semantic proof ID was admitted by production inventory builder")
	}
}

func TestCommandCoverageRejectsRouteOnlyWithSemanticProofMetadata(t *testing.T) {
	route := requiredInputAdmissionRoute
	route.semanticProof = semanticRouteProof("test.route_only_with_semantic_proof")
	if _, err := commandCoverageInventoryFrom(map[string][]commandCoverageRoute{"registry-consumer": {route}}); err == nil {
		t.Fatal("route-only smoke accepted semantic proof metadata in production inventory builder")
	}
}

func TestCommandCoverageInventoryIsAdmittedAndBindsProofRouteCandidates(t *testing.T) {
	result, err := testevidenceinventory.Evaluate(mustCommandCoverageInventory(t))
	if err != nil {
		t.Fatalf("CommandCoverageInventory() admission error = %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("CommandCoverageInventory() failed admission: %#v", result.Report.JSONValue())
	}
	candidateCommandRefs := map[string]struct{}{}
	routeOnlyCount := 0
	for _, entry := range result.Inventory.Entries {
		if len(entry.CommandRefs) != 1 {
			t.Fatalf("command coverage entry must bind exactly one command ref: %#v", entry)
		}
		switch entry.EvidenceClass {
		case "proof_route_candidate":
			if len(entry.OwnerInvariantRefs) != 1 || entry.Falsifier != nil || entry.Oracle != nil {
				t.Fatalf("proof-route candidate laundered semantic evidence: %#v", entry)
			}
			candidateCommandRefs[entry.CommandRefs[0]] = struct{}{}
		case "declared_semantic_falsifier_route":
			t.Fatalf("static command coverage route became semantic evidence: %#v", entry)
		case "routing_smoke_nonclaim":
			if len(entry.OwnerInvariantRefs) != 0 || entry.Falsifier != nil || entry.Oracle != nil {
				t.Fatalf("routing smoke entry claimed semantic evidence: %#v", entry)
			}
			routeOnlyCount++
		default:
			t.Fatalf("unexpected command coverage evidence class: %#v", entry)
		}
	}
	if routeOnlyCount == 0 {
		t.Fatal("command coverage inventory must preserve route-only smoke entries as non-claims")
	}
	for command := range supportedCommands {
		ref := CommandCoverageCommandRef(command)
		if _, ok := candidateCommandRefs[ref]; !ok {
			t.Fatalf("supported command %s lacks admitted proof-route candidate", command)
		}
	}
}

func TestCommandCoverageOracleCandidatesAreExactAndRouteSpecific(t *testing.T) {
	candidates, err := CommandCoverageOracleCandidates()
	if err != nil {
		t.Fatalf("CommandCoverageOracleCandidates() error = %v", err)
	}
	wantCount := 0
	for _, summary := range CommandCoverageSummaries() {
		wantCount += summary.ProofRouteCandidateCount
	}
	if len(candidates) != wantCount || len(candidates) == 0 {
		t.Fatalf("candidate count = %d, want %d", len(candidates), wantCount)
	}
	seenMarkers := map[string]struct{}{}
	seenOutcomes := map[string]struct{}{}
	for index, candidate := range candidates {
		if strings.TrimSpace(candidate.ExpectedPublicOutcome) == "" {
			t.Fatalf("candidate has no route-specific outcome: %#v", candidate)
		}
		if _, exists := seenMarkers[candidate.SourceMarker]; exists {
			t.Fatalf("duplicate candidate marker %s", candidate.SourceMarker)
		}
		seenMarkers[candidate.SourceMarker] = struct{}{}
		seenOutcomes[candidate.ExpectedPublicOutcome] = struct{}{}
		if index > 0 && strings.Join(candidateIdentity(candidates[index-1]), "\x00") >= strings.Join(candidateIdentity(candidate), "\x00") {
			t.Fatalf("candidates are not in strict canonical order at %d", index)
		}
	}
	if len(seenOutcomes) < 2 {
		t.Fatalf("route-specific outcomes collapsed: %#v", seenOutcomes)
	}
}

func TestCommandCoverageSourceMarkerBindsRouteSpecificOutcome(t *testing.T) {
	route := packageFalsifierRoute(
		"internal/command/registryconsumer/registryconsumer_test.go",
		"TestRegistryConsumerAcceptsRegistryReleaseProof",
		semanticRouteProof("registryconsumer.marker_binds_outcome"),
		"Registry consumer accepts only an admitted registry release proof.",
	)
	first := route.sourceOracleMarker("registry-consumer")
	route.rationale = "Registry consumer rejects a registry release proof with mismatched identity."
	second := route.sourceOracleMarker("registry-consumer")
	if first == second {
		t.Fatalf("route-specific outcome did not change source marker: %s", first)
	}
}

func TestCommandCoverageInventoryProjectsStableCandidateRefWithoutSemanticProof(t *testing.T) {
	route := packageFalsifierRoute(
		"internal/command/registryconsumer/registryconsumer_test.go",
		"TestRegistryConsumerAcceptsRegistryReleaseProof",
		semanticRouteProof("registryconsumer.accepts_registry_release_proof"),
		"Registry consumer release proof must be tied to an owner-declared semantic proof identity.",
	)
	entry := route.inventoryEntry("registry-consumer", 99)

	if entry["testId"] != "proofkit.command_coverage.registryconsumer.accepts_registry_release_proof.route" {
		t.Fatalf("testId did not use stable candidate ref: %#v", entry["testId"])
	}
	if entry["evidenceClass"] != "proof_route_candidate" {
		t.Fatalf("static route evidenceClass=%#v, want proof_route_candidate", entry["evidenceClass"])
	}
	if entry["falsifier"] != nil || entry["oracle"] != nil {
		t.Fatalf("static route projected semantic proof fields: %#v", entry)
	}
}

func TestGoTestFunctionProblemRejectsEmptyFunction(t *testing.T) {
	filePath := writeGoTestFixture(t, `package fixture

import "testing"

func TestEmpty(t *testing.T) {}
`)
	problem := goTestFunctionProblem(filePath, "TestEmpty")
	if !strings.Contains(problem, "has no executable body") {
		t.Fatalf("empty test body was not rejected: %q", problem)
	}
}

func TestGoTestFunctionProblemRejectsAssertionlessBody(t *testing.T) {
	filePath := writeGoTestFixture(t, `package fixture

import "testing"

func TestAssertionless(t *testing.T) {
	_ = "not an oracle"
}
`)
	problem := goTestFunctionProblem(filePath, "TestAssertionless")
	if !strings.Contains(problem, "has no direct failure-capable assertion candidate") {
		t.Fatalf("assertionless test body was not rejected: %q", problem)
	}
}

func TestGoTestFunctionProblemRejectsUnconditionalSkip(t *testing.T) {
	filePath := writeGoTestFixture(t, `package fixture

import "testing"

func TestSkipped(t *testing.T) {
	t.Skip("not implemented")
}
`)
	problem := goTestFunctionProblem(filePath, "TestSkipped")
	if !strings.Contains(problem, "contains t.Skip") {
		t.Fatalf("unconditional skip was not rejected: %q", problem)
	}
}

func TestGoTestFunctionProblemRejectsNestedSkipBeforeAssertion(t *testing.T) {
	filePath := writeGoTestFixture(t, `package fixture

import "testing"

func TestConditionallySkipped(t *testing.T) {
	if true {
		t.Skip("not implemented")
	}
	t.Fatal("unreachable")
}
`)
	problem := goTestFunctionProblem(filePath, "TestConditionallySkipped")
	if !strings.Contains(problem, "contains t.Skip") {
		t.Fatalf("nested skip was not rejected: %q", problem)
	}
}

func TestGoTestSemanticOracleProblemRequiresSourceOwnedMarker(t *testing.T) {
	marker := "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001"
	filePath := writeGoTestFixture(t, `package fixture

import "testing"

func TestHasAssertionButNoMarker(t *testing.T) {
	t.Fatal("intentional falsifier")
}
`)
	problem := goTestSemanticOracleProblem(filePath, "TestHasAssertionButNoMarker", marker)
	if !strings.Contains(problem, "missing source-owned semantic oracle import") {
		t.Fatalf("missing marker was not rejected: %q", problem)
	}
}

func TestGoTestSemanticOracleProblemRejectsUnrelatedSourceMarker(t *testing.T) {
	marker := "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001"
	filePath := writeGoTestFixture(t, `package fixture

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestHasWrongMarker(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000002")
	t.Fatal("intentional falsifier")
}
`)
	problem := goTestSemanticOracleProblem(filePath, "TestHasWrongMarker", marker)
	if !strings.Contains(problem, "missing source-owned semantic oracle binding "+marker) {
		t.Fatalf("wrong marker was not rejected: %q", problem)
	}
}

func TestGoTestSemanticOracleProblemRejectsBareStringMarker(t *testing.T) {
	marker := "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001"
	filePath := writeGoTestFixture(t, `package fixture

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestHasBareMarker(t *testing.T) {
	_ = "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001"
	t.Fatal("intentional falsifier")
}
`)
	problem := goTestSemanticOracleProblem(filePath, "TestHasBareMarker", marker)
	if !strings.Contains(problem, "missing source-owned semantic oracle binding "+marker) {
		t.Fatalf("bare marker was not rejected: %q", problem)
	}
}

func TestGoTestSemanticOracleProblemRejectsMismatchedBindingFact(t *testing.T) {
	route := packageFalsifierRoute(
		"internal/command/registryconsumer/registryconsumer_test.go",
		"TestRegistryConsumerAcceptsRegistryReleaseProof",
		semanticRouteProof("registryconsumer.registry_consumer_accepts_registry_release_proof"),
		"Registry consumer release proof must be tied to an owner-declared semantic proof identity.",
	)
	filePath := filepath.Join(repoRoot(t), route.file)
	mismatchedCommandRefMarker := route.sourceOracleMarker("external-consumer")
	problem := goTestSemanticOracleProblem(filePath, route.testName, mismatchedCommandRefMarker)
	if !strings.Contains(problem, "missing source-owned semantic oracle binding "+mismatchedCommandRefMarker) {
		t.Fatalf("mismatched commandRef marker was not rejected: %q", problem)
	}
}

func TestGoTestSemanticOracleProblemAdmitsSourceOwnedMarker(t *testing.T) {
	marker := "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001"
	filePath := writeGoTestFixture(t, `package fixture

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestHasMarker(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001")
	t.Fatal("intentional falsifier")
}
`)
	if problem := goTestSemanticOracleProblem(filePath, "TestHasMarker", marker); problem != "" {
		t.Fatalf("source-owned marker was rejected: %q", problem)
	}
}

func TestUnreachableFatalCannotBecomeSemanticEvidence(t *testing.T) {
	route := packageFalsifierRoute(
		"internal/command/registryconsumer/registryconsumer_test.go",
		"TestRegistryConsumerAcceptsRegistryReleaseProof",
		semanticRouteProof("registryconsumer.unreachable_fatal_regression"),
		"An unreachable assertion must remain candidate-only.",
	)
	marker := route.sourceOracleMarker("registry-consumer")
	source := strings.ReplaceAll(`package fixture

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestUnreachableFatal(t *testing.T) {
	commandcoverage.SemanticRoute(t, "{{MARKER}}")
	if false {
		t.Fatal("unreachable")
	}
}
`, "{{MARKER}}", marker)
	filePath := writeGoTestFixture(t, source)
	if problem := goTestSemanticOracleProblem(filePath, "TestUnreachableFatal", marker); problem != "" {
		t.Fatalf("regression fixture must satisfy static route hygiene, got %q", problem)
	}

	entry := route.inventoryEntry("registry-consumer", 0)
	if entry["evidenceClass"] != "proof_route_candidate" || entry["falsifier"] != nil || entry["oracle"] != nil {
		t.Fatalf("unreachable failure assertion became semantic evidence: %#v", entry)
	}
}

func TestRequiredInputCommandsRejectMalformedCallerRecords(t *testing.T) {
	for _, command := range readCLIContract(t).Commands {
		if command.Input != "required" || command.Command == "self-check" {
			continue
		}
		t.Run(command.Command, func(t *testing.T) {
			args := append(effectiveContractRoute(command), "--input", "-")
			args = append(args, malformedInputExtraArgs(command.Command)...)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), args, strings.NewReader(`{"schemaVersion":1,"unexpected":true}`), &stdout, &stderr)
			if status == 0 {
				t.Fatalf("%s accepted malformed caller record: stdout=%s stderr=%s", command.Command, stdout.String(), stderr.String())
			}
			output := stdout.String() + stderr.String()
			if output == "" {
				t.Fatalf("%s failed without diagnostics", command.Command)
			}
			for _, forbidden := range []string{"requires --input", "requires exactly one", "unsupported argument", "unsupported command"} {
				if strings.Contains(output, forbidden) {
					t.Fatalf("%s did not reach command-specific input admission, output=%s", command.Command, output)
				}
			}
		})
	}
}

func TestNoInputCommandsHaveCommandSpecificBehavior(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.070498585436389324351139272251942930131041611602879828983669878551280280496659")
	t.Run("stack-preset", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		status := Run(t.Context(), []string{"stack-preset", "--preset", "typescript_workspace"}, strings.NewReader(""), &stdout, &stderr)
		if status != 0 || stderr.Len() != 0 {
			t.Fatalf("stack-preset failed status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
		}
		var output map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatalf("stack-preset stdout must be JSON: %v\n%s", err, stdout.String())
		}
		if output["reportKind"] != "proofkit.stack-preset" || output["state"] != "passed" {
			t.Fatalf("unexpected stack-preset output: %#v", output)
		}

		stdout.Reset()
		stderr.Reset()
		status = Run(t.Context(), []string{"stack-preset", "--preset", "unknown"}, strings.NewReader(""), &stdout, &stderr)
		if status == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "--preset requires one of:") {
			t.Fatalf("stack-preset accepted unknown preset status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
		}
	})
}

func TestNoInputCommandDescriptorsHaveRuntimeSmoke(t *testing.T) {
	for _, descriptor := range commandDescriptors {
		if descriptor.input != commandInputNone {
			continue
		}
		t.Run(descriptor.name, func(t *testing.T) {
			args, wantJSON := noInputRuntimeSmokeArgs(t, descriptor)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), args, strings.NewReader(""), &stdout, &stderr)
			if status != 0 || stderr.Len() != 0 {
				t.Fatalf("%s smoke failed status=%d stdout=%s stderr=%s", descriptor.name, status, stdout.String(), stderr.String())
			}
			if wantJSON {
				var output map[string]any
				if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
					t.Fatalf("%s smoke stdout must be JSON: %v\n%s", descriptor.name, err, stdout.String())
				}
				return
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("%s smoke stdout must be help text: %s", descriptor.name, stdout.String())
			}
		})
	}
}

func noInputRuntimeSmokeArgs(t *testing.T, descriptor commandDescriptor) ([]string, bool) {
	t.Helper()
	switch descriptor.name {
	case "adopt-materialize-recover":
		return append(cloneStrings(descriptor.routeTokens), "--help"), false
	case "adopt-plan":
		return append(cloneStrings(descriptor.routeTokens), "--mode", "fresh", "--repo-root", t.TempDir()), true
	case "help":
		return []string{"help"}, false
	case "json-report-cli-adapter-source":
		return []string{"json-report-cli-adapter-source", "--language", "typescript"}, true
	case "native-evidence-guidance":
		return []string{"native-evidence-guidance"}, true
	case "next", "status":
		return append(cloneStrings(descriptor.routeTokens), "--repo-root", t.TempDir()), true
	case "repository-inventory":
		return append(cloneStrings(descriptor.routeTokens), "--repo-root", t.TempDir()), true
	case "stack-preset":
		return []string{"stack-preset", "--preset", "typescript_workspace"}, true
	default:
		panic("missing no-input command smoke args for " + descriptor.name)
	}
}

func assertCommandCoverageRoute(t *testing.T, command string, contractCommand cliContractCommand, route commandCoverageRoute) {
	t.Helper()
	if route.file == "" || route.kind == "" || route.rationale == "" || route.testName == "" {
		t.Fatalf("%s has incomplete coverage route: %#v", command, route)
	}
	if problem := route.semanticProofProblem(); problem != "" {
		t.Fatalf("%s has invalid semantic proof route metadata: %s", command, problem)
	}
	filePath := filepath.Join(repoRoot(t), route.file)
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("%s coverage route file %s is not readable: %v", command, route.file, err)
	}
	assertGoTestFunctionExists(t, command, filePath, route.testName)
	switch route.kind {
	case "routing_admission_smoke_nonclaim":
		if contractCommand.Input != "required" {
			t.Fatalf("%s uses required-input admission smoke but contract input=%s", command, contractCommand.Input)
		}
		if route.testName != "TestRequiredInputCommandsRejectMalformedCallerRecords" {
			t.Fatalf("%s required-input route points at unexpected test %s", command, route.testName)
		}
	case "direct_semantic_falsifier":
		if problem := routeSemanticOwnerProblem(command, route); problem != "" {
			t.Fatalf("%s direct semantic route is not owner-scoped: %s", command, problem)
		}
	case "package_level_falsifier":
		if problem := routeSemanticOwnerProblem(command, route); problem != "" {
			t.Fatalf("%s package-level semantic route is not owner-scoped: %s", command, problem)
		}
	default:
		t.Fatalf("%s uses unsupported coverage route kind %s", command, route.kind)
	}
}

func mustCommandCoverageInventory(t *testing.T) map[string]any {
	t.Helper()
	inventory, err := CommandCoverageInventory()
	if err != nil {
		t.Fatalf("CommandCoverageInventory() error = %v", err)
	}
	return inventory
}

func assertGoTestFunctionExists(t *testing.T, command string, filePath string, testName string) {
	t.Helper()
	if problem := goTestFunctionProblem(filePath, testName); problem != "" {
		t.Fatalf("%s coverage route %s is invalid: %s", command, testName, problem)
	}
}

func writeGoTestFixture(t *testing.T, source string) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "fixture_test.go")
	if err := os.WriteFile(filePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write Go test fixture: %v", err)
	}
	return filePath
}

func malformedInputExtraArgs(command string) []string {
	switch command {
	case "adopt-materialize-apply":
		return []string{
			"--expect-desired-state", "sha256:" + strings.Repeat("0", 64),
			"--expect-transaction", "sha256:" + strings.Repeat("1", 64),
			"--repo-root", ".",
		}
	case "adopt-materialize-plan":
		return []string{"--repo-root", "."}
	case "adoption-contract-envelope":
		return []string{"--mode", "workflow"}
	case "conformance-profile":
		return []string{"--verify"}
	case "pilot-admission":
		return []string{"--pilot", "first"}
	case "requirement-browser-server":
		return []string{"--view", "source"}
	case "requirement-context-compose":
		return []string{"--repo-root", "."}
	case "requirement-proof-resolver":
		return []string{"--empty-local-environment-policy"}
	case "requirement-proof-view":
		return []string{"--format", "json"}
	case "requirement-source-view":
		return []string{"--format", "json"}
	case "requirement-spec-tree-view":
		return []string{"--format", "json"}
	case "typescript-public-api-surfaces":
		return []string{"--repo-root", "."}
	default:
		return nil
	}
}
