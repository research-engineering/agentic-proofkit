package adoptionmaterialization

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide owns the connected authoring example, not child admission policy.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Materialization input guide:
  Before materialization: the owner must review the requirement meanings and
  the agent must inspect the declared native test paths, selectors and commands.
  Source-only drafting and admission may precede native witness design; use
  /requirementSources/0 below without inventing tests or approval. These are
  materialization prerequisites, not prerequisites for reading the source shape.
  No package documentation is needed for this example. It is not an exhaustive
  schema and does not authorize writes, approve meaning or prove test execution.

  First obtain the source plan:
  {{cli}} adopt plan --repo-root <root> --mode <intent> --format json
  Choose fresh for owner-supplied intent, audit-from-code for untrusted code,
  or code-baseline only when the caller explicitly trusts the existing behavior.
  Replace sourcePlan: null below with that entire output object, not its planId,
  a report wrapper, file path or fabricated digest. Null deliberately fails
  admission. Keep the plan's trust declaration; changing a mode is an owner
  decision, not a way to make validation pass. This plan is routing context,
  not proof that the inspected code or witness is current.

  All other values below form one fictional, connected example. Replace them
  consistently with reviewed repository facts; never copy a fictional witness
  or passing result into a real inventory. Missing intent or witnesses means
  stop and ask the owner or use native-evidence-guidance to design the missing
  check. A declared_semantic_falsifier_route is a declaration, not an execution
  receipt. Run native checks separately under repository authority.

  Store your completed packet in a caller-selected scratch JSON file. Its
  requirementSources are requirement-source-admission inputs, not source reports.
  Binding and inventory record fields are raw owner inputs, not passed reports.
  Paths are repository-relative; stable IDs and ID lists must obey admission.
  Sort unique ID/path lists. Preserve identical requirementId, ownerId,
  claimLevel and nonClaims across the source and binding projection.
  The binding's specPath must equal its source's requirementsPath; the source
  does not have a specPath field.
  Each inventory entry's requirementRefs, witnessRefs, commandRefs and sourcePath
  must meet on a binding route. Select environmentClasses from actual repository
  policy; local-go here is an example, not an inferred default for your project.
  For multiple scenarios, add binding rows and tests, not duplicate requirements.
  The packet is the complete desired project record set, NOT an additive patch.
  In an existing project retain every still-required source and its connected
  binding/inventory rows; replacing shared records with one edited source alone
  can remove other sources from routing. Review removals as well as additions.

Connected request template (sourcePlan is the only runtime placeholder):
` + "```json\n" + `{
  "schemaVersion": 1,
  "requestKind": "proofkit.adoption-materialization-request",
  "requestId": "example.materialization",
  "projectId": "example.project",
  "sourcePlan": null,
  "requirementSources": [{
    "schemaVersion": 1,
    "sourceId": "example.requirements",
    "specPackagePath": "docs/specs/requests",
    "overviewPath": "docs/specs/requests/overview.md",
    "requirementsPath": "docs/specs/requests/requirements.v1.json",
    "nonClaims": ["Synthetic source; no product intent or execution is proven."],
    "requirements": [{
      "requirementId": "REQ-EXAMPLE-001",
      "ownerId": "example.backend",
      "invariant": "Empty requests are rejected.",
      "claimLevel": "blocking",
      "riskClass": "high",
      "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
      "nonClaimRefs": [],
      "nonClaims": ["Synthetic requirement; no native execution is proven."],
      "proofBindingRefs": ["proofkit/requirement-bindings.json"],
      "updatePolicy": {"requiresImpactDeclaration": true, "requiresProofBindingReview": true, "reviewOwnerId": "example.backend"}
    }]
  }],
  "requirementProofBinding": {
    "path": "proofkit/requirement-bindings.json",
    "record": {
      "schemaVersion": 1,
      "bindingId": "example.bindings",
      "requirements": [{
        "requirementId": "REQ-EXAMPLE-001",
        "ownerId": "example.backend",
        "claimLevel": "blocking",
        "proofState": "witness_backed",
        "specPath": "docs/specs/requests/requirements.v1.json",
        "nonClaims": ["Synthetic requirement; no native execution is proven."]
      }],
      "bindings": [{
        "requirementId": "REQ-EXAMPLE-001",
        "scenarioId": "example.requests.empty",
        "witnessId": "example.witness.empty",
        "witnessKind": "contract",
        "witnessPath": "src/request_test.go",
        "commandIds": ["example.test.requests"],
        "environmentClasses": ["local-go"]
      }],
      "witnessCommands": [{
        "commandId": "example.test.requests",
        "command": "go test ./src -run TestRejectEmptyInput",
        "environmentClasses": ["local-go"]
      }],
      "selection": {"changedPaths": [], "ownerIds": [], "requirementIds": []},
      "nonClaims": ["Synthetic binding; witness_backed declares a route, not a passing run."]
    }
  },
  "testEvidenceInventory": {
    "path": "proofkit/test-evidence-inventory.json",
    "record": {
      "schemaVersion": 1,
      "inventoryId": "example.inventory",
      "authority": "caller_owned_inventory",
      "entries": [{
        "testId": "example.test.empty",
        "ownerId": "example.backend",
        "sourcePath": "src/request_test.go",
        "selector": "src/request_test.go::TestRejectEmptyInput",
        "evidenceClass": "declared_semantic_falsifier_route",
        "requirementRefs": ["REQ-EXAMPLE-001"],
        "ownerInvariantRefs": [],
        "commandRefs": ["example.test.requests"],
        "witnessRefs": ["example.witness.empty"],
        "falsifier": {
          "falsifierId": "example.falsifier.empty",
          "negativeCaseId": "example.case.empty",
          "wrongImplementationClassId": "example.wrong.accept-empty",
          "dominanceGroup": "example.requests.empty",
          "supersedes": []
        },
        "oracle": {
          "oracleId": "example.oracle.empty",
          "oracleKind": "negative_exit_and_diagnostic",
          "expectedPublicOutcome": "The test fails when empty input is accepted.",
          "assertionSummary": "TestRejectEmptyInput asserts rejection; an accepting mutant must fail that assertion."
        },
        "nonClaims": ["Synthetic test route; mutation execution is not asserted."]
      }],
      "nonClaims": ["Synthetic inventory; no test execution or coverage is proven."]
    }
  },
  "nonClaims": ["Synthetic template; review scope, intent and witnesses before materialization."]
}
` + "```\n" + `
Validate the completed packet (replace <packet> with its scratch file path):
  {{cli}} requirement-source-admission --input <packet> --input-pointer /requirementSources/0
  {{cli}} requirement-bindings --input <packet> --input-pointer /requirementProofBinding/record
  {{cli}} test-evidence-inventory --input <packet> --input-pointer /testEvidenceInventory/record
  {{cli}} adopt materialize plan --input <packet> --repo-root <root>
  Child success requires exit 0 and state passed; the plan requires exit 0 and
  state ready. On rejection, repair the named input field and rerun admission;
  never replace a failed report with invented passed JSON. A sourcePlan failure
  requires a new adopt plan output, not hand-edited task text or hashes.
  If a parent error only says a child must pass, invoke that child directly
  with its pointer above to inspect its ruleResults and diagnostics. For more
  sources repeat requirement-source-admission for /requirementSources/<index>.

Before applying, review transaction.operations and manifest. Only requirement
  sources, the binding record, test inventory and project routing manifest are
  materialized. No test, overview, execution receipt or CI script is generated.
  Source and test path references do not prove that files exist or execute.
  Creating or changing those files requires separate repository authorization.

After explicit approval of the exact planned writes, pass the SAME packet:
  {{cli}} adopt materialize apply --input <packet> --repo-root <root> --expect-transaction <transaction.transactionId> --expect-desired-state <transaction.desiredStateId>
  Do not pass the plan output as the apply input. Copy both identities from
  the reviewed plan. If the target changes, replan and review; do not force it.
  Exit 0 and state passed confirms materialization only, not behavioral proof.
  Any non-passed result stops normal writes. For recovery_required or
  cleanup_required inspect {{cli}} adopt materialize recover --help; never
  delete a journal to retry. durability_unknown means writes may have applied
  but synchronization is not proven: preserve the receipt, inspect the target
  and recovery state, and escalate to the repository owner rather than claiming
  success, blindly retrying or deleting transaction evidence.
`
