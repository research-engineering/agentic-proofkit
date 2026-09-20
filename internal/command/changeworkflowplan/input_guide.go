package changeworkflowplan

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide describes the consumer boundary; it grants no approval or IO authority.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Current-subject review input guide:
  This command checks declared workflow state and identities. It does not read
  artifactPath, discover dependencies, authenticate a reviewer or approve a change.
  A supplied digest is not proof that current files still have that content.

Consumer adapter steps (implement in the repository's change/check workflow):
  1. Read exact base/current inputs from an explicit bounded scope. Bind source
     namespace, requirement/scenario meaning, matched native witness/path/selector,
     assertion and helper inputs, command argv, environment/toolchain and receipt
     policy. Enumerate transitive semantic dependencies; omitted inputs cannot
     be repaired by hashing the declared subset again. Do not hash only IDs.
  2. Build one deterministic review subject per independently reviewable scope.
     Use canonical admitted semantics for structured records and exact bytes for
     native code unless a reviewed semantic normalization is available. Keep
     source provenance separately; only an owner-approved normalization can
     disregard a presentation change. Unknown equivalence requires review.
  3. Recompute the current subject before every checkpoint submission. Derive
     affected relations from the exact base/current records, including additions,
     removals, renames and shared many-to-many dependencies. Retain tombstone/base
     identities for removals; compare source-qualified pairs, not bare local IDs.
     Preserve unaffected confirmations. A test change requests upstream review,
     never an automatic specification rewrite. Unknown/missing dependencies block.
  4. Obtain the assessment digest from the actual retained owner review. Do not
     replace it with the new subject digest just to make admission pass. After a
     semantic change, request new review or update the affected owners. Register
     this adapter in a required consumer check; running it manually once does
     not establish automatic invalidation for future changes.

Review checkpoint template (null digests must be supplied):
` + "```json\n" + `{
  "schemaVersion": 1,
  "completedStageIds": [],
  "checkpoint": {
    "state": "review_passed",
    "subjectRefId": "example.subject",
    "subjectDigest": null,
    "assessmentSubjectDigest": null
  },
  "contextRefs": [{
    "refId": "example.authority",
    "refKind": "authority",
    "artifactPath": "review/authority.json",
    "subjectDigest": null,
    "dependencyRefIds": []
  }, {
    "refId": "example.subject",
    "refKind": "artifact",
    "artifactPath": "review/subject.json",
    "subjectDigest": null,
    "dependencyRefIds": []
  }],
  "governingAuthorityRefId": "example.authority",
  "requiredContextRefIds": []
}
` + "```\n" + `
  Replace example references and paths with admitted consumer facts; keep refs
  sorted and dependencies explicit. Digests use sha256:<64 lowercase hex digits>.
  Both subjectDigest slots must name the same current artifact; the independent
  assessmentSubjectDigest must match it. Bind authority to its own actual record.
  completedStageIds is the exact completed prefix, not permission to skip stages.
  This empty prefix reviews architecture; do not call it native verification.
  Use review_passed only for an actual review without unresolved findings.
  For a new subject awaiting review, use state ready_for_review and omit
  assessmentSubjectDigest; retain subjectRefId and its current subjectDigest.

  {{cli}} change plan --input <checkpoint>
  A stale assessment rejects admission. Matching stale caller-supplied digests
  can still agree: the consumer's actual-byte check must detect that substitution.
  An admitted accept_stage action and successorStateDelta remain a derived plan,
  not authenticated approval, execution or merge authority. Apply only that
  delta to the exact prior snapshot, preserve its other fields, and re-admit the
  merged snapshot. Never pass the output report itself as a workflow input.

  Qualify the adapter with an unchanged positive, each independently changed
  semantic operand, a stale assessment, a changed file with old supplied hashes,
  a cross-source substitution, an unaffected neighbor and a presentation-only
  admitted-record control. Include add/remove/rename and changed environment.
  No fixture count proves an arbitrary repository's dependency completeness.
`
