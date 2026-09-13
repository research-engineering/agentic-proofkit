package proofreceiptadmission

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide explains receipt operands without producing execution evidence.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Proof receipt input guide:
  Start after the repository owner has approved the native witness and its
  execution policy. Design that check with native-evidence-guidance; obtain
  binding/source shapes with adopt materialize plan --help. Neither command
  executes your tests. Use a repository-owned runner; never invent a passing
  result, timestamp, digest or producer approval to fill this template.

  Fill every required null operand below from the selected run and its retained
  subjects. receiptSetId identifies this input set; receiptId identifies the run.
  For spec-proof-bundle-admission, proofPlanId equals schedulerPlanId,
  receiptKind equals a binding commandId (not a test framework name), and each
  witnessSelectors entry is a requirementId or scenarioId covered by that
  command. A native path::test selector belongs in the binding/inventory, not
  this logical selector list. Sort unique selectors and evidence paths; sort
  receipts by receiptId, artifactRefs by kind then path, and nonClaims lexicographically.

  Digests use sha256:<64 lowercase hex digits>. The consumer must define and
  retain one exact encoding for each structured subject; do not hash a filename
  or a passing report instead of its subject. Record that encoding/version and
  its source bytes in evidenceRefs so currentness can be checked independently:
    proofBindingDigest: the selected complete requirement-binding input.
    commandDigest: exact executable/argv and execution-root declaration.
    environmentDigest: the selected environment-class policy and observed context.
    preconditionDigest: the actual precondition observations, including blockers.
    witnessSelectorDigest: the complete ordered logical selector list.
    toolchainDigest: observed tool/runtime/platform identity.
    dependencyDigest and lockfileDigest: applicable dependency/lockfile subjects;
      null only when inapplicable under explicit consumer policy.
    artifactRefs[].sha256: exact retained artifact bytes at the declared path.
  sourceRevision names the observed source snapshot. A commit alone does not
  describe dirty files; retain their subject manifest and declare the limitation.
  Required digest subjects must exist even for a blocked/not_run attempt; an
  unknown prerequisite is a recorded observation, not a made-up successful run.

  startedAt/finishedAt are recorded UTC timestamps ending in Z, with finish not
  before start. status is passed, failed, blocked or not_run. passed requires
  exitCode 0; failed requires a nonzero exitCode; both require artifactRefs.
  blocked/not_run require exitCode null and an explanatory nonClaim. Record
  attempt times without implying the witness ran. Keep each negative status.
  All paths are repository-relative POSIX paths. Do not include secrets in
  subjects, paths, reports or diagnostics. Store sanitized evidence only when
  the consumer's policy preserves the claim; otherwise stop and escalate.

Receipt template (required null operands deliberately reject admission):
` + "```json\n" + `{
  "schemaVersion": 1,
  "receiptSetId": null,
  "receipts": [{
    "receiptId": null,
    "receiptKind": null,
    "proofPlanId": null,
    "sourceRevision": null,
    "proofBindingDigest": null,
    "commandDigest": null,
    "environmentClass": null,
    "environmentDigest": null,
    "preconditionDigest": null,
    "witnessSelectors": null,
    "witnessSelectorDigest": null,
    "toolchainDigest": null,
    "dependencyDigest": null,
    "lockfileDigest": null,
    "runnerIdentity": null,
    "runnerClass": null,
    "producerId": null,
    "producerAdmissionClass": "advisory",
    "provenanceRef": null,
    "startedAt": null,
    "finishedAt": null,
    "status": null,
    "exitCode": null,
    "artifactRefs": [],
    "evidenceRefs": [],
    "nonClaims": ["Local advisory metadata does not authenticate a producer or approve merge."]
  }],
  "nonClaims": ["Receipt admission checks shape, not execution, freshness or trust."]
}
` + "```\n" + `
  Each artifactRef is {"kind":"log","path":"<retained-path>","sha256":"<digest>"};
  kind may also be artifact or report. Replace both placeholders with observed
  values; retain failed-run logs as well as passed-run logs. evidenceRefs name
  supporting files, not inline evidence or authentication.

Admit the completed packet (use - for stdin):
  {{cli}} proof-receipt-admission --input <receipt-input>
  Preserve stdout, stderr and exit code separately. Exit 0 with state passed
  means the receipt structure is admissible, even when a receipt records failed
  or not_run. Inspect each receipt status; never relabel it from report.state.
  Do not use the report as a replacement for the original receipt input.
  Continue with spec-proof-bundle-admission --help to bind the admitted receipt
  to its requirement/scenario and scheduler inputs. receipt-currentness-scope
  and receipt-trust-class are separate checks, not implications of this pass.
  Leave advisory unchanged unless a separately admitted producer policy and
  provenance justify a stronger class; a provenance path alone is not trust.
`
