package receiptcurrentnessscope

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide explains caller-owned capture without claiming file discovery.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Receipt currentness input guide:
  Currentness compares caller-supplied identities. It does not read files,
  compute receipt age, authenticate a producer, execute tests or approve merge.
  First retain the original receipt input and the exact subjects it recorded:
    {{cli}} proof-receipt-admission --help
  Do not substitute that admission report for the receipt. Preserve receiptId;
  select requirementId and proofRouteRef from its admitted binding route, and
  obligationId/owner from the consumer's obligation policy. Check the qualified
  relation, not separate sets of IDs. This command cannot verify that mapping
  against an external receipt or detect deliberately invented equal digests.

  For every dependency relevant to reuse, supply a uniquely identified
  currentnessChecks entry. Copy recordedDigest from the corresponding receipt
  subject (binding, command, environment, precondition, selectors, toolchain,
  or applicable dependency/lockfile). Independently capture current bytes with
  the same encoding/version; calculate currentDigest from those actual bytes.
  Never copy the old digest into both fields to obtain a pass. If a required
  subject is unavailable, stop: this template cannot establish its currentness.
  Keep sanitized source bytes/encoding and evidenceRefs for independent replay.
  Do not claim whole-repository freshness from an incomplete dependency list.

  Every obligation needs nonempty currentnessChecks and scopeChecks. Check and
  obligation IDs must be unique; checkClass/scopeClass name consumer-owned rules.
  Choose scope admission from evidence: admitted_current_scope,
  not_admitted_current_scope, unknown_current_scope, or not_applicable.
  Include both recordedScopeDigest and currentScopeDigest keys. Admission allows
  null values, but null does not prove equal scope. This reuse recipe requires
  both observed digests for an equal-scope claim; otherwise use unknown scope
  or a separately justified consumer policy. Digests are sha256:<64 lowercase
  hex digits>. Paths are repository-relative; sort unique evidenceRefs and
  nonClaims. Every evidenceRefs and nonClaims array must be nonempty; fill it
  from retained evidence and actual limitations. Never include secrets.

Currentness template (required null operands deliberately reject admission):
` + "```json\n" + `{
  "schemaVersion": 1,
  "admissionId": null,
  "obligationReceipts": [{
    "obligationId": null,
    "requirementId": null,
    "proofRouteRef": null,
    "receiptId": null,
    "owner": null,
    "reason": null,
    "currentnessChecks": [{
      "checkId": null,
      "checkClass": null,
      "recordedDigest": null,
      "currentDigest": null,
      "evidenceRefs": null,
      "nonClaims": ["Consumer declarations require independent evidence."]
    }],
    "scopeChecks": [{
      "checkId": null,
      "scopeClass": null,
      "admissionState": null,
      "recordedScopeDigest": null,
      "currentScopeDigest": null,
      "reason": null,
      "evidenceRefs": null,
      "nonClaims": ["Consumer declarations require independent evidence."]
    }],
    "evidenceRefs": null,
    "nonClaims": ["Current subjects and scope are supplied by the consumer."]
  }],
  "nonClaims": ["Currentness is not producer authentication or merge approval."]
}
` + "```\n" + `
  Replace <currentness-input> with the completed packet path, or - for stdin:
  {{cli}} receipt-currentness-scope --input <currentness-input>
  Preserve stdout, stderr and exit independently. Malformed input exits1 with
  a diagnostic; stale or unknown/not-admitted scope exits1 with a failed JSON
  report. Inspect receiptCurrentnessScope diagnostics and ruleResults: digest
  mismatch yields stale_receipt; scope mismatch yields unknown_scope.
  An all-not_applicable scope can exit0 with skipped ruleResults: this is not
  current execution evidence. Even current inputs may describe a failed or
  not-run receipt; retain the original receipt status and separate trust policy.
  Restore recorded subjects to test recovery, or run fresh approved checks for
  intentionally changed subjects. Never replace historical evidence with
  fabricated success or treat this comparison as automatic filesystem capture.
`
