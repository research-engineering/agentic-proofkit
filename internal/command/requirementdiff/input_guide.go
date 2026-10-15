package requirementdiff

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide owns the base/current comparison request; context capture stays
// with requirement-context-compose.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Requirement semantic diff input guide:
  The diff compares admitted requirement and scenario fields of two retained
  contexts. It is not a text or Git diff and does not read files, decide proof
  freshness, execute witnesses or approve a change. Capture each context with:
    {{cli}} requirement-context-compose --help
  Retain baseContext before the change and currentContext after it as the
  complete compose stdout objects; never edit, merge or rebuild either one.

  query may be null for all requirements. To narrow it, supply an object with
  unique requirementIds and/or ownerIds and an optional maxChanges.
  Narrowing hides other changes; it never proves that they are unchanged.

Diff template (required null operands deliberately reject admission):
` + "```json" + `
{
  "schemaVersion": 3,
  "diffId": null,
  "baseContext": null,
  "currentContext": null,
  "query": null
}
` + "```" + `

  {{cli}} requirement-semantic-diff --input <diff-input>
  Each change names entityKind, entityId, changeClass and jsonPointer. A
  scenario-body edit appears as scenario entries under
  /requirementSources/<sourceId>/scenarios/<scenarioId> and as its member
  requirements' sourceReviewDigest change. changeCount 0 means no compared
  requirement or scenario field changed; binding, witness, test and command
  edits are outside this comparison. Compare their proof fragments with
  requirement-context-slice and re-check retained receipt subjects with
  receipt-currentness-scope before reusing earlier execution evidence.
`
