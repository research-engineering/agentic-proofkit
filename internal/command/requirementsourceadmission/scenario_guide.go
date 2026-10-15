package requirementsourceadmission

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// ScenarioGuide teaches the optional typed scenario body owned by a grouped
// source; binding rows keep referencing the same stable scenario ID.
func ScenarioGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(scenarioGuide, "{{cli}}", renderer.DisplayCommand())
}

const scenarioGuide = `Scenario body guide:
  A scenario body is optional. Keep one editable copy of each scenario: put a
  body here only when the owner gives it portable meaning; otherwise keep the
  stable scenarioId beside the native test and in its binding rows. Never keep
  a second editable copy in test annotations, inventories or prose.

  The body below completes the scenarios array of the source at
  /requirementSources/0 in the template named by CLI authoring continuation.
  requirementIds lists every member requirement whose binding rows use that
  scenarioId; a binding row for another requirement is rejected. Text lists
  are sorted and unique except ordered actionSequence; observations must not
  overlap. Each declared parameter is referenced as ${name} and needs at least
  two examples whose EX- IDs bind every parameter. Use vocabularyRefs and
  nonClaimRefs only for TERM- and NCL- records declared in the same source.

Scenario body example (complete scenarios array for the example source):
` + "```json" + `
[{
  "scenarioId": "example.requests.empty",
  "requirementIds": ["REQ-EXAMPLE-001"],
  "parameters": ["request"],
  "preconditions": ["The request handler is running."],
  "actionSequence": ["Submit ${request} to the request handler."],
  "expectedObservations": ["The handler rejects ${request} with a validation error."],
  "forbiddenObservations": ["The handler accepts ${request}."],
  "examples": [
    {"exampleId": "EX-EMPTY-BODY", "values": {"request": "an empty body"}},
    {"exampleId": "EX-WHITESPACE-BODY", "values": {"request": "a whitespace-only body"}}
  ],
  "vocabularyRefs": [],
  "nonClaimRefs": []
}]
` + "```" + `

  {{cli}} requirement-source-admission --input <source>
  Admission and materialization preserve the body in canonical order. A body
  edit changes its member requirements' sourceReviewDigest; the semantic diff
  reports that change and the scenario's own entries. A scenario body is not a
  test, binding or execution claim.
`
