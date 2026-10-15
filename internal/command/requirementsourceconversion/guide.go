package requirementsourceconversion

import "strings"

// Guide is the bounded command-help projection of the format, preservation
// and refusal contract.
func Guide() string {
	return strings.Join([]string{
		"Formats:",
		"  The input format is its admitted identity, never a flag or filename:",
		"  grouped is kind proofkit.requirement-source schemaVersion 2; flat is kind",
		"  proofkit.requirement-source-flat schemaVersion 1. The retired flat v1 source",
		"  (schemaVersion 1 without kind) and every other identity are refused.",
		"  --to flat exports a grouped source as one resolved record per requirement plus",
		"  the profile fieldIds and group profileId, statementStemBytes and requirementIds",
		"  that own each value, and basisDigest, the sha256 of the canonical grouped source.",
		"  --to grouped imports a flat document and requires --baseline <path>, the grouped",
		"  source whose canonical sha256 equals basisDigest. Requirement, group, profile,",
		"  field-owner and statement-stem coordinates must equal the baseline; values may",
		"  change, and a profile-owned field, the shared premises and the statement stem",
		"  must be identical in every member record.",
		"",
		"Preservation:",
		"  Every conversion admits its input into the one requirement-source model and emits",
		"  only from that model; the emission is re-admitted and must equal it in resolved",
		"  values, ownership layout and references. Nothing is inferred from equal values and",
		"  no loss is accepted. Input formatting and key order are not preserved.",
		"",
		"Output:",
		"  One JSON document on stdout, or --output <repo-relative path> publishes a new file",
		"  atomically; an existing path, or one entering .git or .agentic-proofkit at any",
		"  depth, is refused and left untouched. An emission larger than the CLI input",
		"  bound is refused, so every output can be read back. A refusal writes one",
		"  diagnostic to stderr and no output; a refused decoded input or baseline",
		"  document is named by a closed code and a JSON pointer or structural path,",
		"  and JSON decoding refusals (syntax, duplicate keys, the input size bound)",
		"  use the shared CLI diagnostics.",
		"  Proof bindings and other references are not migrated.",
		"",
	}, "\n")
}
