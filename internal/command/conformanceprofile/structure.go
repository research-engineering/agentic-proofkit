package conformanceprofile

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// profileIDPatternBody is the RuleID grammar restricted by lowerDashID.
const profileIDPatternBody = `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`

// failureOrdinalPattern is the %03d spelling of a positive one-based index.
const failureOrdinalPattern = `(?:00[1-9]|0[1-9][0-9]|[1-9][0-9]{2,})`

// InputShape describes the record admitted by admitInput for every mode.
func InputShape() jsonshape.Shape {
	text, id := inputTextShape(), ruleIDShape()
	texts := func(minimum int) jsonshape.Shape { return jsonshape.Array(text, minimum) }
	expected := jsonshape.RequiredObject(expectedManifestKeys, map[string]jsonshape.Shape{
		"authorityState": text, "contractId": text, "contractKind": text, "nonClaims": texts(1), "normalizationProfile": text, "sourceContract": text,
	})
	policy := jsonshape.ObjectFromKeys(policyKeys, map[string]jsonshape.Shape{
		"blockingStatuses": texts(1), "expectedManifest": expected, "failOnUnusedAllowedEnvironmentClass": jsonshape.Boolean(),
		"knownEnvironmentClasses": texts(1), "localEnvironmentClasses": texts(1),
	}, "failOnUnusedAllowedEnvironmentClass")
	profile := jsonshape.RequiredObject(profileKeys, map[string]jsonshape.Shape{
		"allowedEnvironmentClasses": texts(1), "nonClaims": texts(1), "optionalSurfaceIds": texts(0),
		"preconditionPolicy": preconditionPolicyShape(), "profileId": profileIDShape(), "purpose": text, "requiredSurfaceIds": texts(1),
	})
	manifest := jsonshape.RequiredObject(manifestKeys, map[string]jsonshape.Shape{
		"authorityState": text, "contractId": text, "contractKind": text, "nonClaims": texts(1), "normalizationProfile": text,
		"profiles": jsonshape.Array(profile, 0), "schemaVersion": jsonshape.IntegerLiteral(1), "sourceContract": text,
	})
	witness := func(role string) jsonshape.Shape {
		return jsonshape.RequiredObject(witnessRefKeys, map[string]jsonshape.Shape{
			"environmentClasses": texts(1), "resolutionOrderIndex": jsonshape.IntegerRange(0, compactproofcontract.MaxResolutionOrderIndex),
			"role": jsonshape.StringLiteral(role), "selector": text, "verifyCommands": texts(1), "witnessRouteId": digestRefShape(),
		})
	}
	falsification, positive := witness(compactproofcontract.FalsificationWitnessRole), witness(compactproofcontract.PositiveWitnessRole)
	binding := jsonshape.RequiredObject(bindingKeys, map[string]jsonshape.Shape{
		"bindingRecordId": digestRefShape(), "blockingStatus": id, "declaredMutationResistanceClaimId": id,
		"invariantRole": id, "ownedInvariant": id, "requiredEnvironmentClasses": texts(1), "requirementId": id,
		"scenarioId": scenarioShape(), "surfaceId": id, "verifyCommands": texts(1),
		// Exactly one witness per role, in either caller order.
		"witnessRefs": jsonshape.OneOf(jsonshape.Tuple(falsification, positive), jsonshape.Tuple(positive, falsification)),
	})
	surface := jsonshape.RequiredObject(surfaceKeys, map[string]jsonshape.Shape{
		"preconditionedEnvironmentClasses": texts(0), "requiredEnvironmentClasses": texts(1), "surfaceId": id,
	})
	proofContract := jsonshape.RequiredObject(proofContractKeys, map[string]jsonshape.Shape{
		"bindings": jsonshape.Array(binding, 0), "contractId": text, "declarationKind": jsonshape.StringLiteral(proofContractDeclarationKind),
		"schemaVersion": jsonshape.IntegerLiteral(2), "surfaces": jsonshape.Array(surface, 0),
	})
	return jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"manifest": manifest, "policy": policy, "profileId": text, "proofContract": proofContract, "schemaVersion": jsonshape.IntegerLiteral(2),
	}, "profileId")
}

func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	binding := schema["properties"].(map[string]any)["proofContract"].(map[string]any)["properties"].(map[string]any)["bindings"].(map[string]any)["items"].(map[string]any)
	scenario := binding["properties"].(map[string]any)["scenarioId"].(map[string]any)
	scenario["allOf"] = []any{map[string]any{"pattern": ScenarioBoundShape().JSONSchema()["pattern"]}}
	schema["description"] = "One record serves --list, --profile and --verify. Under --list and --profile a native admission refusal exits 1 with stderr and empty stdout; under --verify the same refusal becomes a failed verification report carrying the admission message, so this structure is the precondition for semantic verification rather than a --verify refusal predicate. All root, policy, manifest, profile, proof-contract, surface, binding and witness fields are required and nonnull except root profileId (optional nonnull text; the public CLI always selects the profile with --profile) and failOnUnusedAllowedEnvironmentClass (optional nonnull boolean, default true). Text trims Unicode whitespace, must be nonblank and contains no NUL. Policy, manifest, profile, surface-requirement, binding and witness lists are nonempty except optionalSurfaceIds and preconditionedEnvironmentClasses; manifest profiles, surfaces and bindings may be empty. Profile IDs are lowercase dash-separated RuleIDs and preconditionPolicy is a trimmed allow_preconditioned or local_only. Binding and witness route IDs are trimmed sha256 references; scenario IDs are trimmed surface_id::stable_anchor RuleID pairs whose components are each at most 256 bytes; every binding has exactly one falsification and one positive witness in either order. Native admission owns secret-like text, timestamp-like identifiers, already-sorted unique policy/manifest/profile lists after trimming, manifest equality with expectedManifest, local-within-known environment classes, required/optional surface disjointness, display-only commands, repository-relative witness selectors, scenario surface scoping, sorted unique surfaces and binding identities, binding surface references, canonical integer tokens and the v2 binding-record and witness-route identity digests. Commands are never executed."
	return schema
}

// ScenarioBoundShape bounds each identifier component of a structurally valid
// scoped scenario ID; RuleIDs cannot contain the "::" separator.
func ScenarioBoundShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		component := "[^" + space + "]{1," + strconv.Itoa(admit.MaxRuleIDBytes) + "}"
		return "[" + space + "]*" + component + "::" + component + "[" + space + "]*"
	})
}

func ListOutputShape() jsonshape.Shape {
	return jsonshape.Object(jsonshape.Required("profiles", jsonshape.Array(profileIDShape(), 0)))
}

func ListOutputStructure() map[string]any {
	schema := ListOutputShape().JSONSchema()
	schema["description"] = "--list projects every admitted manifest profileId in native byte order. The list has no schemaVersion member; duplicate profile IDs are listed, not refused, because --profile and --verify own duplicate rejection. An empty manifest yields an empty list. Admission refusal emits no list."
	return schema
}

func ProfileOutputShape() jsonshape.Shape {
	count, text := jsonshape.IntegerMinimum(0), outputTextShape()
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)), jsonshape.Required("profileId", profileIDShape()),
		jsonshape.Required("profileResolutionState", vocabularyShape(profileResolved, profileInvalid)),
		jsonshape.Required("commandExecutionState", jsonshape.StringLiteral(commandExecutionNotRun)),
		jsonshape.Required("purpose", text), jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("failures", jsonshape.Array(jsonshape.NonBlankString(), 0)),
		jsonshape.Required("environmentClasses", jsonshape.Array(text, 0)), jsonshape.Required("surfaces", jsonshape.Array(ruleIDShape(), 0)),
		jsonshape.Required("verifyCommands", jsonshape.Array(text, 0)),
		jsonshape.Required("bindingCount", count), jsonshape.Required("commandCount", count), jsonshape.Required("optionalSurfaceCount", count),
		jsonshape.Required("preconditionedBindingCount", count), jsonshape.Required("requiredSurfaceCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("requirementCount", count), jsonshape.Required("scenarioCount", count), jsonshape.Required("surfaceCount", count),
		jsonshape.Required("witnessMappingCount", count),
	)
}

func ProfileOutputStructure() map[string]any {
	schema := ProfileOutputShape().JSONSchema()
	schema["description"] = "JSON resolution of the profile selected by --profile. Resolved profiles have no failures and exit 0; invalid profiles list sorted unique failures and exit 1 with JSON stdout. --format markdown emits non-JSON text that this structure does not describe. Unknown or duplicate selected profiles refuse with stderr and empty stdout. Native Build owns count arithmetic over selected bindings (witnessMappingCount is twice bindingCount), sorted unique environmentClasses, surfaces and verifyCommands, failure text and resolution-state/failure/exit consistency. Commands are never executed; commandExecutionState is always not_run."
	return schema
}

func VerifyOutputShape() jsonshape.Shape {
	passed := report.RuleStructure(jsonshape.StringLiteral(resolvedRuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(resolvedRuleMessage), jsonshape.Tuple())
	failed := report.RuleStructure(jsonshape.StringGrammar(regexp.QuoteMeta(failureRuleIDPrefix)+failureOrdinalPattern),
		jsonshape.StringLiteral("failed"), jsonshape.NonBlankString(), jsonshape.Tuple())
	return report.Structure(1, reportKind, vocabularyShape("passed", "failed"),
		jsonshape.Object(jsonshape.Required("profileCount", jsonshape.IntegerMinimum(0))), jsonshape.Tuple(),
		jsonshape.OneOf(jsonshape.Tuple(passed), jsonshape.Array(failed, 1)))
}

func VerifyOutputStructure() map[string]any {
	schema := VerifyOutputShape().JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = map[string]any{"type": "string", "const": verificationReportID}
	claims := jsonshape.Array(outputTextShape(), 0).JSONSchema()
	delete(claims, "$schema")
	properties["nonClaims"] = claims
	schema["description"] = "Passed verification has exactly the resolved rule and exits 0. Failed verification exits 1 with one or more sequentially numbered failure rules: either the single native admission refusal message or the sorted unique profile failures. nonClaims are the admitted expectedManifest nonClaims, or empty after admission refusal; report and rule diagnostics are always empty. Native Build owns failure ordering and numbering, profileCount and state/rule/exit consistency. Verification does not execute commands, prove coverage or approve release."
	return schema
}

func ruleIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func profileIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(profileIDPatternBody, admit.MaxRuleIDBytes)
}

// Input text is admit.NonEmptyText without NUL; surrounding whitespace is trimmed.
func inputTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^\x00]*[^` + space + `\x00][^\x00]*`
	})
}

// Output text is the trimmed admitted value.
func outputTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^` + space + `\x00](?:[^\x00]*[^` + space + `\x00])?`
	})
}

// admit.SHA256Ref trims the reference and again after its sha256: prefix.
func digestRefShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[` + space + `]*sha256:[` + space + `]*[0-9a-f]{64}[` + space + `]*`
	})
}

func scenarioShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[` + space + `]*(?:` + admit.RuleIDPatternBody + `)::(?:` + admit.RuleIDPatternBody + `)[` + space + `]*`
	})
}

func preconditionPolicyShape() jsonshape.Shape {
	quoted := make([]string, 0, len(preconditionPolicies))
	for _, value := range preconditionPolicies {
		quoted = append(quoted, regexp.QuoteMeta(value))
	}
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[` + space + `]*(?:` + strings.Join(quoted, "|") + `)[` + space + `]*`
	})
}

func vocabularyShape(values ...string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}
