package registryconsumerinputcompose

import (
	"regexp"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputFields = []string{"compositionId", "consumerId", "dependencyName", "dependencySpec", "frozenInstall", "install", "nonClaims", "packageName", "packageVersion", "preconditions", "registryMetadata", "registryPackProof", "registryUrl", "releaseAuthorityInput", "releaseAuthorityReport", "rollback", "rollbackVersionPin", "schemaVersion", "smoke"}
var metadataFields = []string{"packageName", "packageVersion", "tarballFileName", "tarballIntegrity", "tarballShasum"}
var packProofFields = []string{"integrityMatches", "nameMatches", "shasumMatches", "versionMatches"}
var lockFields = []string{"dependencySpec", "lockContainsPackage", "lockUsesWorkspace"}
var smokeFields = []string{"binarySmokeOutputSha256", "cliWitnessPlanOutputSha256"}
var releaseReportFields = []string{"outputSha256", "reportKind", "state"}
var rollbackFields = []string{"lockContainsPackage"}
var preconditionFields = []string{"preconditionId", "reason", "state"}
var preconditionStates = map[string]struct{}{"available": {}, "unavailable": {}}

const preconditionRuleID = "proofkit.registry-consumer-proof-input-compose.preconditions"
const acceptedRuleID = "proofkit.registry-consumer-proof-input-compose.accepted"
const acceptedMessage = "registry-consumer input composition is accepted by registry-consumer"
const failureRulePrefix = "proofkit.registry-consumer-proof-input-compose.failure."

func InputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	fields := map[string]jsonshape.Shape{}
	for _, name := range inputFields {
		fields[name] = text
	}
	fields["schemaVersion"], fields["compositionId"], fields["consumerId"] = jsonshape.IntegerLiteral(1), id, id
	fields["nonClaims"] = jsonshape.Array(text, 0)
	fields["registryMetadata"] = jsonshape.ObjectFromKeys(metadataFields, map[string]jsonshape.Shape{
		"packageName": text, "packageVersion": text, "tarballFileName": text, "tarballIntegrity": text, "tarballShasum": text,
	})
	fields["registryPackProof"] = jsonshape.ObjectFromKeys(packProofFields, map[string]jsonshape.Shape{
		"integrityMatches": jsonshape.Boolean(), "nameMatches": jsonshape.Boolean(), "shasumMatches": jsonshape.Boolean(), "versionMatches": jsonshape.Boolean(),
	})
	lock := jsonshape.ObjectFromKeys(lockFields, map[string]jsonshape.Shape{"dependencySpec": text, "lockContainsPackage": jsonshape.Boolean(), "lockUsesWorkspace": jsonshape.Boolean()})
	fields["install"], fields["frozenInstall"] = lock, lock
	fields["smoke"] = jsonshape.ObjectFromKeys(smokeFields, map[string]jsonshape.Shape{"binarySmokeOutputSha256": text, "cliWitnessPlanOutputSha256": text})
	fields["releaseAuthorityReport"] = jsonshape.ObjectFromKeys(releaseReportFields, map[string]jsonshape.Shape{"outputSha256": text, "reportKind": text, "state": text})
	fields["rollback"] = jsonshape.ObjectFromKeys(rollbackFields, map[string]jsonshape.Shape{"lockContainsPackage": jsonshape.Boolean()})
	fields["preconditions"] = jsonshape.Array(jsonshape.ObjectFromKeys(preconditionFields, map[string]jsonshape.Shape{"preconditionId": id, "reason": text, "state": jsonshape.Enum(preconditionStates)}), 1)
	fields["releaseAuthorityInput"] = jsonshape.Null()
	schema := jsonshape.ObjectFromKeys(inputFields, fields, "releaseAuthorityInput").JSONSchema()
	schema["properties"].(map[string]any)["releaseAuthorityInput"] = map[string]any{}
	schema["description"] = "Header1 and eighteen fields other than releaseAuthorityInput are required. releaseAuthorityInput is optional arbitrary JSON: child owner rejection becomes failed-report evidence. NonClaims may be empty; preconditions is nonempty with raw boundedASCII IDs and exact available/unavailable states. Native admission owns sorted unique precondition IDs/nonClaims, package/version/HTTPS/tarball/rollback grammar, lowercase SHA256 smoke/report fields, canonical numeric tokens and privacy. Missing members of the seven required precondition IDs are evaluation failures, while unavailable members block; blockers dominate other semantic failures. Declaration acceptance does not execute package managers or authenticate producers."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	count := jsonshape.IntegerMinimum(0)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	precondition := report.RuleStructure(jsonshape.StringLiteral(preconditionRuleID), jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "blocked": {}}), text, jsonshape.Tuple())
	accepted := report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(acceptedMessage), jsonshape.Tuple())
	failure := report.RuleStructure(jsonshape.StringGrammar(regexp.QuoteMeta(failureRulePrefix)+`[0-9]{3,}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple())
	rules := jsonshape.Array(failure, 1).JSONSchema()
	rules["prefixItems"] = []any{precondition.JSONSchema()}
	schema := jsonshape.Object(
		jsonshape.Required("compositionId", id), jsonshape.Required("compositionKind", jsonshape.StringLiteral(compositionKind)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, len(standardNonClaims))), jsonshape.Required("registryConsumerInput", jsonshape.Null()),
		jsonshape.Required("ruleResults", jsonshape.Null()), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", jsonshape.Enum(map[string]struct{}{"passed": {}, "blocked": {}, "failed": {}})),
		jsonshape.Required("summary", jsonshape.Object(jsonshape.Required("blockedPreconditionCount", count), jsonshape.Required("dependencySpec", text),
			jsonshape.Required("failureCount", count), jsonshape.Required("packageName", text), jsonshape.Required("packageVersion", text), jsonshape.Required("registryUrl", text))),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["ruleResults"] = map[string]any{"oneOf": []any{jsonshape.Tuple(precondition, accepted).JSONSchema(), rules}}
	properties["registryConsumerInput"] = map[string]any{"oneOf": []any{jsonshape.Null().JSONSchema(), MaterializedInputStructure()}}
	schema["description"] = "Fixed composition identity/header1 and all eight root fields, six summary fields. Rules begin with the fixed preconditions rule. With no blockers and no failures outside the precondition class, a fixed accepted rule follows, even when missing preconditions make overall state failed. Otherwise sequential non-precondition failure rules follow (possibly none). Accepted-rule presence alone proves neither passed composition nor final child admission. registryConsumerInput is required nullable; when materialized it uses the registry consumer owner's input structure with releaseAuthorityInput required and refined to the admitted release-authority input that a passed composition carries. Native Build materializes it only for passed composition after registryconsumer.Build passes, prioritizes blocked over failed, and owns counter/rule/state relations. Builtin/caller nonClaims are sorted and deduplicated. No consumer execution, registry access, freshness or merge/release/readiness approval."
	return schema
}

// MaterializedInputStructure refines the registry consumer owner's input
// structure to the registryConsumerInput that Build materializes. Build emits
// it only for a passed composition, so releaseAuthorityInput is always the
// admitted release-authority input that releaseAuthorityFailures accepted:
// header3, channel registry_release, rolloutClaim false, and non-null
// registryAuthority and package publishConfigRegistry. Other members keep the
// owner structure; the owner's caller-input description is replaced because
// its optional arbitrary releaseAuthorityInput does not describe this output.
func MaterializedInputStructure() map[string]any {
	schema := registryconsumer.InputStructure()
	input := schema["properties"].(map[string]any)["input"].(map[string]any)
	input["properties"].(map[string]any)["releaseAuthorityInput"] = materializedReleaseAuthorityStructure()
	input["required"] = withRequired(input["required"].([]any), "releaseAuthorityInput")
	schema["description"] = "Materialized only for a passed composition. The registry consumer owner's input structure, except that inner releaseAuthorityInput is required and is the admitted release-authority input: header3, channel registry_release, rolloutClaim false, a non-null registryAuthority and a present non-null package publishConfigRegistry. Native Build emits it only after registryconsumer.Build passes on it."
	return schema
}

func materializedReleaseAuthorityStructure() map[string]any {
	schema, err := releaseauthority.InputStructure(3)
	if err != nil {
		panic("invalid release-authority structure for composed registry consumer input")
	}
	delete(schema, "$schema")
	properties := schema["properties"].(map[string]any)
	properties["channel"] = subschema(jsonshape.StringLiteral(string(releasechannel.RegistryRelease)))
	properties["rolloutClaim"] = subschema(jsonshape.BooleanLiteral(false))
	properties["registryAuthority"] = nonNullable(properties["registryAuthority"])
	releasePackage := properties["package"].(map[string]any)
	packageProperties := releasePackage["properties"].(map[string]any)
	packageProperties["publishConfigRegistry"] = nonNullable(packageProperties["publishConfigRegistry"])
	releasePackage["required"] = withRequired(releasePackage["required"].([]any), "publishConfigRegistry")
	schema["description"] = "Admitted release-authority input re-serialized by a passed composition: header3, channel registry_release, rolloutClaim false, a non-null registryAuthority and a present non-null package publishConfigRegistry. Other members keep the release-authority input structure; release-authority evaluation owns the remaining channel, package, consumer and publisher relations."
	return schema
}

func subschema(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}

// nonNullable removes the null alternative that jsonshape.Nullable projects.
func nonNullable(value any) map[string]any {
	schema, ok := value.(map[string]any)
	if !ok || len(schema) != 1 {
		panic("composed registry consumer input expects a nullable owner member")
	}
	alternatives, ok := schema["anyOf"].([]any)
	if !ok || len(alternatives) != 2 {
		panic("composed registry consumer input expects a nullable owner member")
	}
	if null, ok := alternatives[0].(map[string]any); !ok || len(null) != 1 || null["type"] != "null" {
		panic("composed registry consumer input expects a nullable owner member")
	}
	member, ok := alternatives[1].(map[string]any)
	if !ok {
		panic("composed registry consumer input expects a nullable owner member")
	}
	return member
}

func withRequired(required []any, name string) []any {
	if slices.Contains(required, any(name)) {
		panic("composed registry consumer input member is already required")
	}
	result := append(slices.Clone(required), name)
	slices.SortFunc(result, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	return result
}
