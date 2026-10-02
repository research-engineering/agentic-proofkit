package packageruntimedependency

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"admissibleLocations", "expectedDependencySpec", "expectedLockfileIntegrity", "expectedPackageName", "expectedPackageVersion", "nonClaims", "packageResolution", "reportId", "schemaVersion"}
var resolutionKeys = []string{"dependencySpec", "lockfileEntryPresent", "lockfileIntegrity", "packageName", "packageRoot", "packageVersion", "realPackageRoot", "resolvedEntryPoint"}
var locationKeys = []string{"expectedPackageRoot", "localWorkspaceRoot", "nodeModulesRoot"}

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	dependency := jsonshape.StringGrammar(`[^\x00\r\n]+`)
	name := jsonshape.StringGrammar(packageNamePattern.String())
	integrity := jsonshape.StringGrammar(lockfileIntegrityPattern.String())
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"admissibleLocations": jsonshape.ObjectFromKeys(locationKeys, map[string]jsonshape.Shape{
			"expectedPackageRoot": jsonshape.Nullable(text), "localWorkspaceRoot": jsonshape.Nullable(text), "nodeModulesRoot": jsonshape.Nullable(text),
		}, locationKeys...),
		"expectedDependencySpec": dependency, "expectedLockfileIntegrity": integrity,
		"expectedPackageName": name, "expectedPackageVersion": text,
		"nonClaims": jsonshape.Array(text, 0), "reportId": jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes),
		"schemaVersion": jsonshape.IntegerLiteral(1),
		"packageResolution": jsonshape.ObjectFromKeys(resolutionKeys, map[string]jsonshape.Shape{
			"dependencySpec": jsonshape.Nullable(dependency), "lockfileEntryPresent": jsonshape.Boolean(),
			"lockfileIntegrity": integrity, "packageName": name, "packageRoot": text, "packageVersion": text,
			"realPackageRoot": text, "resolvedEntryPoint": text,
		}, "dependencySpec"),
	}).JSONSchema()
	schema["description"] = "All root members are required. Resolution dependencySpec and all three admissibleLocations members are optional and nullable; absence equals null. Missing/null dependencySpec, false lockfileEntryPresent or empty admissibleLocations produce admitted failed reports, not admission errors. Package versions require exact SemVer 2.0.0 without a v-prefix. Text rejects outer whitespace and secret-like values; runtime paths normalize backslashes, repeated slashes and trailing slash, then reject empty, dot and parent segments without reading files. Integrity has syntactic sha256/384/512 base64 grammar only, not digest-length or authenticity verification. Input nonClaims may be empty and are sorted/deduplicated; collisions with builtin output claims remain duplicated. Canonical token spelling, IDs, privacy, SemVer and path normalization remain native."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	name := jsonshape.StringGrammar(packageNamePattern.String())
	boolean := jsonshape.Boolean()
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	mode := jsonshape.Enum(map[string]struct{}{"external_package": {}, "local_workspace": {}, "unadmitted_package": {}})
	locationShapes := make([]jsonshape.Shape, 0, 11)
	for _, diagnostic := range locationDiagnostics("", locationFacts{}) {
		value := boolean
		if diagnostic.Key == "mode" {
			value = mode
		}
		locationShapes = append(locationShapes, report.DiagnosticStructure(diagnostic.Key, value))
	}
	rule := func(suffix string, diagnostics ...jsonshape.Shape) jsonshape.Shape {
		return report.RuleStructure(jsonshape.StringLiteral(reportKind+"."+suffix), status, text, jsonshape.Tuple(diagnostics...))
	}
	schema := report.Structure(1, reportKind, status, jsonshape.Object(
		jsonshape.Required("accepted", boolean), jsonshape.Required("dependencySpecMatched", boolean),
		jsonshape.Required("expectedPackageName", name), jsonshape.Required("expectedPackageVersion", text),
		jsonshape.Required("failureCount", jsonshape.IntegerRange(0, 6)), jsonshape.Required("lockfileEntryPresent", boolean),
		jsonshape.Required("lockfileIntegrityMatched", boolean), jsonshape.Required("mode", mode),
		jsonshape.Required("packageIdentityMatched", boolean), jsonshape.Required("runtimeLocationAdmitted", boolean),
	), jsonshape.Tuple(locationShapes...), jsonshape.Tuple(
		rule("dependency-spec", report.DiagnosticStructure("dependencySpecMatched", boolean)),
		rule("lockfile-entry", report.DiagnosticStructure("lockfileEntryPresent", boolean), report.DiagnosticStructure("lockfileIntegrityMatched", boolean)),
		rule("package-identity", report.DiagnosticStructure("expectedPackageName", name), report.DiagnosticStructure("expectedPackageVersion", text)),
		rule("runtime-location", report.DiagnosticStructure("mode", mode)),
	)).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes).JSONSchema()
	claims := jsonshape.Array(text, len(standardNonClaims)).JSONSchema()
	contains := make([]any, 0, len(standardNonClaims))
	for _, claim := range standardNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	schema["description"] = "ReportId preserves reportId. The four rules and eleven top-level diagnostics have fixed positions. Counts, rule statuses, accepted and overall state derive from identity, dependency, integrity and location comparisons; false booleans are valid report data. Local-workspace classification dominates external-package classification. At most six independent failures exist. Sorted nonClaims include all three builtins; caller/builtin collisions are retained, so output uniqueness is not required. Structural validity does not prove comparison equality, actual package resolution, registry authentication, freshness or release readiness."
	return schema
}
