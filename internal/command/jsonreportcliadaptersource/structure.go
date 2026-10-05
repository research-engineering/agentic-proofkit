package jsonreportcliadaptersource

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

func OutputStructure() map[string]any {
	symbols := make([]jsonshape.Shape, len(exportedSymbols))
	for index, value := range exportedSymbols {
		symbols[index] = jsonshape.StringLiteral(value)
	}
	claims := make([]jsonshape.Shape, len(nonClaims))
	for index, value := range nonClaims {
		claims[index] = jsonshape.StringLiteral(value)
	}
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("artifactKind", jsonshape.StringLiteral(artifactKind)),
		jsonshape.Required("generatorId", jsonshape.StringLiteral(TypeScriptGeneratorID)),
		jsonshape.Required("language", jsonshape.StringLiteral(LanguageTypeScript)),
		jsonshape.Required("format", jsonshape.StringLiteral(FormatJSON)),
		jsonshape.Required("sourceFileName", jsonshape.StringLiteral(sourceFileName)),
		jsonshape.Required("source", jsonshape.NonBlankString()),
		jsonshape.Required("sourceSha256", jsonshape.StringGrammar("sha256:[a-f0-9]{64}")),
		jsonshape.Required("exportedSymbols", jsonshape.Tuple(symbols...)),
		jsonshape.Required("summary", jsonshape.Object(
			jsonshape.Required("exportedSymbolCount", jsonshape.IntegerLiteral(int64(len(exportedSymbols)))),
			jsonshape.Required("lineCount", jsonshape.IntegerMinimum(1)),
			jsonshape.Required("publicContract", jsonshape.StringLiteral(publicContract)),
		)),
		jsonshape.Required("nonClaims", jsonshape.Tuple(claims...)),
	).JSONSchema()
	schema["description"] = "Successful TypeScript adapter bundle with fixed identity, ordered exported symbols and ordered nonClaims. Native generation owns source bytes, their SHA-256 and the source line count; JSON Schema cannot establish these dependent equalities or TypeScript behavior. Generated source is a local CLI adapter, not a package-root SDK, native witness, merge approval or rollout decision. Flag errors emit stderr without a JSON bundle."
	return schema
}
