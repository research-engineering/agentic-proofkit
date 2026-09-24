package publicapi

import "strings"

const maxStringFoldEstimateBytes uint64 = 64 << 20

func admitStringFoldEstimate(scan typeScriptLexicalScan) error {
	if scan.plusTokens != 0 && scan.literalBytes > maxStringFoldEstimateBytes/scan.plusTokens {
		return unsupportedTypeScriptSourceGrammar("string-fold work estimate exceeds 64 MiB")
	}
	return nil
}

func admitNoExpandingDeclarations(masked string) error {
	for index := 0; index < len(masked); index++ {
		if index > 0 && isASCIITypeScriptIdentifierByte(masked[index-1]) {
			continue
		}
		for _, keyword := range []string{"enum", "namespace"} {
			if !strings.HasPrefix(masked[index:], keyword) {
				continue
			}
			if hasTypeScriptMemberAccessPrefix(masked, index) {
				continue
			}
			end := index + len(keyword)
			if end < len(masked) && isASCIITypeScriptIdentifierByte(masked[end]) {
				continue
			}
			cursor := skipMaskedWhitespace(masked, end)
			if cursor >= len(masked) || !isASCIITypeScriptIdentifierStart(masked[cursor]) {
				continue
			}
			for cursor < len(masked) && isASCIITypeScriptIdentifierByte(masked[cursor]) {
				cursor++
			}
			cursor = skipMaskedWhitespace(masked, cursor)
			if cursor < len(masked) && (masked[cursor] == '{' || keyword == "namespace" && masked[cursor] == '.') {
				return unsupportedTypeScriptSourceGrammar(keyword + " declarations are not admitted without a native compiler witness")
			}
		}
	}
	return nil
}

func skipMaskedWhitespace(source string, index int) int {
	for index < len(source) && strings.ContainsRune(" \t\r\n\v\f", rune(source[index])) {
		index++
	}
	return index
}

func isASCIITypeScriptIdentifierStart(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}
