package publicapi

import (
	"regexp"
	"strings"
)

var literalEnumInitializer = regexp.MustCompile(`^(?:"[^"]*"|'[^']*'|[+-]?(?:0[xX][0-9A-Fa-f]+|[0-9]+(?:\.[0-9]+)?))$`)

func admitBoundedEnumInitializers(masked string) error {
	for index := 0; index+4 <= len(masked); index++ {
		if !strings.HasPrefix(masked[index:], "enum") || index > 0 && isASCIITypeScriptIdentifierByte(masked[index-1]) || index+4 < len(masked) && isASCIITypeScriptIdentifierByte(masked[index+4]) {
			continue
		}
		cursor := skipMaskedWhitespace(masked, index+4)
		if cursor >= len(masked) || !isASCIITypeScriptIdentifierStart(masked[cursor]) {
			return unsupportedTypeScriptSourceGrammar("enum declaration shape is not admitted")
		}
		for cursor < len(masked) && isASCIITypeScriptIdentifierByte(masked[cursor]) {
			cursor++
		}
		cursor = skipMaskedWhitespace(masked, cursor)
		if cursor >= len(masked) || masked[cursor] != '{' {
			return unsupportedTypeScriptSourceGrammar("enum declaration shape is not admitted")
		}
		bodyStart := cursor + 1
		depth := 1
		for cursor++; cursor < len(masked) && depth > 0; cursor++ {
			switch masked[cursor] {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth != 0 {
			return unsupportedTypeScriptSourceGrammar("enum declaration shape is not admitted")
		}
		for _, member := range strings.Split(masked[bodyStart:cursor-1], ",") {
			if equals := strings.IndexByte(member, '='); equals >= 0 {
				initializer := strings.TrimSpace(member[equals+1:])
				if !literalEnumInitializer.MatchString(initializer) {
					return unsupportedTypeScriptSourceGrammar("computed enum initializers require a native compiler witness")
				}
			}
		}
		index = cursor - 1
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
