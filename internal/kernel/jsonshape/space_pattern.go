package jsonshape

import (
	"fmt"
	"strings"
	"unicode"
)

// TrimSpacePatternClass projects the native Unicode whitespace inventory into
// an ECMAScript character class body without using JavaScript's different \s.
func TrimSpacePatternClass() string {
	var result strings.Builder
	for _, r := range trimSpaceCharacters() {
		fmt.Fprintf(&result, `\u%04x`, r)
	}
	return result.String()
}

func trimSpaceCharacters() string {
	var result strings.Builder
	for _, row := range unicode.White_Space.R16 {
		for r := uint32(row.Lo); r <= uint32(row.Hi); r += uint32(row.Stride) {
			result.WriteRune(rune(r))
		}
	}
	if len(unicode.White_Space.R32) != 0 {
		panic("structural whitespace projection requires supplementary escape support")
	}
	return result.String()
}

func NonBlankString() Shape {
	return WhitespaceStringGrammar(func(class string) string {
		return `[\s\S]*[^` + class + `][\s\S]*`
	})
}

// WhitespaceStringGrammar projects one grammar over the native whitespace set.
// The declaration receives a character-class body: literal runes for Go and
// ASCII ECMAScript escapes for the schema, since Go does not accept \u escapes.
func WhitespaceStringGrammar(body func(string) string) Shape {
	shape := StringGrammar(body(trimSpaceCharacters()))
	shape.node.text = body(TrimSpacePatternClass())
	return shape
}
