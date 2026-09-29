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
	for _, row := range unicode.White_Space.R16 {
		for r := uint32(row.Lo); r <= uint32(row.Hi); r += uint32(row.Stride) {
			fmt.Fprintf(&result, `\u%04x`, r)
		}
	}
	if len(unicode.White_Space.R32) != 0 {
		panic("structural whitespace projection requires supplementary escape support")
	}
	return result.String()
}
