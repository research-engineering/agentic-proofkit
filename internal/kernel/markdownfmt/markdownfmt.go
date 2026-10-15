package markdownfmt

import "strings"

func Text(value string) string {
	return escapeMarkdownText(strings.Join(strings.Fields(value), " "))
}

func htmlText(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(value)
}

// CodeSpan renders value literally. CommonMark code spans cannot escape '<',
// '>' or '&', and Markdown output never emits those bytes raw, so such values
// (and the empty value, which has no code-span form) become escaped inline text.
// Line endings become spaces, as CommonMark code spans already render them.
func CodeSpan(value string) string {
	value = lineEndings.Replace(value)
	if value == "" || strings.ContainsAny(value, "<>&") {
		return literalText(value)
	}
	delimiter := strings.Repeat("`", longestBacktickRun(value)+1)
	if codeSpanStripsEdges(value) {
		value = " " + value + " "
	}
	return delimiter + value + delimiter
}

var lineEndings = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ")

// codeSpanStripsEdges reports whether CommonMark would merge an edge backtick
// into a delimiter or strip one edge space from each side of the content.
func codeSpanStripsEdges(value string) bool {
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") {
		return true
	}
	return strings.HasPrefix(value, " ") && strings.HasSuffix(value, " ") && strings.Trim(value, " ") != ""
}

// literalText escapes value as inline text; edge spaces and tabs become numeric
// references because CommonMark strips them from the start and end of a line.
func literalText(value string) string {
	escaped := escapeMarkdownText(value)
	rest := strings.TrimLeft(escaped, " \t")
	core := strings.TrimRight(rest, " \t")
	return edgeWhitespace.Replace(escaped[:len(escaped)-len(rest)]) + core + edgeWhitespace.Replace(rest[len(core):])
}

var edgeWhitespace = strings.NewReplacer(" ", "&#32;", "\t", "&#9;")

func CodeListOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, CodeSpan(value))
	}
	return strings.Join(parts, ", ")
}

func longestBacktickRun(value string) int {
	longest := 0
	current := 0
	for _, char := range value {
		if char == '`' {
			current++
			if current > longest {
				longest = current
			}
			continue
		}
		current = 0
	}
	return longest
}

func escapeMarkdownText(value string) string {
	value = htmlText(value)
	var builder strings.Builder
	builder.Grow(len(value))
	for _, char := range value {
		switch char {
		case '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|', '>', '~':
			builder.WriteRune('\\')
		}
		builder.WriteRune(char)
	}
	return builder.String()
}
