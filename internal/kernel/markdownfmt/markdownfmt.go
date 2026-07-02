package markdownfmt

import "strings"

func Text(value string) string {
	return escapeMarkdownText(strings.Join(strings.Fields(value), " "))
}

func htmlText(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(value)
}

func CodeSpan(value string) string {
	delimiter := strings.Repeat("`", longestBacktickRun(value)+1)
	return delimiter + htmlText(value) + delimiter
}

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
		case '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|', '>':
			builder.WriteRune('\\')
		}
		builder.WriteRune(char)
	}
	return builder.String()
}
