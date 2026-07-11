package publicapi

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	namedExportPattern    = regexp.MustCompile(`^export\s+(\{[^}]+\})\s+from\s+["'][^"']+["'];?$`)
	typeExportPattern     = regexp.MustCompile(`^export\s+type\s+(\{[^}]+\})\s+from\s+["'][^"']+["'];?$`)
	runtimeDeclPattern    = regexp.MustCompile(`^export\s+(?:abstract\s+)?(?:async\s+)?(?:function|class|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)
	typeDeclPattern       = regexp.MustCompile(`^export\s+(?:interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)
	varDeclPattern        = regexp.MustCompile(`^export\s+(?:const|let|var)\s+(.+?);?$`)
	exportClauseNameRegex = regexp.MustCompile(`\bas\s+([A-Za-z_$][A-Za-z0-9_$]*)$`)
	identifierRegex       = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
)

func CollectExports(source string) ([]string, []string, error) {
	runtimeExports := map[string]struct{}{}
	typeExports := map[string]struct{}{}
	for _, statement := range exportStatements(maskTypeScriptNonCode(source)) {
		if strings.HasPrefix(statement, "export *") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use export *")
		}
		if strings.HasPrefix(statement, "export default") || strings.HasPrefix(statement, "export =") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use default exports")
		}
		if strings.HasPrefix(statement, "export declare") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use ambient declare exports")
		}
		if match := typeExportPattern.FindStringSubmatch(statement); match != nil {
			addTypeClauseExports(match[1], typeExports)
			continue
		}
		if match := namedExportPattern.FindStringSubmatch(statement); match != nil {
			addNamedClauseExports(match[1], runtimeExports, typeExports)
			continue
		}
		if match := runtimeDeclPattern.FindStringSubmatch(statement); match != nil {
			runtimeExports[match[1]] = struct{}{}
			continue
		}
		if match := typeDeclPattern.FindStringSubmatch(statement); match != nil {
			typeExports[match[1]] = struct{}{}
			continue
		}
		if match := varDeclPattern.FindStringSubmatch(statement); match != nil {
			names, err := variableExportNames(match[1])
			if err != nil {
				return nil, nil, err
			}
			for _, name := range names {
				runtimeExports[name] = struct{}{}
			}
			continue
		}
		return nil, nil, fmt.Errorf("unsupported public export statement")
	}
	return sortedSet(runtimeExports), sortedSet(typeExports), nil
}

func maskTypeScriptNonCode(source string) string {
	const (
		code = iota
		lineComment
		blockComment
		singleQuoted
		doubleQuoted
		templateQuoted
	)
	runes := []rune(source)
	state := code
	escaped := false
	maskQuotedContent := false
	for index := 0; index < len(runes); index++ {
		current := runes[index]
		next := rune(0)
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		switch state {
		case code:
			switch {
			case current == '/' && next == '/':
				runes[index], runes[index+1] = ' ', ' '
				index++
				state = lineComment
			case current == '/' && next == '*':
				runes[index], runes[index+1] = ' ', ' '
				index++
				state = blockComment
			case current == '\'':
				maskQuotedContent = false
				state = singleQuoted
			case current == '"':
				maskQuotedContent = false
				state = doubleQuoted
			case current == '`':
				runes[index] = ' '
				state = templateQuoted
			}
		case lineComment:
			if current == '\n' {
				state = code
			} else {
				runes[index] = ' '
			}
		case blockComment:
			if current == '*' && next == '/' {
				runes[index], runes[index+1] = ' ', ' '
				index++
				state = code
			} else if current != '\n' {
				runes[index] = ' '
			}
		case singleQuoted, doubleQuoted, templateQuoted:
			if current == '\n' && state != templateQuoted {
				if escaped {
					escaped = false
					maskQuotedContent = true
					continue
				}
				state = code
				continue
			}
			closing := rune('\'')
			if state == doubleQuoted {
				closing = '"'
			} else if state == templateQuoted {
				closing = '`'
			}
			if current != '\n' && (state == templateQuoted || maskQuotedContent) {
				runes[index] = ' '
			}
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == closing {
				state = code
				maskQuotedContent = false
			}
		}
	}
	return string(runes)
}

func exportStatements(source string) []string {
	statements := []string{}
	pending := []string{}
	for _, rawLine := range strings.Split(source, "\n") {
		line := strings.TrimSpace(rawLine)
		if len(pending) > 0 {
			pending = append(pending, line)
			if strings.Contains(line, ";") {
				statements = append(statements, strings.Join(pending, " "))
				pending = nil
			}
			continue
		}
		if !strings.HasPrefix(line, "export ") && line != "export" {
			continue
		}
		if startsMultilineReexport(line) && !strings.Contains(line, ";") {
			pending = append(pending, line)
			continue
		}
		statements = append(statements, line)
	}
	if len(pending) > 0 {
		statements = append(statements, strings.Join(pending, " "))
	}
	return statements
}

func startsMultilineReexport(line string) bool {
	return strings.HasPrefix(line, "export {") || strings.HasPrefix(line, "export type {")
}

func addTypeClauseExports(clause string, target map[string]struct{}) {
	addClauseExports(clause, nil, target, true)
}

func addNamedClauseExports(clause string, runtimeTarget map[string]struct{}, typeTarget map[string]struct{}) {
	addClauseExports(clause, runtimeTarget, typeTarget, false)
}

func addClauseExports(clause string, runtimeTarget map[string]struct{}, typeTarget map[string]struct{}, typeClause bool) {
	body := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(clause), "{"), "}")
	for _, rawPart := range strings.Split(body, ",") {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		typeOnly := typeClause
		if isInlineTypeOnlyReexport(part) {
			typeOnly = true
			part = strings.TrimSpace(strings.TrimPrefix(part, "type "))
		}
		name := part
		if match := exportClauseNameRegex.FindStringSubmatch(part); match != nil {
			name = match[1]
		}
		if typeOnly {
			typeTarget[name] = struct{}{}
			continue
		}
		runtimeTarget[name] = struct{}{}
	}
}

func isInlineTypeOnlyReexport(part string) bool {
	if !strings.HasPrefix(part, "type ") {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(part, "type "))
	return rest != "" && !strings.HasPrefix(rest, "as ")
}

func variableExportNames(declarations string) ([]string, error) {
	names := []string{}
	parts, err := splitTopLevelComma(declarations)
	if err != nil {
		return nil, err
	}
	for _, rawPart := range parts {
		part := strings.TrimSpace(rawPart)
		if equals := strings.Index(part, "="); equals >= 0 {
			part = strings.TrimSpace(part[:equals])
		}
		if colon := strings.Index(part, ":"); colon >= 0 {
			part = strings.TrimSpace(part[:colon])
		}
		if !identifierRegex.MatchString(part) {
			return nil, fmt.Errorf("TypeScript public API variable exports must use identifier declarations")
		}
		names = append(names, part)
	}
	return names, nil
}

func splitTopLevelComma(value string) ([]string, error) {
	parts := []string{}
	start := 0
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	angleDepth := 0
	var quote rune
	escaped := false
	inRegex := false
	inRegexClass := false
	inInitializer := false
	for index, char := range value {
		if inRegex {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == '[' {
				inRegexClass = true
				continue
			}
			if char == ']' && inRegexClass {
				inRegexClass = false
				continue
			}
			if char == '/' && !inRegexClass {
				inRegex = false
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			quote = char
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '=':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 {
				inInitializer = true
			}
		case '<':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && (!inInitializer || looksLikeTypeArgumentStart(value, index)) {
				angleDepth++
			}
		case '>':
			if angleDepth > 0 {
				angleDepth--
			}
		case '/':
			if inInitializer && looksLikeRegexLiteralStart(value, index) {
				inRegex = true
				inRegexClass = false
			}
		case ',':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 {
				parts = append(parts, value[start:index])
				start = index + len(string(char))
				inInitializer = false
			}
		}
	}
	if quote != 0 || inRegex || inRegexClass {
		return nil, fmt.Errorf("TypeScript public API variable exports must not contain unterminated literals")
	}
	parts = append(parts, value[start:])
	return parts, nil
}

func looksLikeRegexLiteralStart(value string, start int) bool {
	for index := start - 1; index >= 0; index-- {
		switch value[index] {
		case ' ', '\t', '\n', '\r':
			continue
		case '=', '(', '[', '{', ',', ':', ';', '!', '&', '|', '?':
			return true
		case '>':
			return index > 0 && value[index-1] == '='
		default:
			return false
		}
	}
	return true
}

func looksLikeTypeArgumentStart(value string, start int) bool {
	depth := 0
	var quote rune
	escaped := false
	for index, char := range value[start:] {
		absolute := start + index
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			quote = char
		case '<':
			depth++
		case '>':
			if depth == 0 {
				return false
			}
			depth--
			if depth == 0 {
				next := nextNonSpaceRune(value[absolute+len(string(char)):])
				return next == '(' || next == '[' || next == '.' || next == ',' || next == ';'
			}
		case ';':
			if depth == 0 {
				return false
			}
		}
	}
	return false
}

func nextNonSpaceRune(value string) rune {
	for _, char := range value {
		if char != ' ' && char != '\t' && char != '\n' && char != '\r' {
			return char
		}
	}
	return 0
}
