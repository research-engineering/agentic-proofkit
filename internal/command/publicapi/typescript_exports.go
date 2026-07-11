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
	for _, statement := range exportStatements(source) {
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
			if err := addTypeClauseExports(match[1], typeExports); err != nil {
				return nil, nil, err
			}
			continue
		}
		if match := namedExportPattern.FindStringSubmatch(statement); match != nil {
			if err := addNamedClauseExports(match[1], runtimeExports, typeExports); err != nil {
				return nil, nil, err
			}
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
		regexLiteral
	)
	masked := []byte(source)
	state := code
	escaped := false
	regexClass := false
	for index := 0; index < len(masked); index++ {
		current := source[index]
		next := byte(0)
		if index+1 < len(masked) {
			next = source[index+1]
		}
		switch state {
		case code:
			switch {
			case current == '/' && next == '/':
				masked[index], masked[index+1] = ' ', ' '
				index++
				state = lineComment
			case current == '/' && next == '*':
				masked[index], masked[index+1] = ' ', ' '
				index++
				state = blockComment
			case current == '\'':
				state = singleQuoted
			case current == '"':
				state = doubleQuoted
			case current == '`':
				masked[index] = ' '
				state = templateQuoted
			case current == '/' && looksLikeRegexLiteralStart(source, index):
				masked[index] = ' '
				state = regexLiteral
				regexClass = false
			}
		case lineComment:
			if current == '\n' {
				state = code
			} else {
				masked[index] = ' '
			}
		case blockComment:
			if current == '*' && next == '/' {
				masked[index], masked[index+1] = ' ', ' '
				index++
				state = code
			} else if current != '\n' {
				masked[index] = ' '
			}
		case singleQuoted, doubleQuoted:
			if current == '\n' && !escaped {
				state = code
				continue
			}
			closing := byte('\'')
			if state == doubleQuoted {
				closing = '"'
			}
			if escaped {
				masked[index] = ' '
				escaped = false
			} else if current == '\\' {
				masked[index] = ' '
				escaped = true
			} else if current == closing {
				state = code
			} else if current != '\n' {
				masked[index] = ' '
			}
		case templateQuoted:
			if current != '\n' {
				masked[index] = ' '
			}
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '`' {
				state = code
			}
		case regexLiteral:
			if current != '\n' {
				masked[index] = ' '
			}
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '[' {
				regexClass = true
			} else if current == ']' {
				regexClass = false
			} else if current == '/' && !regexClass {
				state = code
			}
		}
	}
	return string(masked)
}

func exportStatements(source string) []string {
	starts := topLevelExportStarts(source)
	statements := make([]string, 0, len(starts))
	for index, start := range starts {
		limit := len(source)
		if index+1 < len(starts) {
			limit = starts[index+1]
		}
		end := exportStatementEnd(source, start, limit)
		statement := strings.Join(strings.Fields(maskTypeScriptNonCode(source[start:end])), " ")
		if statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

func topLevelExportStarts(source string) []int {
	const (
		code = iota
		lineComment
		blockComment
		singleQuoted
		doubleQuoted
		templateQuoted
		regexLiteral
	)
	starts := []int{}
	state := code
	escaped := false
	regexClass := false
	braceDepth := 0
	bracketDepth := 0
	parenDepth := 0
	for index := 0; index < len(source); index++ {
		current := source[index]
		next := byte(0)
		if index+1 < len(source) {
			next = source[index+1]
		}
		switch state {
		case lineComment:
			if current == '\n' {
				state = code
			}
			continue
		case blockComment:
			if current == '*' && next == '/' {
				state = code
				index++
			}
			continue
		case singleQuoted, doubleQuoted, templateQuoted:
			closing := byte('\'')
			if state == doubleQuoted {
				closing = '"'
			} else if state == templateQuoted {
				closing = '`'
			}
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == closing {
				state = code
			}
			continue
		case regexLiteral:
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '[' {
				regexClass = true
			} else if current == ']' {
				regexClass = false
			} else if current == '/' && !regexClass {
				state = code
			}
			continue
		}
		switch {
		case current == '/' && next == '/':
			state = lineComment
			index++
			continue
		case current == '/' && next == '*':
			state = blockComment
			index++
			continue
		case current == '\'':
			state = singleQuoted
			continue
		case current == '"':
			state = doubleQuoted
			continue
		case current == '`':
			state = templateQuoted
			continue
		case current == '/' && looksLikeRegexLiteralStart(source, index):
			state = regexLiteral
			regexClass = false
			continue
		}
		switch current {
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		}
		if braceDepth != 0 || bracketDepth != 0 || parenDepth != 0 || !strings.HasPrefix(source[index:], "export") {
			continue
		}
		beforeOK := index == 0 || !isTypeScriptIdentifierByte(source[index-1]) && source[index-1] != '.'
		after := index + len("export")
		afterOK := after == len(source) || !isTypeScriptIdentifierByte(source[after])
		if beforeOK && afterOK {
			starts = append(starts, index)
			index = after - 1
		}
	}
	return starts
}

func exportStatementEnd(source string, start int, limit int) int {
	masked := maskTypeScriptNonCode(source[start:limit])
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	for index := 0; index < len(masked); index++ {
		switch masked[index] {
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
		case ';':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return start + index + 1
			}
		}
	}
	return limit
}

func isTypeScriptIdentifierByte(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func addTypeClauseExports(clause string, target map[string]struct{}) error {
	return addClauseExports(clause, nil, target, true)
}

func addNamedClauseExports(clause string, runtimeTarget map[string]struct{}, typeTarget map[string]struct{}) error {
	return addClauseExports(clause, runtimeTarget, typeTarget, false)
}

func addClauseExports(clause string, runtimeTarget map[string]struct{}, typeTarget map[string]struct{}, typeClause bool) error {
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
		if name == "default" {
			return fmt.Errorf("TypeScript public API entrypoints must not export a default alias")
		}
		if !identifierRegex.MatchString(name) {
			return fmt.Errorf("TypeScript public API re-exports must use identifier names")
		}
		if typeOnly {
			typeTarget[name] = struct{}{}
			continue
		}
		runtimeTarget[name] = struct{}{}
	}
	return nil
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
