package publicapi

import (
	"fmt"
	"regexp"
	"strings"
)

const maxGenericAngleNesting = 128

var (
	namedExportPattern     = regexp.MustCompile(`^export[[:space:]]+(\{[^}]+\})[[:space:]]+from[[:space:]]+["'][^"']+["']`)
	typeExportPattern      = regexp.MustCompile(`^export[[:space:]]+type[[:space:]]+(\{[^}]+\})[[:space:]]+from[[:space:]]+["'][^"']+["']`)
	runtimeDeclPattern     = regexp.MustCompile(`^export[[:space:]]+(?:abstract[[:space:]]+)?(?:async[[:space:]]+)?(?:function|class)[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)(?:[[:space:]]|[({<;=]|$)`)
	typeDeclPattern        = regexp.MustCompile(`^export[[:space:]]+(interface|type)[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)(?:[[:space:]]|[({<;=]|$)`)
	varDeclStartPattern    = regexp.MustCompile(`^export[[:space:]]+(?:const|let|var)[[:space:]]+`)
	exportClauseNameRegex  = regexp.MustCompile(`\bas[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)$`)
	identifierRegex        = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	commonJSBindingPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$.])(?:exports|module)(?:$|[^A-Za-z0-9_$])`)
	genericTypePosition    = regexp.MustCompile(`^export[[:space:]]+(?:(?:const|let|var)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*:|type[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=)[[:space:]]*$`)
	typeAliasPrefix        = regexp.MustCompile(`^export[[:space:]]+type[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=`)
	erasedInterfaceName    = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])interface[[:space:]]+(as|satisfies)[[:space:]]*(?:\{|<|extends[[:space:]])`)
	erasedTypeAliasName    = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])type[[:space:]]+(as)[[:space:]]*=`)
)

func CollectExports(source string) ([]string, []string, error) {
	return collectExportsWithExtension(source, ".ts")
}

func collectExportsWithExtension(source string, extension string) ([]string, []string, error) {
	extension = strings.ToLower(extension)
	scan, err := scanTypeScriptSource(source)
	if err != nil {
		return nil, nil, err
	}
	if commonJSBindingPattern.MatchString(scan.masked) {
		return nil, nil, unsupportedTypeScriptSourceGrammar("CommonJS binding identifiers are not admitted")
	}
	if err := admitNoExpandingDeclarations(scan.masked); err != nil {
		return nil, nil, err
	}
	if err := admitGenericAngleSyntax(scan, extension); err != nil {
		return nil, nil, err
	}
	runtimeExports, err := collectRuntimeExports(runtimeParserSource(source, scan), extension)
	if err != nil {
		return nil, nil, err
	}
	typeExports := map[string]struct{}{}
	for _, start := range scan.topLevelExportOffsets {
		statement := scan.masked[start:]
		if strings.HasPrefix(statement, "export *") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use export *")
		}
		if strings.HasPrefix(statement, "export default") || strings.HasPrefix(statement, "export =") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use default exports")
		}
		if strings.HasPrefix(statement, "export declare") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use ambient declare exports")
		}
		if match := typeExportPattern.FindStringSubmatchIndex(statement); match != nil {
			if err := admitTypeReexportAttributes(source[start+match[1]:], true); err != nil {
				return nil, nil, err
			}
			if err := addTypeClauseExports(statement[match[2]:match[3]], typeExports); err != nil {
				return nil, nil, err
			}
			continue
		}
		if match := namedExportPattern.FindStringSubmatchIndex(statement); match != nil {
			if err := admitTypeReexportAttributes(source[start+match[1]:], false); err != nil {
				return nil, nil, err
			}
			if err := addNamedClauseTypeExports(statement[match[2]:match[3]], typeExports); err != nil {
				return nil, nil, err
			}
			continue
		}
		if runtimeDeclPattern.MatchString(statement) {
			continue
		}
		if match := typeDeclPattern.FindStringSubmatch(statement); match != nil {
			if invalidTypeDeclarationName(match[1], match[2]) {
				return nil, nil, unsupportedTypeScriptSourceGrammar("type declaration name is not admitted")
			}
			typeExports[match[2]] = struct{}{}
			continue
		}
		if varDeclStartPattern.MatchString(statement) {
			continue
		}
		return nil, nil, fmt.Errorf("unsupported public export statement")
	}
	for _, name := range runtimeExports {
		if name == "default" {
			return nil, nil, unsupportedTypeScriptSourceGrammar("default exports are not admitted")
		}
	}
	return runtimeExports, sortedSet(typeExports), nil
}

func admitTypeReexportAttributes(rawTail string, topLevelType bool) error {
	index, crossedLine := scanTypeScriptTrivia(rawTail, 0)
	if strings.HasPrefix(rawTail[index:], "assert") && (index+6 == len(rawTail) || !isASCIITypeScriptIdentifierByte(rawTail[index+6])) {
		return unsupportedTypeScriptSourceGrammar("legacy assert import attributes are not admitted")
	}
	if !strings.HasPrefix(rawTail[index:], "with") || index+4 < len(rawTail) && isASCIITypeScriptIdentifierByte(rawTail[index+4]) {
		return nil
	}
	if crossedLine {
		return unsupportedTypeScriptSourceGrammar("type-only re-export attributes must follow the module specifier on the same line")
	}
	if !topLevelType {
		return unsupportedTypeScriptSourceGrammar("inline type-only re-exports cannot use import attributes")
	}
	index = skipTypeScriptTrivia(rawTail, index+4)
	if index >= len(rawTail) || rawTail[index] != '{' {
		return unsupportedTypeScriptSourceGrammar("type-only re-export attributes must use resolution-mode")
	}
	key, next, ok := readTypeScriptAttributeString(rawTail, skipTypeScriptTrivia(rawTail, index+1))
	if !ok || key != "resolution-mode" {
		return unsupportedTypeScriptSourceGrammar("type-only re-export attributes must use resolution-mode")
	}
	index = skipTypeScriptTrivia(rawTail, next)
	if index >= len(rawTail) || rawTail[index] != ':' {
		return unsupportedTypeScriptSourceGrammar("type-only re-export attributes must use resolution-mode")
	}
	value, next, ok := readTypeScriptAttributeString(rawTail, skipTypeScriptTrivia(rawTail, index+1))
	if !ok || value != "import" && value != "require" {
		return unsupportedTypeScriptSourceGrammar("type-only re-export attributes must use resolution-mode")
	}
	index = skipTypeScriptTrivia(rawTail, next)
	if index < len(rawTail) && rawTail[index] == ',' {
		index = skipTypeScriptTrivia(rawTail, index+1)
	}
	if index >= len(rawTail) || rawTail[index] != '}' {
		return unsupportedTypeScriptSourceGrammar("type-only re-export attributes must use resolution-mode")
	}
	return nil
}

func skipTypeScriptTrivia(source string, index int) int {
	index, _ = scanTypeScriptTrivia(source, index)
	return index
}

func scanTypeScriptTrivia(source string, index int) (int, bool) {
	crossedLine := false
	for index < len(source) {
		if width := unicodeLineTerminatorWidth(source, index); width != 0 {
			index += width
			crossedLine = true
			continue
		}
		if strings.ContainsRune(" \t\r\n\v\f", rune(source[index])) {
			if source[index] == '\r' || source[index] == '\n' {
				crossedLine = true
			}
			index++
			continue
		}
		if strings.HasPrefix(source[index:], "//") {
			for index < len(source) && source[index] != '\n' && source[index] != '\r' && unicodeLineTerminatorWidth(source, index) == 0 {
				index++
			}
			continue
		}
		if strings.HasPrefix(source[index:], "/*") {
			if end := strings.Index(source[index+2:], "*/"); end >= 0 {
				body := source[index+2 : index+2+end]
				if strings.ContainsAny(body, "\r\n") || strings.ContainsRune(body, '\u2028') || strings.ContainsRune(body, '\u2029') {
					crossedLine = true
				}
				index += end + 4
				continue
			}
		}
		break
	}
	return index, crossedLine
}

func readTypeScriptAttributeString(source string, index int) (string, int, bool) {
	if index >= len(source) || source[index] != '\'' && source[index] != '"' {
		return "", index, false
	}
	quote := source[index]
	start := index + 1
	for index = start; index < len(source); index++ {
		if source[index] == '\\' {
			return "", index, false
		}
		if source[index] == quote {
			return source[start:index], index + 1, true
		}
	}
	return "", index, false
}

func admitGenericAngleSyntax(scan typeScriptLexicalScan, extension string) error {
	masked := scan.masked
	exportIndex, latestExport := 0, -1
	for start := 0; start < len(masked); start++ {
		if masked[start] != '<' {
			continue
		}
		for exportIndex < len(scan.topLevelExportOffsets) && scan.topLevelExportOffsets[exportIndex] <= start {
			latestExport = scan.topLevelExportOffsets[exportIndex]
			exportIndex++
		}
		index := start + 1
		for index < len(masked) && strings.ContainsRune(" \t\r\n\v\f", rune(masked[index])) {
			index++
		}
		if index >= len(masked) || !isASCIITypeScriptIdentifierByte(masked[index]) {
			continue
		}
		angle, square, round, curly := 1, 0, 0, 0
		separated, defaultSeen, constraintSeen, malformedConstraint := false, false, false, false
		for ; index < len(masked); index++ {
			switch masked[index] {
			case '<':
				angle++
				if angle > maxGenericAngleNesting {
					return unsupportedTypeScriptSourceGrammar("generic angle nesting exceeds 128")
				}
			case '>':
				if index > 0 && masked[index-1] == '=' {
					continue
				}
				angle--
				if angle == 0 {
					after := index + 1
					for after < len(masked) && strings.ContainsRune(" \t\r\n\v\f", rune(masked[after])) {
						after++
					}
					if after < len(masked) && masked[after] == '(' && !angleInTypeContext(masked, start, latestExport) {
						if malformedConstraint {
							return unsupportedTypeScriptSourceGrammar("conditional generic constraints require parentheses")
						}
						if extension == ".mts" && !separated {
							return unsupportedTypeScriptSourceGrammar("ambiguous .mts generic syntax is not admitted")
						}
					}
					goto nextCandidate
				}
			case '[':
				square++
			case ']':
				square--
			case '(':
				round++
			case ')':
				round--
			case '{':
				curly++
			case '}':
				curly--
			case ',':
				if angle == 1 && square == 0 && round == 0 && curly == 0 {
					separated = true
					defaultSeen, constraintSeen = false, false
				}
			case '=':
				if angle == 1 && square == 0 && round == 0 && curly == 0 && (index+1 == len(masked) || masked[index+1] != '>') {
					defaultSeen = true
				}
			case '?':
				if angle == 1 && square == 0 && round == 0 && curly == 0 && constraintSeen && !defaultSeen {
					malformedConstraint = true
				}
			}
			if !defaultSeen && angle == 1 && square == 0 && round == 0 && curly == 0 && strings.HasPrefix(masked[index:], "extends") && (index == 0 || !isASCIITypeScriptIdentifierByte(masked[index-1])) {
				end := index + len("extends")
				if end == len(masked) || !isASCIITypeScriptIdentifierByte(masked[end]) {
					separated = true
					constraintSeen = true
				}
			}
		}
	nextCandidate:
	}
	return nil
}

func angleInTypeContext(masked string, start int, latestExport int) bool {
	if latestExport >= 0 {
		prefix := masked[latestExport:start]
		if genericTypePosition.MatchString(prefix) || typeAliasPrefix.MatchString(prefix) {
			return true
		}
	}
	end := start
	for end > 0 && strings.ContainsRune(" \t\r\n\v\f", rune(masked[end-1])) {
		end--
	}
	if end == 0 {
		return false
	}
	if masked[end-1] == ':' {
		return true
	}
	if !isASCIITypeScriptIdentifierByte(masked[end-1]) {
		return false
	}
	begin := end - 1
	for begin > 0 && isASCIITypeScriptIdentifierByte(masked[begin-1]) {
		begin--
	}
	word := masked[begin:end]
	return word != "async" && word != "return"
}

// Only erased declaration names are substituted for esbuild; original bytes own type names and offsets.
func runtimeParserSource(source string, scan typeScriptLexicalScan) string {
	var rewritten []byte
	for _, pattern := range []*regexp.Regexp{erasedInterfaceName, erasedTypeAliasName} {
		for _, indices := range pattern.FindAllStringSubmatchIndex(scan.masked, -1) {
			nameStart, nameEnd := indices[2], indices[3]
			if rewritten == nil {
				rewritten = []byte(source)
			}
			rewritten[nameStart] = '_'
			for index := nameStart + 1; index < nameEnd; index++ {
				rewritten[index] = 'x'
			}
		}
	}
	if rewritten == nil {
		return source
	}
	return string(rewritten)
}

func invalidTypeDeclarationName(kind string, name string) bool {
	if kind == "type" && name == "as" {
		return true
	}
	switch name {
	case "any", "await", "bigint", "boolean", "implements", "interface", "let", "never", "number", "object", "package", "private", "protected", "public", "static", "string", "symbol", "undefined", "unknown", "yield":
		return true
	default:
		return false
	}
}

type typeScriptLexicalState uint8

const (
	typeScriptCode typeScriptLexicalState = iota
	typeScriptLineComment
	typeScriptBlockComment
	typeScriptSingleQuoted
	typeScriptDoubleQuoted
	typeScriptTemplateQuoted
)

type typeScriptLexicalScan struct {
	masked                string
	topLevelExportOffsets []int
}

func scanTypeScriptSource(source string) (typeScriptLexicalScan, error) {
	masked := []byte(source)
	starts := make([]int, 0)
	state := typeScriptCode
	escaped := false
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
		case typeScriptLineComment:
			if width := unicodeLineTerminatorWidth(source, index); width > 0 {
				masked[index] = '\n'
				for offset := 1; offset < width; offset++ {
					masked[index+offset] = ' '
				}
				state = typeScriptCode
				index += width - 1
				continue
			}
			if current == '\n' || current == '\r' {
				state = typeScriptCode
			} else {
				masked[index] = ' '
			}
			continue
		case typeScriptBlockComment:
			if width := unicodeLineTerminatorWidth(source, index); width > 0 {
				masked[index] = '\n'
				for offset := 1; offset < width; offset++ {
					masked[index+offset] = ' '
				}
				index += width - 1
				continue
			}
			if current == '*' && next == '/' {
				masked[index], masked[index+1] = ' ', ' '
				state = typeScriptCode
				index++
			} else if current != '\n' && current != '\r' {
				masked[index] = ' '
			}
			continue
		case typeScriptSingleQuoted, typeScriptDoubleQuoted:
			closing := byte('\'')
			if state == typeScriptDoubleQuoted {
				closing = '"'
			}
			unicodeLineWidth := unicodeLineTerminatorWidth(source, index)
			if (current == '\n' || current == '\r' || unicodeLineWidth > 0) && !escaped {
				return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("quoted strings must terminate before an unescaped newline")
			}
			if escaped {
				if unicodeLineWidth > 0 {
					escaped = false
					index += unicodeLineWidth - 1
					continue
				}
				if current == '\r' && next == '\n' {
					escaped = false
					index++
					continue
				}
				if current != '\n' && current != '\r' {
					masked[index] = ' '
				}
				escaped = false
			} else if current == '\\' {
				masked[index] = ' '
				escaped = true
			} else if current == closing {
				state = typeScriptCode
			} else if current != '\n' {
				masked[index] = ' '
			}
			continue
		case typeScriptTemplateQuoted:
			if current != '\n' {
				masked[index] = ' '
			}
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '$' && next == '{' {
				return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("template interpolation is not admitted")
			} else if current == '`' {
				masked[index] = '`'
				state = typeScriptCode
			}
			continue
		}
		if current >= 0x80 {
			return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("code tokens must use direct ASCII identifiers")
		}
		switch {
		case current == '/' && next == '/':
			masked[index], masked[index+1] = ' ', ' '
			state = typeScriptLineComment
			index++
			continue
		case current == '/' && next == '*':
			masked[index], masked[index+1] = ' ', ' '
			state = typeScriptBlockComment
			index++
			continue
		case current == '/':
			return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("slash tokens outside comments are not admitted")
		case current == '\'':
			state = typeScriptSingleQuoted
			continue
		case current == '"':
			state = typeScriptDoubleQuoted
			continue
		case current == '`':
			masked[index] = ' '
			state = typeScriptTemplateQuoted
			continue
		case current == '\\':
			return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("escaped code identifiers are not admitted")
		}
		if braceDepth == 0 && bracketDepth == 0 && parenDepth == 0 && strings.HasPrefix(source[index:], "export") {
			beforeOK := index == 0 || !isASCIITypeScriptIdentifierByte(source[index-1]) && source[index-1] != '.'
			after := index + len("export")
			afterOK := after == len(source) || !isASCIITypeScriptIdentifierByte(source[after])
			if beforeOK && afterOK {
				starts = append(starts, index)
			}
		}
		switch current {
		case '{':
			braceDepth++
		case '}':
			if braceDepth == 0 {
				return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("closing brace has no matching opener")
			}
			braceDepth--
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth == 0 {
				return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("closing bracket has no matching opener")
			}
			bracketDepth--
		case '(':
			parenDepth++
		case ')':
			if parenDepth == 0 {
				return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("closing parenthesis has no matching opener")
			}
			parenDepth--
		}
	}
	switch state {
	case typeScriptCode, typeScriptLineComment:
	case typeScriptBlockComment:
		return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("block comments must terminate")
	case typeScriptSingleQuoted, typeScriptDoubleQuoted:
		return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("quoted strings must terminate")
	case typeScriptTemplateQuoted:
		return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("template literals must terminate")
	}
	if braceDepth != 0 || bracketDepth != 0 || parenDepth != 0 {
		return typeScriptLexicalScan{}, unsupportedTypeScriptSourceGrammar("delimiters must be balanced")
	}
	return typeScriptLexicalScan{masked: string(masked), topLevelExportOffsets: starts}, nil
}

func isASCIITypeScriptIdentifierByte(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func unicodeLineTerminatorWidth(source string, index int) int {
	if index+2 >= len(source) || source[index] != 0xe2 || source[index+1] != 0x80 {
		return 0
	}
	if source[index+2] == 0xa8 || source[index+2] == 0xa9 {
		return 3
	}
	return 0
}

func unsupportedTypeScriptSourceGrammar(reason string) error {
	return fmt.Errorf("unsupported TypeScript public API source grammar: %s", reason)
}

func addTypeClauseExports(clause string, target map[string]struct{}) error {
	return addClauseExports(clause, target, true)
}

func addNamedClauseTypeExports(clause string, target map[string]struct{}) error {
	return addClauseExports(clause, target, false)
}

func addClauseExports(clause string, target map[string]struct{}, typeClause bool) error {
	body := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(clause), "{"), "}")
	for _, rawPart := range strings.Split(body, ",") {
		part := strings.Join(strings.Fields(rawPart), " ")
		if part == "" {
			continue
		}
		typeOnly := typeClause
		if isInlineTypeOnlyReexport(part) {
			if typeClause {
				return unsupportedTypeScriptSourceGrammar("duplicate type-only re-export modifier")
			}
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
		if !typeOnly {
			return fmt.Errorf("TypeScript public API unresolved runtime re-exports are not admitted")
		}
		target[name] = struct{}{}
	}
	return nil
}

func isInlineTypeOnlyReexport(part string) bool {
	if !strings.HasPrefix(part, "type ") {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(part, "type "))
	if rest == "" {
		return false
	}
	if strings.HasPrefix(rest, "as ") {
		return strings.HasPrefix(rest, "as as ")
	}
	return true
}
