package publicapi

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	namedExportPattern    = regexp.MustCompile(`^export[[:space:]]+(\{[^}]+\})[[:space:]]+from[[:space:]]+["'][^"']+["']`)
	typeExportPattern     = regexp.MustCompile(`^export[[:space:]]+type[[:space:]]+(\{[^}]+\})[[:space:]]+from[[:space:]]+["'][^"']+["']`)
	runtimeDeclPattern    = regexp.MustCompile(`^export[[:space:]]+(?:abstract[[:space:]]+)?(?:async[[:space:]]+)?(?:function|class|enum)[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)(?:[[:space:]]|[({<;=]|$)`)
	typeDeclPattern       = regexp.MustCompile(`^export[[:space:]]+(?:interface|type)[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)(?:[[:space:]]|[({<;=]|$)`)
	constEnumPattern      = regexp.MustCompile(`^export[[:space:]]+const[[:space:]]+enum[[:space:]]+`)
	varDeclStartPattern   = regexp.MustCompile(`^export[[:space:]]+(?:const|let|var)[[:space:]]+`)
	exportClauseNameRegex = regexp.MustCompile(`\bas[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)$`)
	identifierRegex       = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
)

func CollectExports(source string) ([]string, []string, error) {
	scan, err := scanTypeScriptSource(source)
	if err != nil {
		return nil, nil, err
	}
	runtimeExports, err := collectRuntimeExports(source)
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
		if match := typeExportPattern.FindStringSubmatch(statement); match != nil {
			if err := addTypeClauseExports(match[1], typeExports); err != nil {
				return nil, nil, err
			}
			continue
		}
		if match := namedExportPattern.FindStringSubmatch(statement); match != nil {
			if err := addNamedClauseTypeExports(match[1], typeExports); err != nil {
				return nil, nil, err
			}
			continue
		}
		if runtimeDeclPattern.MatchString(statement) {
			continue
		}
		if match := typeDeclPattern.FindStringSubmatch(statement); match != nil {
			typeExports[match[1]] = struct{}{}
			continue
		}
		if constEnumPattern.MatchString(statement) {
			return nil, nil, fmt.Errorf("TypeScript public API const enum exports are not admitted")
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
