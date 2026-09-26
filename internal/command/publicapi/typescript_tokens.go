package publicapi

import "strings"

type tsTokenKind uint8

const (
	tsEnd tsTokenKind = iota
	tsWord
	tsNumber
	tsString
	tsTemplate
	tsPunctuation
)

type tsToken struct {
	kind       tsTokenKind
	start, end int
	depth      int
	lineBefore bool
}

// Source spans, two lookahead tokens, and one byte per open delimiter suffice.
// The lexer also admits every byte inside regions the inventory leaves opaque.
type tsTokens struct {
	source string
	pos    int
	stack  []byte
	queue  [2]tsToken
	queued int
	err    error
}

func (s *tsTokens) text(t tsToken) string { return s.source[t.start:t.end] }

func (s *tsTokens) peek(n int) tsToken {
	for s.queued <= n {
		s.queue[s.queued] = s.lex()
		s.queued++
	}
	return s.queue[n]
}

func (s *tsTokens) take() tsToken {
	t := s.peek(0)
	s.queue[0] = s.queue[1]
	s.queued--
	return t
}

func (s *tsTokens) at(text string) bool { return s.text(s.peek(0)) == text }

func (s *tsTokens) fail(reason string) {
	if s.err == nil {
		s.err = unsupportedTypeScriptSourceGrammar(reason)
	}
}

func tsLineWidth(source string, pos int) int {
	if pos >= len(source) {
		return 0
	}
	switch source[pos] {
	case '\n':
		return 1
	case '\r':
		if pos+1 < len(source) && source[pos+1] == '\n' {
			return 2
		}
		return 1
	case 0xe2:
		if pos+2 < len(source) && source[pos+1] == 0x80 && (source[pos+2] == 0xa8 || source[pos+2] == 0xa9) {
			return 3
		}
	}
	return 0
}

func tsIdentifierStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
func tsIdentifierPart(c byte) bool { return tsIdentifierStart(c) || tsDigit(c) }
func tsDigit(c byte) bool          { return c >= '0' && c <= '9' }

func (s *tsTokens) lex() tsToken {
	line := false
	for s.pos < len(s.source) && s.err == nil {
		if width := tsLineWidth(s.source, s.pos); width != 0 {
			line = true
			s.pos += width
			continue
		}
		c := s.source[s.pos]
		if c == ' ' || c == '\t' || c == '\v' || c == '\f' {
			s.pos++
			continue
		}
		if strings.HasPrefix(s.source[s.pos:], "//") {
			s.pos += 2
			for s.pos < len(s.source) && tsLineWidth(s.source, s.pos) == 0 {
				s.pos++
			}
			continue
		}
		if strings.HasPrefix(s.source[s.pos:], "/*") {
			s.pos += 2
			for s.pos < len(s.source) && !strings.HasPrefix(s.source[s.pos:], "*/") {
				if width := tsLineWidth(s.source, s.pos); width != 0 {
					line = true
					s.pos += width
				} else {
					s.pos++
				}
			}
			if s.pos == len(s.source) {
				s.fail("block comments must terminate")
				break
			}
			s.pos += 2
			continue
		}
		break
	}
	t := tsToken{start: s.pos, end: s.pos, depth: len(s.stack), lineBefore: line}
	if s.err != nil || s.pos == len(s.source) {
		if s.err == nil && len(s.stack) != 0 {
			s.fail("delimiters must be balanced")
		}
		return t
	}
	c := s.source[s.pos]
	switch {
	case c >= 0x80:
		s.fail("code tokens must use direct ASCII identifiers")
	case c == '/':
		s.fail("slash tokens outside comments are not admitted")
	case c == '\\':
		s.fail("escaped code identifiers are not admitted")
	case tsIdentifierStart(c):
		t.kind = tsWord
		s.pos++
		for s.pos < len(s.source) && tsIdentifierPart(s.source[s.pos]) {
			s.pos++
		}
	case tsDigit(c) || c == '.' && s.pos+1 < len(s.source) && tsDigit(s.source[s.pos+1]):
		t.kind = tsNumber
		s.number()
	case c == '\'' || c == '"' || c == '`':
		t.kind = tsString
		if c == '`' {
			t.kind = tsTemplate
		}
		s.quoted(c)
	default:
		t.kind = tsPunctuation
		width := 1
		switch c {
		case '=', '!', '+', '-', '*', '&', '|', '?', '<', '>', '.', '%', '^':
			for _, operator := range tsOperators {
				if operator[0] == c && strings.HasPrefix(s.source[s.pos:], operator) {
					if operator == "?." && s.pos+2 < len(s.source) && tsDigit(s.source[s.pos+2]) {
						continue
					}
					width = len(operator)
					break
				}
			}
		}
		s.pos += width
		switch c {
		case '(', '[', '{':
			s.stack = append(s.stack, c)
		case ')', ']', '}':
			if len(s.stack) == 0 || !tsMatching(s.stack[len(s.stack)-1], c) {
				s.fail("delimiters must be balanced and properly nested")
			} else {
				s.stack = s.stack[:len(s.stack)-1]
			}
		}
	}
	t.end = s.pos
	return t
}

var tsOperators = [...]string{
	">>>=", "===", "!==", "**=", "&&=", "||=", "??=", "<<=", ">>=", ">>>", "...",
	"=>", "==", "!=", "<=", ">=", "++", "--", "**", "&&", "||", "??", "?.",
	"+=", "-=", "*=", "%=", "&=", "|=", "^=", "<<", ">>",
}

func tsMatching(open, close byte) bool {
	return open == '(' && close == ')' || open == '[' && close == ']' || open == '{' && close == '}'
}

func (s *tsTokens) number() {
	if s.source[s.pos] == '0' && s.pos+1 < len(s.source) && strings.ContainsRune("xXoObB", rune(s.source[s.pos+1])) {
		s.pos += 2
		for s.pos < len(s.source) && tsIdentifierPart(s.source[s.pos]) {
			s.pos++
		}
		return
	}
	for s.pos < len(s.source) && (tsDigit(s.source[s.pos]) || s.source[s.pos] == '_') {
		s.pos++
	}
	if s.pos < len(s.source) && s.source[s.pos] == '.' {
		s.pos++
		for s.pos < len(s.source) && (tsDigit(s.source[s.pos]) || s.source[s.pos] == '_') {
			s.pos++
		}
	}
	if s.pos < len(s.source) && (s.source[s.pos] == 'e' || s.source[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.source) && (s.source[s.pos] == '+' || s.source[s.pos] == '-') {
			s.pos++
		}
		for s.pos < len(s.source) && (tsDigit(s.source[s.pos]) || s.source[s.pos] == '_') {
			s.pos++
		}
	}
	if s.pos < len(s.source) && s.source[s.pos] == 'n' {
		s.pos++
	}
}

func (s *tsTokens) quoted(quote byte) {
	s.pos++
	for s.pos < len(s.source) {
		c := s.source[s.pos]
		if c == quote {
			s.pos++
			return
		}
		if c == '\\' {
			s.pos++
			if s.pos < len(s.source) {
				if width := tsLineWidth(s.source, s.pos); width != 0 {
					s.pos += width
				} else {
					s.pos++
				}
			}
			continue
		}
		if quote != '`' && tsLineWidth(s.source, s.pos) != 0 {
			s.fail("quoted strings must terminate before an unescaped newline")
			return
		}
		if quote == '`' && strings.HasPrefix(s.source[s.pos:], "${") {
			s.fail("template interpolation is not admitted")
			return
		}
		s.pos++
	}
	s.fail("quoted strings and template literals must terminate")
}

type tsRegion struct{ parameterHead bool }

func tsOpen(text string) bool { return text == "(" || text == "[" || text == "{" }

// Only parameter-start and its following token distinguish a function type
// signature from a parenthesized type. No parameter/body AST is retained.
func (s *tsTokens) region() tsRegion {
	open := s.take()
	first, second := "", ""
	firstKind := tsEnd
	for s.err == nil {
		t := s.take()
		if t.kind == tsEnd {
			break
		}
		text := s.text(t)
		if t.depth == open.depth+1 && (text == ")" || text == "]" || text == "}") {
			parameter := first == "" || first == "..."
			if firstKind == tsWord || first == "{" || first == "[" {
				parameter = second == "" || second == ":" || second == "?" || second == "=" || second == ","
			}
			return tsRegion{parameterHead: parameter}
		}
		if t.depth == open.depth+1 {
			if first == "" {
				first, firstKind = text, t.kind
			} else if second == "" {
				second = text
			}
		}
	}
	return tsRegion{}
}
