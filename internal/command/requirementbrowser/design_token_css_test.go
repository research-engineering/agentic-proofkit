package requirementbrowser

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A CSS Syntax Level 3 tokenizer and a small rule parser for the design-token
// grammar test. It recognizes comments, strings, url, function, hash,
// at-keyword, ident, number, percentage, dimension and the punctuation tokens;
// comments are consumed and produce no token.

type cssTokenKind int

const (
	cssWhitespace cssTokenKind = iota
	cssString
	cssBadString
	cssURL
	cssBadURL
	cssFunction
	cssHash
	cssAtKeyword
	cssIdent
	cssNumber
	cssPercentage
	cssDimension
	cssDelim
	cssColon
	cssSemicolon
	cssComma
	cssOpenParen
	cssCloseParen
	cssOpenSquare
	cssCloseSquare
	cssOpenCurly
	cssCloseCurly
	cssCDO
	cssCDC
)

type cssToken struct {
	kind cssTokenKind
	// text is the exact source text of the token.
	text string
	// value is the unescaped name of an ident, function, at-keyword or hash,
	// the content of a string or url, or the delimiter code point.
	value string
	// number and unit describe numeric tokens; numberText is the source text
	// of the number without its unit or percent sign.
	number     float64
	numberText string
	unit       string
}

type cssTokenizer struct {
	input []rune
	at    int
}

func tokenizeCSS(source string) ([]cssToken, error) {
	if !utf8.ValidString(source) {
		return nil, fmt.Errorf("css is not valid UTF-8")
	}
	normalized := strings.NewReplacer("\r\n", "\n", "\r", "\n", "\f", "\n").Replace(source)
	tokenizer := cssTokenizer{input: []rune(normalized)}
	tokens := []cssToken{}
	for {
		token, ok, err := tokenizer.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			return tokens, nil
		}
		tokens = append(tokens, token)
	}
}

func (t *cssTokenizer) peek(offset int) rune {
	if t.at+offset < len(t.input) {
		return t.input[t.at+offset]
	}
	return -1
}

func (t *cssTokenizer) next() (cssToken, bool, error) {
	for t.peek(0) == '/' && t.peek(1) == '*' {
		t.at += 2
		for !(t.peek(0) == '*' && t.peek(1) == '/') {
			if t.peek(0) < 0 {
				return cssToken{}, false, fmt.Errorf("unterminated css comment")
			}
			t.at++
		}
		t.at += 2
	}
	start := t.at
	r := t.peek(0)
	if r < 0 {
		return cssToken{}, false, nil
	}
	emit := func(kind cssTokenKind, value string) (cssToken, bool, error) {
		return cssToken{kind: kind, text: string(t.input[start:t.at]), value: value}, true, nil
	}
	switch {
	case isCSSWhitespace(r):
		for isCSSWhitespace(t.peek(0)) {
			t.at++
		}
		return emit(cssWhitespace, " ")
	case r == '"' || r == '\'':
		t.at++
		value, bad := t.consumeString(r)
		if bad {
			return emit(cssBadString, value)
		}
		return emit(cssString, value)
	case r == '#':
		if isCSSNameCodePoint(t.peek(1)) || validCSSEscape(t.peek(1), t.peek(2)) {
			t.at++
			return emit(cssHash, t.consumeName())
		}
		t.at++
		return emit(cssDelim, "#")
	case r == '(':
		t.at++
		return emit(cssOpenParen, "(")
	case r == ')':
		t.at++
		return emit(cssCloseParen, ")")
	case r == '[':
		t.at++
		return emit(cssOpenSquare, "[")
	case r == ']':
		t.at++
		return emit(cssCloseSquare, "]")
	case r == '{':
		t.at++
		return emit(cssOpenCurly, "{")
	case r == '}':
		t.at++
		return emit(cssCloseCurly, "}")
	case r == ',':
		t.at++
		return emit(cssComma, ",")
	case r == ':':
		t.at++
		return emit(cssColon, ":")
	case r == ';':
		t.at++
		return emit(cssSemicolon, ";")
	case r == '+' || r == '.':
		if startsCSSNumber(r, t.peek(1), t.peek(2)) {
			return t.consumeNumeric(start)
		}
		t.at++
		return emit(cssDelim, string(r))
	case r == '-':
		if startsCSSNumber(r, t.peek(1), t.peek(2)) {
			return t.consumeNumeric(start)
		}
		if t.peek(1) == '-' && t.peek(2) == '>' {
			t.at += 3
			return emit(cssCDC, "-->")
		}
		if startsCSSIdent(r, t.peek(1), t.peek(2)) {
			return t.consumeIdentLike(start)
		}
		t.at++
		return emit(cssDelim, "-")
	case r == '<':
		if t.peek(1) == '!' && t.peek(2) == '-' && t.peek(3) == '-' {
			t.at += 4
			return emit(cssCDO, "<!--")
		}
		t.at++
		return emit(cssDelim, "<")
	case r == '@':
		if startsCSSIdent(t.peek(1), t.peek(2), t.peek(3)) {
			t.at++
			return emit(cssAtKeyword, t.consumeName())
		}
		t.at++
		return emit(cssDelim, "@")
	case r == '\\':
		if validCSSEscape(r, t.peek(1)) {
			return t.consumeIdentLike(start)
		}
		return cssToken{}, false, fmt.Errorf("invalid css escape")
	case r >= '0' && r <= '9':
		return t.consumeNumeric(start)
	case isCSSNameStart(r):
		return t.consumeIdentLike(start)
	default:
		t.at++
		return emit(cssDelim, string(r))
	}
}

func (t *cssTokenizer) consumeString(quote rune) (string, bool) {
	var builder strings.Builder
	for {
		r := t.peek(0)
		switch {
		case r < 0:
			return builder.String(), false
		case r == quote:
			t.at++
			return builder.String(), false
		case r == '\n':
			return builder.String(), true
		case r == '\\':
			if t.peek(1) < 0 {
				t.at++
				continue
			}
			if t.peek(1) == '\n' {
				t.at += 2
				continue
			}
			t.at++
			builder.WriteRune(t.consumeEscape())
		default:
			builder.WriteRune(r)
			t.at++
		}
	}
}

func (t *cssTokenizer) consumeEscape() rune {
	r := t.peek(0)
	if r < 0 {
		return utf8.RuneError
	}
	if isHexDigit(r) {
		digits := ""
		for len(digits) < 6 && isHexDigit(t.peek(0)) {
			digits += string(t.peek(0))
			t.at++
		}
		if isCSSWhitespace(t.peek(0)) {
			t.at++
		}
		value, _ := strconv.ParseUint(digits, 16, 32)
		if value == 0 || value > utf8.MaxRune || (value >= 0xd800 && value <= 0xdfff) {
			return utf8.RuneError
		}
		return rune(value)
	}
	t.at++
	return r
}

func (t *cssTokenizer) consumeName() string {
	var builder strings.Builder
	for {
		r := t.peek(0)
		switch {
		case isCSSNameCodePoint(r):
			builder.WriteRune(r)
			t.at++
		case validCSSEscape(r, t.peek(1)):
			t.at++
			builder.WriteRune(t.consumeEscape())
		default:
			return builder.String()
		}
	}
}

func (t *cssTokenizer) consumeNumeric(start int) (cssToken, bool, error) {
	numberStart := t.at
	if t.peek(0) == '+' || t.peek(0) == '-' {
		t.at++
	}
	for isDigit(t.peek(0)) {
		t.at++
	}
	if t.peek(0) == '.' && isDigit(t.peek(1)) {
		t.at += 2
		for isDigit(t.peek(0)) {
			t.at++
		}
	}
	if (t.peek(0) == 'e' || t.peek(0) == 'E') && (isDigit(t.peek(1)) || ((t.peek(1) == '+' || t.peek(1) == '-') && isDigit(t.peek(2)))) {
		t.at += 2
		for isDigit(t.peek(0)) {
			t.at++
		}
	}
	numberText := string(t.input[numberStart:t.at])
	number, err := strconv.ParseFloat(numberText, 64)
	if err != nil {
		return cssToken{}, false, fmt.Errorf("invalid css number %q", numberText)
	}
	token := cssToken{number: number, numberText: numberText}
	switch {
	case startsCSSIdent(t.peek(0), t.peek(1), t.peek(2)):
		token.kind = cssDimension
		token.unit = t.consumeName()
	case t.peek(0) == '%':
		t.at++
		token.kind = cssPercentage
		token.unit = "%"
	default:
		token.kind = cssNumber
	}
	token.text = string(t.input[start:t.at])
	return token, true, nil
}

func (t *cssTokenizer) consumeIdentLike(start int) (cssToken, bool, error) {
	name := t.consumeName()
	if strings.EqualFold(name, "url") && t.peek(0) == '(' {
		t.at++
		for isCSSWhitespace(t.peek(0)) && isCSSWhitespace(t.peek(1)) {
			t.at++
		}
		if t.peek(0) == '"' || t.peek(0) == '\'' || (isCSSWhitespace(t.peek(0)) && (t.peek(1) == '"' || t.peek(1) == '\'')) {
			return cssToken{kind: cssFunction, text: string(t.input[start:t.at]), value: name}, true, nil
		}
		return t.consumeURL(start)
	}
	if t.peek(0) == '(' {
		t.at++
		return cssToken{kind: cssFunction, text: string(t.input[start:t.at]), value: name}, true, nil
	}
	return cssToken{kind: cssIdent, text: string(t.input[start:t.at]), value: name}, true, nil
}

func (t *cssTokenizer) consumeURL(start int) (cssToken, bool, error) {
	var builder strings.Builder
	for isCSSWhitespace(t.peek(0)) {
		t.at++
	}
	for {
		r := t.peek(0)
		switch {
		case r < 0:
			return cssToken{kind: cssURL, text: string(t.input[start:t.at]), value: builder.String()}, true, nil
		case r == ')':
			t.at++
			return cssToken{kind: cssURL, text: string(t.input[start:t.at]), value: builder.String()}, true, nil
		case isCSSWhitespace(r):
			for isCSSWhitespace(t.peek(0)) {
				t.at++
			}
			if t.peek(0) == ')' || t.peek(0) < 0 {
				continue
			}
			return t.consumeBadURL(start)
		case r == '"' || r == '\'' || r == '(' || isCSSNonPrintable(r):
			return t.consumeBadURL(start)
		case r == '\\':
			if !validCSSEscape(r, t.peek(1)) {
				return t.consumeBadURL(start)
			}
			t.at++
			builder.WriteRune(t.consumeEscape())
		default:
			builder.WriteRune(r)
			t.at++
		}
	}
}

func (t *cssTokenizer) consumeBadURL(start int) (cssToken, bool, error) {
	for {
		r := t.peek(0)
		if r < 0 {
			break
		}
		if r == ')' {
			t.at++
			break
		}
		if validCSSEscape(r, t.peek(1)) {
			t.at++
			t.consumeEscape()
			continue
		}
		t.at++
	}
	return cssToken{kind: cssBadURL, text: string(t.input[start:t.at])}, true, nil
}

func isCSSWhitespace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' }
func isDigit(r rune) bool         { return r >= '0' && r <= '9' }
func isHexDigit(r rune) bool {
	return isDigit(r) || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
func isCSSNameStart(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r >= 0x80
}
func isCSSNameCodePoint(r rune) bool { return isCSSNameStart(r) || isDigit(r) || r == '-' }
func isCSSNonPrintable(r rune) bool {
	return (r >= 0 && r <= 8) || r == 0x0b || (r >= 0x0e && r <= 0x1f) || r == 0x7f
}
func validCSSEscape(first, second rune) bool { return first == '\\' && second != '\n' && second >= 0 }
func startsCSSIdent(first, second, third rune) bool {
	switch {
	case first == '-':
		return isCSSNameStart(second) || second == '-' || validCSSEscape(second, third)
	case isCSSNameStart(first):
		return true
	case first == '\\':
		return validCSSEscape(first, second)
	default:
		return false
	}
}
func startsCSSNumber(first, second, third rune) bool {
	switch {
	case first == '+' || first == '-':
		return isDigit(second) || (second == '.' && isDigit(third))
	case first == '.':
		return isDigit(second)
	default:
		return isDigit(first)
	}
}

// cssNode is a rule or a declaration of a parsed stylesheet. An at-rule or a
// qualified rule keeps its prelude tokens and, when it has a block, its
// children; a declaration keeps its property name and value tokens.
type cssNode struct {
	kind      cssNodeKind
	name      string
	prelude   []cssToken
	value     []cssToken
	important bool
	hasBlock  bool
	children  []cssNode
}

type cssNodeKind int

const (
	cssAtRule cssNodeKind = iota
	cssQualifiedRule
	cssDeclaration
)

// cssRuleListAtRules hold a list of rules in their block; every other at-rule
// and every qualified rule holds a list of declarations.
var cssRuleListAtRules = map[string]bool{"media": true, "container": true, "supports": true, "layer": true}

func parseStylesheet(source string) ([]cssNode, error) {
	tokens, err := tokenizeCSS(source)
	if err != nil {
		return nil, err
	}
	parser := cssParser{tokens: tokens}
	nodes, err := parser.rules(true)
	if err != nil {
		return nil, err
	}
	if parser.at != len(parser.tokens) {
		return nil, fmt.Errorf("unbalanced css block")
	}
	return nodes, nil
}

type cssParser struct {
	tokens []cssToken
	at     int
}

func (p *cssParser) rules(topLevel bool) ([]cssNode, error) {
	nodes := []cssNode{}
	for p.at < len(p.tokens) {
		token := p.tokens[p.at]
		switch {
		case token.kind == cssWhitespace || (topLevel && (token.kind == cssCDO || token.kind == cssCDC)):
			p.at++
		case token.kind == cssCloseCurly:
			if topLevel {
				return nil, fmt.Errorf("unbalanced css block")
			}
			return nodes, nil
		case token.kind == cssAtKeyword:
			p.at++
			name := strings.ToLower(token.value)
			prelude, hasBlock, err := p.prelude(true)
			if err != nil {
				return nil, err
			}
			node := cssNode{kind: cssAtRule, name: name, prelude: prelude, hasBlock: hasBlock}
			if hasBlock {
				if cssRuleListAtRules[name] {
					node.children, err = p.rules(false)
				} else {
					node.children, err = p.declarations()
				}
				if err != nil {
					return nil, err
				}
				if err := p.closeBlock(); err != nil {
					return nil, err
				}
			}
			nodes = append(nodes, node)
		default:
			prelude, hasBlock, err := p.prelude(false)
			if err != nil {
				return nil, err
			}
			if !hasBlock {
				return nil, fmt.Errorf("css qualified rule has no block")
			}
			children, err := p.declarations()
			if err != nil {
				return nil, err
			}
			if err := p.closeBlock(); err != nil {
				return nil, err
			}
			nodes = append(nodes, cssNode{kind: cssQualifiedRule, prelude: prelude, hasBlock: true, children: children})
		}
	}
	if !topLevel {
		return nil, fmt.Errorf("unterminated css block")
	}
	return nodes, nil
}

// prelude consumes tokens up to an opening curly bracket, which it consumes,
// or, for an at-rule, up to a semicolon.
func (p *cssParser) prelude(atRule bool) ([]cssToken, bool, error) {
	prelude := []cssToken{}
	depth := 0
	for p.at < len(p.tokens) {
		token := p.tokens[p.at]
		switch {
		case depth == 0 && token.kind == cssOpenCurly:
			p.at++
			return trimCSSWhitespace(prelude), true, nil
		case depth == 0 && atRule && token.kind == cssSemicolon:
			p.at++
			return trimCSSWhitespace(prelude), false, nil
		case depth == 0 && token.kind == cssCloseCurly:
			return nil, false, fmt.Errorf("css rule prelude ends without a block")
		case token.kind == cssFunction || token.kind == cssOpenParen || token.kind == cssOpenSquare:
			depth++
		case token.kind == cssCloseParen || token.kind == cssCloseSquare:
			depth--
		}
		prelude = append(prelude, token)
		p.at++
	}
	return nil, false, fmt.Errorf("css rule prelude ends without a block")
}

func (p *cssParser) closeBlock() error {
	if p.at >= len(p.tokens) || p.tokens[p.at].kind != cssCloseCurly {
		return fmt.Errorf("unterminated css block")
	}
	p.at++
	return nil
}

// declarations consumes a declaration list up to, not including, the closing
// curly bracket of its block. A nested rule is a parse error: neither style
// owner uses CSS nesting.
func (p *cssParser) declarations() ([]cssNode, error) {
	nodes := []cssNode{}
	for p.at < len(p.tokens) {
		token := p.tokens[p.at]
		switch {
		case token.kind == cssWhitespace || token.kind == cssSemicolon:
			p.at++
		case token.kind == cssCloseCurly:
			return nodes, nil
		case token.kind == cssIdent:
			p.at++
			for p.at < len(p.tokens) && p.tokens[p.at].kind == cssWhitespace {
				p.at++
			}
			if p.at >= len(p.tokens) || p.tokens[p.at].kind != cssColon {
				return nil, fmt.Errorf("css declaration %q has no colon", token.value)
			}
			p.at++
			value := []cssToken{}
			depth := 0
			for p.at < len(p.tokens) {
				current := p.tokens[p.at]
				if depth == 0 && (current.kind == cssSemicolon || current.kind == cssCloseCurly) {
					break
				}
				switch current.kind {
				case cssFunction, cssOpenParen, cssOpenSquare, cssOpenCurly:
					depth++
				case cssCloseParen, cssCloseSquare, cssCloseCurly:
					depth--
				}
				value = append(value, current)
				p.at++
			}
			value = trimCSSWhitespace(value)
			important := false
			if n := len(value); n >= 2 && value[n-1].kind == cssIdent && strings.EqualFold(value[n-1].value, "important") {
				bang := n - 2
				for bang >= 0 && value[bang].kind == cssWhitespace {
					bang--
				}
				if bang >= 0 && value[bang].kind == cssDelim && value[bang].value == "!" {
					important = true
					value = trimCSSWhitespace(value[:bang])
				}
			}
			name := token.value
			if !strings.HasPrefix(name, "--") {
				name = strings.ToLower(name)
			}
			nodes = append(nodes, cssNode{kind: cssDeclaration, name: name, value: value, important: important})
		default:
			return nil, fmt.Errorf("css declaration list holds a nested rule or a stray %q", token.text)
		}
	}
	return nil, fmt.Errorf("unterminated css declaration block")
}

func trimCSSWhitespace(tokens []cssToken) []cssToken {
	for len(tokens) > 0 && tokens[0].kind == cssWhitespace {
		tokens = tokens[1:]
	}
	for len(tokens) > 0 && tokens[len(tokens)-1].kind == cssWhitespace {
		tokens = tokens[:len(tokens)-1]
	}
	return tokens
}

// cssText joins token source texts; compactCSSText also drops whitespace and
// lowercases, so that two preludes compare by their tokens.
func cssText(tokens []cssToken) string {
	var builder strings.Builder
	for _, token := range tokens {
		builder.WriteString(token.text)
	}
	return builder.String()
}

func compactCSSText(tokens []cssToken) string {
	var builder strings.Builder
	for _, token := range tokens {
		if token.kind != cssWhitespace {
			builder.WriteString(strings.ToLower(token.text))
		}
	}
	return builder.String()
}
