package publicapi

import (
	"fmt"
	"strings"
)

// CollectExports inventories compiler-valid sources in the declared lexical
// profile. Balanced private regions are not a claim of TypeScript validity.
func CollectExports(source string) ([]string, []string, error) {
	p := tsInventory{tokens: tsTokens{source: source}, runtime: map[string]struct{}{}, types: map[string]struct{}{}}
	hashbangEnd := 0
	if strings.HasPrefix(source, "#!") {
		for hashbangEnd < len(source) && tsLineWidth(source, hashbangEnd) == 0 {
			hashbangEnd++
		}
	}
	previous := ""
	for p.tokens.err == nil && p.tokens.peek(0).kind != tsEnd {
		t := p.tokens.peek(0)
		// Keep the existing lexical exclusions in the header, but never project
		// its words as module declarations. Slash-bearing hashbangs still fail.
		if t.start < hashbangEnd {
			p.tokens.take()
			continue
		}
		text := p.tokens.text(t)
		if tsOpen(text) {
			p.tokens.region()
			previous = ""
		} else if text == "export" && previous != "." && previous != "?." {
			p.tokens.take()
			if err := p.export(); err != nil {
				return nil, nil, err
			}
			previous = ""
		} else {
			p.tokens.take()
			previous = text
		}
	}
	if p.tokens.err != nil {
		return nil, nil, p.tokens.err
	}
	return sortedSet(p.runtime), sortedSet(p.types), nil
}

type tsInventory struct {
	tokens         tsTokens
	runtime, types map[string]struct{}
}

func unsupportedTypeScriptSourceGrammar(reason string) error {
	return fmt.Errorf("unsupported TypeScript public API source grammar: %s", reason)
}

func (p *tsInventory) export() error {
	s := &p.tokens
	kind := s.text(s.take())
	switch kind {
	case "*":
		return fmt.Errorf("TypeScript public API entrypoints must not use export *")
	case "default", "=":
		return fmt.Errorf("TypeScript public API entrypoints must not use default exports")
	case "declare":
		return fmt.Errorf("TypeScript public API entrypoints must not use ambient declare exports")
	case "{":
		return p.clause(false)
	case "type":
		if s.at("{") {
			s.take()
			return p.clause(true)
		}
		return p.named(p.types)
	case "interface":
		return p.named(p.types)
	case "const", "let", "var":
		return p.variables()
	case "abstract", "async":
		if kind == "abstract" && s.at("async") {
			s.take()
		}
		kind = s.text(s.take())
	}
	if kind == "function" || kind == "class" || kind == "enum" {
		return p.named(p.runtime)
	}
	return fmt.Errorf("unsupported public export statement")
}

func (p *tsInventory) named(target map[string]struct{}) error {
	t := p.tokens.take()
	if t.kind != tsWord {
		return fmt.Errorf("unsupported public export statement")
	}
	target[p.tokens.text(t)] = struct{}{}
	return nil
}

func (p *tsInventory) clause(typeClause bool) error {
	s := &p.tokens
	for s.err == nil && !s.at("}") {
		var item [4]tsToken
		n := 0
		for !s.at(",") && !s.at("}") {
			if n == len(item) || s.peek(0).kind == tsEnd || s.err != nil {
				return fmt.Errorf("unsupported public export statement")
			}
			item[n] = s.take()
			n++
		}
		typeOnly := typeClause
		name := tsToken{}
		switch {
		case n == 1 && item[0].kind == tsWord:
			name = item[0]
		case n == 2 && s.text(item[0]) == "type" && item[1].kind == tsWord:
			name, typeOnly = item[1], true
		case n == 3 && (item[0].kind == tsWord || item[0].kind == tsString) && s.text(item[1]) == "as":
			name = item[2]
		case n == 4 && s.text(item[0]) == "type" && (item[1].kind == tsWord || item[1].kind == tsString) && s.text(item[2]) == "as":
			name, typeOnly = item[3], true
		default:
			return fmt.Errorf("TypeScript public API re-exports must use identifier names")
		}
		if name.kind != tsWord {
			return fmt.Errorf("TypeScript public API re-exports must use identifier names")
		}
		if s.text(name) == "default" {
			return fmt.Errorf("TypeScript public API entrypoints must not export a default alias")
		}
		if typeOnly {
			p.types[s.text(name)] = struct{}{}
		} else {
			p.runtime[s.text(name)] = struct{}{}
		}
		if s.at(",") {
			s.take()
		}
	}
	s.take()
	if !s.at("from") {
		return fmt.Errorf("unsupported public export statement")
	}
	s.take()
	if s.take().kind != tsString {
		return fmt.Errorf("unsupported public export statement")
	}
	return p.end()
}

func (p *tsInventory) end() error {
	s := &p.tokens
	t := s.peek(0)
	if s.at(";") {
		s.take()
		return nil
	}
	if t.kind == tsEnd || t.lineBefore {
		return s.err
	}
	return fmt.Errorf("unsupported public export statement boundary")
}

func (p *tsInventory) variables() error {
	s := &p.tokens
	for s.err == nil {
		name := s.take()
		if name.kind != tsWord {
			return fmt.Errorf("TypeScript public API variable exports must use identifier declarations")
		}
		p.runtime[s.text(name)] = struct{}{}
		if s.at(":") {
			s.take()
			if err := tsTypeOutline(s); err != nil {
				return err
			}
		}
		if s.at("=") {
			s.take()
			if err := tsInitializer(s); err != nil {
				return err
			}
		}
		if s.at(",") {
			s.take()
			continue
		}
		return p.end()
	}
	return s.err
}

func tsVariableAngle(s *tsTokens, text string) bool {
	if s.peek(0).kind == tsPunctuation && strings.ContainsAny(text, "<>") && text != "=>" {
		s.fail("top-level angle-bracket syntax in variable exports is not admitted")
		return true
	}
	return false
}

// Type interiors in groups stay opaque. Exterior state distinguishes completed
// types, operands, function-type signatures and conditional colons, without AST
// allocation or recursion (including for curried function types).
func tsTypeOutline(s *tsTokens) error {
	complete, signature, conditional := false, false, false
	questions := 0
	for s.err == nil {
		t := s.peek(0)
		text := s.text(t)
		if t.kind == tsEnd || text == "," || text == ";" || text == "=" {
			break
		}
		if tsVariableAngle(s, text) {
			break
		}
		if !complete {
			if text == "|" || text == "&" || text == "-" || text == "keyof" || text == "typeof" || text == "readonly" || text == "unique" || text == "infer" || text == "new" {
				s.take()
				continue
			}
			if text == "abstract" && s.text(s.peek(1)) == "new" {
				s.take()
				continue
			}
			if text == "asserts" && !s.peek(1).lineBefore && s.peek(1).kind == tsWord {
				s.take()
				continue
			}
			if tsOpen(text) {
				group := s.region()
				signature = text == "(" && group.parameterHead
			} else if t.kind == tsWord || t.kind == tsNumber || t.kind == tsString || t.kind == tsTemplate {
				s.take()
				if text == "import" && s.at("(") {
					s.region()
				}
				signature = false
			} else {
				break
			}
			complete = true
			continue
		}
		switch {
		case text == ".":
			s.take()
			if s.take().kind != tsWord {
				s.fail("qualified types require an identifier")
			}
			signature = false
		case text == "[" && !t.lineBefore:
			s.region()
			signature = false
		case text == "=>" && signature:
			s.take()
			complete, signature = false, false
		case text == "|" || text == "&":
			s.take()
			complete, signature = false, false
		case text == "extends" && !t.lineBefore:
			s.take()
			complete, signature, conditional = false, false, true
		case text == "is" && !t.lineBefore:
			s.take()
			complete, signature = false, false
		case text == "?" && conditional:
			s.take()
			questions++
			complete, signature, conditional = false, false, false
		case text == ":" && questions != 0:
			s.take()
			questions--
			complete, signature = false, false
		default:
			return s.err
		}
	}
	if s.err == nil && (!complete || questions != 0) {
		s.fail("incomplete exported type boundary")
	}
	return s.err
}

func tsInitializer(s *tsTokens) error {
	complete, parameters, async := false, false, false
	questions := 0
	for s.err == nil {
		t := s.peek(0)
		text := s.text(t)
		if t.kind == tsEnd || text == ";" || text == "," {
			break
		}
		if tsVariableAngle(s, text) {
			break
		}
		if !complete {
			switch text {
			case "+", "-", "!", "~", "++", "--", "typeof", "void", "delete", "await", "new":
				s.take()
				continue
			case "function":
				if err := tsFunctionValue(s); err != nil {
					return err
				}
				parameters = false
			case "class":
				if err := tsClassValue(s); err != nil {
					return err
				}
				parameters = false
			default:
				if tsOpen(text) {
					s.region()
					parameters = text == "("
				} else if t.kind == tsWord || t.kind == tsNumber || t.kind == tsString || t.kind == tsTemplate {
					s.take()
					parameters = false
				} else {
					return unsupportedTypeScriptSourceGrammar("incomplete exported initializer")
				}
			}
			complete, async = true, text == "async"
			continue
		}
		switch {
		case text == "(" || text == "[":
			s.region()
			parameters, async = text == "(", false
		case text == "." || text == "?.":
			s.take()
			if s.at("(") || s.at("[") {
				s.region()
			} else if s.take().kind != tsWord {
				s.fail("member access requires an identifier")
			}
			parameters, async = false, false
		case t.kind == tsTemplate:
			s.take()
			parameters, async = false, false
		case (text == "++" || text == "--" || text == "!") && !t.lineBefore:
			s.take()
			parameters, async = false, false
		case (text == "as" || text == "satisfies") && !t.lineBefore:
			s.take()
			if err := tsTypeOutline(s); err != nil {
				return err
			}
			parameters, async = false, false
		case text == "=>":
			s.take()
			complete, parameters, async = false, false, false
		case text == ":" && parameters && questions != 0 && tsConditionalArrowReturn(s):
			complete, parameters, async = false, false, false
		case text == ":" && parameters && questions == 0:
			s.take()
			if err := tsTypeOutline(s); err != nil {
				return err
			}
			if !s.at("=>") {
				return unsupportedTypeScriptSourceGrammar("arrow return type requires an arrow")
			}
			s.take()
			complete, parameters, async = false, false, false
		case text == "?":
			s.take()
			questions++
			complete, parameters, async = false, false, false
		case text == ":" && questions != 0:
			s.take()
			questions--
			complete, parameters, async = false, false, false
		case tsExpressionOperator(text):
			s.take()
			complete, parameters, async = false, false, false
		case async && !t.lineBefore && text == "function":
			if err := tsFunctionValue(s); err != nil {
				return err
			}
			parameters, async = false, false
		case async && !t.lineBefore && t.kind == tsWord && s.text(s.peek(1)) == "=>":
			s.take()
			async = false
		default:
			return s.err
		}
	}
	if s.err == nil && (!complete || questions != 0) {
		s.fail("incomplete exported initializer boundary")
	}
	return s.err
}

// In `c ? (x): T => x : y`, the first colon is a return annotation, not
// the conditional separator. A fixed token window cannot bound T's length.
// Probe only this ambiguity, streaming spans rather than buffering T. A failed
// type probe ends before another expression-level ambiguity: groups are opaque;
// ungrouped type conditionals require `extends`, which cannot continue an
// expression. Successful probes transfer their cursor, so do not rescan T.
func tsConditionalArrowReturn(s *tsTokens) bool {
	probe := *s
	probe.stack = append([]byte(nil), s.stack...)
	probe.take()
	if tsTypeOutline(&probe) != nil || !probe.at("=>") {
		return false
	}
	probe.take()
	*s = probe
	return true
}

func tsExpressionOperator(text string) bool {
	switch text {
	case "+", "-", "*", "**", "%", "&", "|", "^", "&&", "||", "??", "==", "!=", "===", "!==", "in", "instanceof",
		"=", "+=", "-=", "*=", "**=", "%=", "&=", "|=", "^=", "&&=", "||=", "??=":
		return true
	}
	return false
}

func tsFunctionValue(s *tsTokens) error {
	s.take()
	if s.at("*") {
		s.take()
	}
	if s.peek(0).kind == tsWord {
		s.take()
	}
	if !s.at("(") {
		return unsupportedTypeScriptSourceGrammar("function expression requires parameters")
	}
	s.region()
	if s.at(":") {
		s.take()
		if err := tsTypeOutline(s); err != nil {
			return err
		}
	}
	if !s.at("{") {
		return unsupportedTypeScriptSourceGrammar("function or class expression requires a body")
	}
	s.region()
	return s.err
}

// Every suspended class awaits one heritage primary, then resumes its suffix.
// Identical continuations compress to a counter; only primary-position class
// tokens push it. Bodies and groups stay opaque, so .class and interior class
// tokens never push. Each transition consumes input or advances to consumption.
func tsClassValue(s *tsTokens) error {
	const (
		header = iota
		primary
		suffix
		body
	)
	s.take()
	pending, state := 1, header
	for pending != 0 && s.err == nil {
		t := s.peek(0)
		text := s.text(t)
		if t.kind == tsEnd {
			return unsupportedTypeScriptSourceGrammar("class expression requires a body")
		}
		if tsVariableAngle(s, text) {
			return s.err
		}
		switch state {
		case header:
			if t.kind == tsWord && text != "extends" && text != "implements" {
				s.take()
			}
			if s.at("extends") {
				s.take()
				state = primary
			} else {
				state = body
			}
		case primary:
			if text == "async" && !s.peek(1).lineBefore && s.text(s.peek(1)) == "function" {
				s.take()
				text = "function"
			}
			switch text {
			case "new":
				s.take()
			case "class":
				s.take()
				pending++
				state = header
			case "function":
				if err := tsFunctionValue(s); err != nil {
					return err
				}
				state = suffix
			default:
				if tsOpen(text) {
					s.region()
				} else if t.kind == tsWord || t.kind == tsNumber || t.kind == tsString || t.kind == tsTemplate {
					s.take()
				} else {
					return unsupportedTypeScriptSourceGrammar("class heritage requires a value")
				}
				state = suffix
			}
		case suffix:
			switch {
			case text == "(" || text == "[":
				s.region()
			case text == "." || text == "?.":
				s.take()
				if s.at("(") || s.at("[") {
					s.region()
				} else if s.take().kind != tsWord {
					s.fail("class heritage member access requires an identifier")
				}
			case t.kind == tsTemplate || text == "!" && !t.lineBefore:
				s.take()
			default:
				state = body
			}
		case body:
			if s.at("implements") {
				s.take()
				for s.err == nil {
					if err := tsTypeOutline(s); err != nil {
						return err
					}
					if !s.at(",") {
						break
					}
					s.take()
				}
			}
			if !s.at("{") {
				return unsupportedTypeScriptSourceGrammar("class expression requires a body")
			}
			s.region()
			pending--
			state = suffix
		}
	}
	return s.err
}
