package publicapi

// Assignment frames retain boundaries, not expression trees. Conditional arms
// and ambiguous annotations need continuations; curried arrow tails do not.
type tsExpressionFrame struct {
	start, colon              int
	originalAllow, falseAllow bool
	wait                      uint8
}

type tsExpressionResult struct {
	end int
	err error
}

// Common expressions use only the inline frames. Segments avoid repeatedly
// copying an arbitrarily deep conditional stack as its backing array grows.
type tsExpressionFrames struct {
	inline   [8]tsExpressionFrame
	segments []*[256]tsExpressionFrame
	length   int
}

func (f *tsExpressionFrames) at(index int) *tsExpressionFrame {
	if index < len(f.inline) {
		return &f.inline[index]
	}
	index -= len(f.inline)
	return &f.segments[index/256][index%256]
}

func (f *tsExpressionFrames) push(frame tsExpressionFrame) {
	if f.length >= len(f.inline) && (f.length-len(f.inline))/256 == len(f.segments) {
		f.segments = append(f.segments, new([256]tsExpressionFrame))
	}
	*f.at(f.length) = frame
	f.length++
}

func (f *tsExpressionFrames) top() *tsExpressionFrame { return f.at(f.length - 1) }
func (f *tsExpressionFrames) pop() tsExpressionFrame {
	f.length--
	return *f.at(f.length)
}

// Most memo results are just endpoints. Error records are stored separately,
// rather than reserving an error interface in every successful cache slot.
type tsExpressionMemo struct {
	ends     map[int]int
	failures []tsExpressionResult
}

func tsExpressionMemoKey(pos int, allow bool) int {
	key := pos << 1
	if allow {
		key++
	}
	return key
}

func (m *tsExpressionMemo) get(pos int, allow bool) (tsExpressionResult, bool) {
	end, ok := m.ends[tsExpressionMemoKey(pos, allow)]
	if !ok {
		return tsExpressionResult{}, false
	}
	if end < 0 {
		return m.failures[-end-1], true
	}
	return tsExpressionResult{end: end}, true
}

func (m *tsExpressionMemo) put(pos int, allow bool, result tsExpressionResult) {
	if m.ends == nil {
		return
	}
	key := tsExpressionMemoKey(pos, allow)
	if _, exists := m.ends[key]; exists {
		return
	}
	end := result.end
	if result.err != nil {
		m.failures = append(m.failures, result)
		end = -len(m.failures)
	}
	m.ends[key] = end
}

// Expression tasks start outside opaque regions. Replay includes leading
// trivia, preserving all line-terminator facts instead of reconstructing them.
func tsExpressionSeek(s *tsTokens, pos int) {
	*s = tsTokens{source: s.source, pos: pos, stack: s.stack[:0]}
}

func tsInitializer(s *tsTokens) error {
	const (
		trueArm = iota + 1
		falseArm
		annotationBody
		ambiguousParameters = 1
		definiteParameters  = 2
		highest             = 16
		relational          = 11
	)
	var frames tsExpressionFrames
	frames.push(tsExpressionFrame{start: s.peek(0).leading, originalAllow: true})
	var memo tsExpressionMemo
	allow, complete, postfix, head, async := true, false, false, true, false
	parameters, binaryFloor, assertionLimit := 0, highest, highest
	done := false
	var failure error
	reset := func(context bool) {
		allow, complete, postfix, head, async = context, false, false, true, false
		parameters, binaryFloor, assertionLimit = 0, highest, highest
		done, failure = false, nil
	}
	finish := func(err error) { done, failure = true, err }
	resume := func(context bool) {
		if cached, ok := memo.get(s.peek(0).leading, context); ok {
			tsExpressionSeek(s, cached.end)
			finish(cached.err)
		} else {
			reset(context)
		}
	}
	enter := func(context bool) {
		frames.push(tsExpressionFrame{start: s.peek(0).leading, originalAllow: context})
		resume(context)
	}
	arrowBody := func(context bool) {
		if s.at("{") {
			s.region()
			finish(s.err)
		} else {
			resume(context)
		}
	}
	cover := func(group tsRegion) int {
		if !group.parameterHead {
			return 0
		}
		if group.definiteParameters {
			return definiteParameters
		}
		return ambiguousParameters
	}
	for {
		if done {
			if failure == nil {
				failure = s.err
			}
			frame := frames.pop()
			memo.put(frame.start, frame.originalAllow, tsExpressionResult{s.peek(0).leading, failure})
			if frames.length == 0 {
				return failure
			}
			parent := frames.top()
			switch parent.wait {
			case trueArm:
				if failure == nil {
					if !s.at(":") {
						finish(unsupportedTypeScriptSourceGrammar("conditional initializer requires a colon"))
					} else {
						s.take()
						parent.wait = falseArm
						enter(parent.falseAllow)
					}
				}
			case annotationBody:
				if failure != nil || !s.at(":") {
					tsExpressionSeek(s, parent.colon)
					finish(nil)
				}
			}
			continue
		}
		if s.err != nil {
			finish(s.err)
			continue
		}
		t := s.peek(0)
		text := s.text(t)
		if t.kind == tsEnd || text == ";" || text == "," {
			if complete {
				finish(s.err)
			} else {
				finish(unsupportedTypeScriptSourceGrammar("incomplete exported initializer boundary"))
			}
			continue
		}
		if tsVariableAngle(s, text) {
			finish(s.err)
			continue
		}
		if !complete {
			if text == "async" && !s.peek(1).lineBefore && s.text(s.peek(1)) == "function" {
				s.take()
				text = "function"
			}
			switch text {
			case "+", "-", "!", "~", "++", "--", "typeof", "void", "delete", "await", "new":
				s.take()
				head = false
				continue
			case "function":
				if err := tsFunctionValue(s); err != nil {
					finish(err)
					continue
				}
			case "class":
				if err := tsClassValue(s); err != nil {
					finish(err)
					continue
				}
			case "@":
				if err := tsDecoratedClassValue(s); err != nil {
					finish(err)
					continue
				}
			default:
				if tsOpen(text) {
					group := s.region()
					if text == "(" && head {
						parameters = cover(group)
					}
				} else if t.kind == tsWord || t.kind == tsNumber || t.kind == tsString || t.kind == tsTemplate {
					s.take()
				} else {
					finish(unsupportedTypeScriptSourceGrammar("incomplete exported initializer"))
					continue
				}
			}
			complete, postfix, async = true, true, head && text == "async"
			continue
		}
		switch {
		case postfix && (text == "(" || text == "["):
			group := s.region()
			parameters = 0
			if async && !t.lineBefore && text == "(" {
				parameters = cover(group)
			}
			async = false
		case postfix && (text == "." || text == "?."):
			s.take()
			if s.at("(") || s.at("[") {
				s.region()
			} else if s.take().kind != tsWord {
				s.fail("member access requires an identifier")
			}
			parameters, async = 0, false
		case postfix && t.kind == tsTemplate:
			s.take()
			parameters, async = 0, false
		case postfix && text == "!" && !t.lineBefore:
			s.take()
			parameters, async = 0, false
		case postfix && (text == "++" || text == "--") && !t.lineBefore:
			s.take()
			postfix, parameters, async = false, 0, false
		case (text == "as" || text == "satisfies") && !t.lineBefore:
			s.take()
			if err := tsTypeOutline(s); err != nil {
				finish(err)
			}
			postfix, parameters, async = false, 0, false
			assertionLimit = binaryFloor
		case text == "=>":
			s.take()
			arrowBody(allow || parameters == definiteParameters)
		case text == ":" && parameters != 0:
			colon := t.leading
			s.take()
			err := tsTypeOutline(s)
			if err != nil || !s.at("=>") {
				if !allow && parameters == ambiguousParameters {
					tsExpressionSeek(s, colon)
					finish(nil)
				} else if err != nil {
					finish(err)
				} else {
					finish(unsupportedTypeScriptSourceGrammar("arrow return type requires an arrow"))
				}
				continue
			}
			s.take()
			if allow || parameters == definiteParameters {
				arrowBody(true)
			} else if s.at("{") {
				s.region()
				if s.err != nil || !s.at(":") {
					tsExpressionSeek(s, colon)
				}
				finish(nil)
			} else {
				if memo.ends == nil {
					memo.ends = make(map[int]int)
				}
				parent := frames.top()
				parent.wait, parent.colon = annotationBody, colon
				enter(false)
			}
		case text == "?":
			s.take()
			parent := frames.top()
			parent.wait, parent.falseAllow = trueArm, allow
			enter(false)
		case tsAssignmentOperator(text):
			s.take()
			resume(allow)
		case tsBinaryPrecedence(text) != 0:
			precedence := tsBinaryPrecedence(text)
			if precedence > assertionLimit {
				finish(nil)
				continue
			}
			s.take()
			if precedence < relational {
				binaryFloor = highest
			} else {
				binaryFloor = min(binaryFloor, precedence)
			}
			assertionLimit = highest
			complete, postfix, head, parameters, async = false, false, false, 0, false
		case async && !t.lineBefore && t.kind == tsWord && s.text(s.peek(1)) == "=>":
			s.take()
			async = false
		default:
			finish(nil)
		}
	}
}

func tsDecoratedClassValue(s *tsTokens) error {
	for s.at("@") && s.err == nil {
		s.take()
		if s.at("(") {
			s.region()
		} else if s.take().kind != tsWord {
			return unsupportedTypeScriptSourceGrammar("decorator requires an expression")
		}
		for s.err == nil {
			if s.at("(") {
				s.region()
			} else if s.at(".") {
				s.take()
				if s.take().kind != tsWord {
					return unsupportedTypeScriptSourceGrammar("decorator member requires an identifier")
				}
			} else if s.at("!") && !s.peek(0).lineBefore {
				s.take()
			} else {
				break
			}
		}
	}
	if s.err != nil {
		return s.err
	}
	if !s.at("class") {
		return unsupportedTypeScriptSourceGrammar("decorated initializer requires a class")
	}
	return tsClassValue(s)
}

func tsAssignmentOperator(text string) bool {
	switch text {
	case "=", "+=", "-=", "*=", "**=", "%=", "&=", "|=", "^=", "&&=", "||=", "??=":
		return true
	}
	return false
}

func tsBinaryPrecedence(text string) int {
	switch text {
	case "??", "||":
		return 2
	case "&&":
		return 3
	case "|":
		return 5
	case "^":
		return 6
	case "&":
		return 7
	case "==", "!=", "===", "!==":
		return 10
	case "in", "instanceof":
		return 11
	case "+", "-":
		return 13
	case "*", "%":
		return 14
	case "**":
		return 15
	}
	return 0
}
