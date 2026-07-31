package gotestsource

import "go/ast"

func HasSkip(function *ast.FuncDecl) bool {
	paramName := TestingParameterName(function)
	if paramName == "" || function.Body == nil {
		return false
	}
	tainted := testingHandleAliases(function.Body, map[string]struct{}{paramName: {}})
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, trusted := tainted[receiver.Name]; !trusted {
			return true
		}
		switch selector.Sel.Name {
		case "Skip", "Skipf", "SkipNow":
			found = true
			return false
		default:
			return true
		}
	})
	return found
}

func HasFailureCapableAssertionCandidate(function *ast.FuncDecl, scopes ...map[string]*ast.FuncDecl) bool {
	functions := map[string]*ast.FuncDecl{}
	if len(scopes) > 0 {
		functions = scopes[0]
	}
	tainted := map[string]struct{}{}
	if parameter := TestingParameterName(function); parameter != "" {
		tainted[parameter] = struct{}{}
	}
	return hasFailureCapablePath(function, tainted, functions, map[*ast.FuncDecl]bool{})
}

func HasFailureCapableAssertionSyntax(function *ast.FuncDecl) bool {
	if function == nil || function.Body == nil {
		return false
	}
	parameter := TestingParameterName(function)
	tainted := testingHandleAliases(function.Body, map[string]struct{}{parameter: {}})
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "panic" {
			found = true
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, trusted := tainted[receiver.Name]; !trusted {
			return true
		}
		switch selector.Sel.Name {
		case "Error", "Errorf", "Fail", "FailNow", "Fatal", "Fatalf":
			found = true
			return false
		default:
			return true
		}
	})
	return found
}

func hasFailureCapablePath(function *ast.FuncDecl, tainted map[string]struct{}, functions map[string]*ast.FuncDecl, visiting map[*ast.FuncDecl]bool) bool {
	if function == nil || function.Body == nil || visiting[function] {
		return false
	}
	tainted = testingHandleAliases(function.Body, tainted)
	if hasTaintedSkip(function.Body, tainted) {
		return false
	}
	visiting[function] = true
	defer delete(visiting, function)
	return hasFailureCapableNode(function.Body, tainted, functions, visiting)
}

func hasFailureCapableNode(root ast.Node, tainted map[string]struct{}, functions map[string]*ast.FuncDecl, visiting map[*ast.FuncDecl]bool) bool {
	found := false
	ast.Inspect(root, func(node ast.Node) bool {
		if found {
			return false
		}
		switch typed := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			condition, constant := booleanConstant(typed.Cond)
			if !constant {
				return true
			}
			branch := ast.Node(typed.Body)
			if !condition {
				branch = typed.Else
			}
			if branch != nil && hasFailureCapableNode(branch, tainted, functions, visiting) {
				found = true
			}
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if identifier, ok := call.Fun.(*ast.Ident); ok {
			if identifier.Name == "panic" {
				found = true
				return false
			}
			callee, exists := functions[identifier.Name]
			if !exists {
				return true
			}
			calleeTainted := propagatedParameters(callee, call.Args, tainted)
			if hasFailureCapablePath(callee, calleeTainted, functions, visiting) {
				found = true
				return false
			}
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, trusted := tainted[receiver.Name]; !trusted {
			return true
		}
		if selector.Sel.Name == "Run" && len(call.Args) == 2 {
			literal, ok := call.Args[1].(*ast.FuncLit)
			if ok && literal.Type.Params != nil && len(literal.Type.Params.List) == 1 && len(literal.Type.Params.List[0].Names) == 1 {
				innerTainted := map[string]struct{}{literal.Type.Params.List[0].Names[0].Name: {}}
				innerTainted = testingHandleAliases(literal.Body, innerTainted)
				if !hasTaintedSkip(literal.Body, innerTainted) && hasFailureCapableNode(literal.Body, innerTainted, functions, visiting) {
					found = true
					return false
				}
			}
			return true
		}
		switch selector.Sel.Name {
		case "Error", "Errorf", "Fail", "FailNow", "Fatal", "Fatalf":
			found = true
			return false
		default:
			return true
		}
	})
	return found
}

func testingHandleAliases(root ast.Node, seed map[string]struct{}) map[string]struct{} {
	aliases := make(map[string]struct{}, len(seed))
	for name := range seed {
		if name != "" {
			aliases[name] = struct{}{}
		}
	}
	changed := true
	for changed {
		changed = false
		ast.Inspect(root, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch typed := node.(type) {
			case *ast.AssignStmt:
				if len(typed.Lhs) != len(typed.Rhs) {
					return true
				}
				for index := range typed.Lhs {
					if addTestingHandleAlias(aliases, typed.Lhs[index], typed.Rhs[index]) {
						changed = true
					}
				}
			case *ast.ValueSpec:
				if len(typed.Names) != len(typed.Values) {
					return true
				}
				for index := range typed.Names {
					if addTestingHandleAlias(aliases, typed.Names[index], typed.Values[index]) {
						changed = true
					}
				}
			}
			return true
		})
	}
	return aliases
}

func addTestingHandleAlias(aliases map[string]struct{}, target, source ast.Expr) bool {
	targetIdentifier, ok := target.(*ast.Ident)
	if !ok || targetIdentifier.Name == "_" {
		return false
	}
	sourceIdentifier, ok := unparenthesizedIdentifier(source)
	if !ok {
		return false
	}
	if _, trusted := aliases[sourceIdentifier.Name]; !trusted {
		return false
	}
	if _, exists := aliases[targetIdentifier.Name]; exists {
		return false
	}
	aliases[targetIdentifier.Name] = struct{}{}
	return true
}

func unparenthesizedIdentifier(expression ast.Expr) (*ast.Ident, bool) {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			identifier, ok := expression.(*ast.Ident)
			return identifier, ok
		}
		expression = parenthesized.X
	}
}

func hasTaintedSkip(root ast.Node, tainted map[string]struct{}) bool {
	found := false
	ast.Inspect(root, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, trusted := tainted[receiver.Name]; !trusted {
			return true
		}
		switch selector.Sel.Name {
		case "Skip", "Skipf", "SkipNow":
			found = true
			return false
		default:
			return true
		}
	})
	return found
}

func booleanConstant(expression ast.Expr) (bool, bool) {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return false, false
	}
	switch identifier.Name {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func propagatedParameters(function *ast.FuncDecl, arguments []ast.Expr, tainted map[string]struct{}) map[string]struct{} {
	result := map[string]struct{}{}
	if function.Type.Params == nil {
		return result
	}
	argumentIndex := 0
	for _, field := range function.Type.Params.List {
		if len(field.Names) == 0 {
			if argumentIndex < len(arguments) {
				argumentIndex++
			}
			continue
		}
		for _, name := range field.Names {
			if argumentIndex >= len(arguments) {
				return result
			}
			identifier, ok := arguments[argumentIndex].(*ast.Ident)
			if ok {
				if _, trusted := tainted[identifier.Name]; trusted {
					result[name.Name] = struct{}{}
				}
			}
			argumentIndex++
		}
	}
	return result
}

func TestingParameterName(function *ast.FuncDecl) string {
	if function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return ""
	}
	parameter := function.Type.Params.List[0]
	if len(parameter.Names) != 1 {
		return ""
	}
	return parameter.Names[0].Name
}
