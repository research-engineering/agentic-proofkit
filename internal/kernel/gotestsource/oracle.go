package gotestsource

import "go/ast"

func HasSkip(function *ast.FuncDecl) bool {
	paramName := testingParameterName(function)
	if paramName == "" || function.Body == nil {
		return false
	}
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
		if !ok || receiver.Name != paramName {
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

func testingParameterName(function *ast.FuncDecl) string {
	if function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return ""
	}
	parameter := function.Type.Params.List[0]
	if len(parameter.Names) != 1 {
		return ""
	}
	return parameter.Names[0].Name
}
