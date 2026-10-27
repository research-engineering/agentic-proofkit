package requirementbrowser

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
)

// The design-token literal grammar. Its inputs are the token stylesheet, the
// static style (the single <style> of a browserdoc page without the token
// stylesheet prefix), workspace.css, every workspace script and the rendered
// HTML of every static view fixture and of the workspace. The two style owners
// are the static style and workspace.css.

type designTokenSources struct {
	tokens        string
	staticStyle   string
	workspaceCSS  string
	scripts       map[string]string
	staticHTML    map[string]string
	workspaceHTML map[string]string
}

type designTokenViolation struct {
	rule   int
	source string
	detail string
}

func (violation designTokenViolation) String() string {
	return fmt.Sprintf("rule %d: %s: %s", violation.rule, violation.source, violation.detail)
}

const (
	tokenSourceName        = "tokens.css"
	staticStyleSourceName  = "static style"
	workspaceCSSSourceName = "workspace.css"
)

// Literal colors: hash tokens, the color functions, named colors, system
// colors, transparent and vendor-prefixed keywords other than the admitted
// non-color ones. currentColor, none and the CSS-wide keywords are not
// literals.
var cssColorFunctions = designTokenSet("rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch", "color", "color-mix", "contrast-color", "light-dark")

var cssSystemColors = designTokenSet(
	"accentcolor", "accentcolortext", "activetext", "buttonborder", "buttonface", "buttontext", "canvas", "canvastext",
	"field", "fieldtext", "graytext", "highlight", "highlighttext", "linktext", "mark", "marktext", "selecteditem",
	"selecteditemtext", "visitedtext",
	// Deprecated system colors remain valid color keywords.
	"activeborder", "activecaption", "appworkspace", "background", "buttonhighlight", "buttonshadow", "captiontext",
	"inactiveborder", "inactivecaption", "inactivecaptiontext", "infobackground", "infotext", "menu", "menutext",
	"scrollbar", "threeddarkshadow", "threedface", "threedhighlight", "threedlightshadow", "threedshadow", "window",
	"windowframe", "windowtext",
)

var cssNamedColors = designTokenSet(
	"aliceblue", "antiquewhite", "aqua", "aquamarine", "azure", "beige", "bisque", "black", "blanchedalmond", "blue",
	"blueviolet", "brown", "burlywood", "cadetblue", "chartreuse", "chocolate", "coral", "cornflowerblue", "cornsilk",
	"crimson", "cyan", "darkblue", "darkcyan", "darkgoldenrod", "darkgray", "darkgreen", "darkgrey", "darkkhaki",
	"darkmagenta", "darkolivegreen", "darkorange", "darkorchid", "darkred", "darksalmon", "darkseagreen",
	"darkslateblue", "darkslategray", "darkslategrey", "darkturquoise", "darkviolet", "deeppink", "deepskyblue",
	"dimgray", "dimgrey", "dodgerblue", "firebrick", "floralwhite", "forestgreen", "fuchsia", "gainsboro", "ghostwhite",
	"gold", "goldenrod", "gray", "green", "greenyellow", "grey", "honeydew", "hotpink", "indianred", "indigo", "ivory",
	"khaki", "lavender", "lavenderblush", "lawngreen", "lemonchiffon", "lightblue", "lightcoral", "lightcyan",
	"lightgoldenrodyellow", "lightgray", "lightgreen", "lightgrey", "lightpink", "lightsalmon", "lightseagreen",
	"lightskyblue", "lightslategray", "lightslategrey", "lightsteelblue", "lightyellow", "lime", "limegreen", "linen",
	"magenta", "maroon", "mediumaquamarine", "mediumblue", "mediumorchid", "mediumpurple", "mediumseagreen",
	"mediumslateblue", "mediumspringgreen", "mediumturquoise", "mediumvioletred", "midnightblue", "mintcream",
	"mistyrose", "moccasin", "navajowhite", "navy", "oldlace", "olive", "olivedrab", "orange", "orangered", "orchid",
	"palegoldenrod", "palegreen", "paleturquoise", "palevioletred", "papayawhip", "peachpuff", "peru", "pink", "plum",
	"powderblue", "purple", "rebeccapurple", "red", "rosybrown", "royalblue", "saddlebrown", "salmon", "sandybrown",
	"seagreen", "seashell", "sienna", "silver", "skyblue", "slateblue", "slategray", "slategrey", "snow", "springgreen",
	"steelblue", "tan", "teal", "thistle", "tomato", "turquoise", "violet", "wheat", "white", "whitesmoke", "yellow",
	"yellowgreen",
)

// Literal sizes: a dimension with a nonzero value in any unit, a nonzero
// number or percentage in a size property, and the size keywords. Zero, a
// percentage or fr in a layout property and a unitless number in a property
// that is not a size are allowed.
var cssSizeKeywords = designTokenSet("thin", "medium", "thick", "xx-small", "x-small", "small", "large", "x-large", "xx-large", "xxx-large", "smaller", "larger")

// A unitless number in these properties is a size: a font or line size, a
// tab width in spaces, an outline or stroke size, an SVG geometry property, a
// scale factor or a perspective distance.
var cssNumberSizeProperties = designTokenSet(
	"font", "font-size", "font-size-adjust", "line-height", "letter-spacing", "word-spacing", "tab-size",
	"outline-width", "outline-offset", "stroke-width", "stroke-dasharray", "stroke-dashoffset",
	"cx", "cy", "r", "rx", "ry", "x", "y", "zoom", "scale", "perspective", "transform",
)

// Vendor-prefixed keywords can name engine colors such as -webkit-link or
// -moz-hyperlinktext, so every one is a literal color except these non-color
// keywords that the style owners use: a layout display value and a font family.
var admittedVendorKeywords = designTokenSet("-webkit-box", "-apple-system")

// isVendorKeyword reports an ident that begins with one hyphen and holds a
// second hyphen, such as -webkit-link; custom property names begin with two.
func isVendorKeyword(name string) bool {
	return strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "--") && strings.Contains(name[1:], "-")
}

// unprefixedProperty returns a property name without its vendor prefix, so
// that -webkit-transform is classified as transform and -moz-tab-size as
// tab-size.
func unprefixedProperty(property string) string {
	if isVendorKeyword(property) {
		return property[strings.Index(property[1:], "-")+2:]
	}
	return property
}

func isLiteralColorKeyword(name string) bool {
	name = strings.ToLower(name)
	return cssNamedColors[name] || cssSystemColors[name] || name == "transparent" || (isVendorKeyword(name) && !admittedVendorKeywords[name])
}

var cssLayoutProperties = designTokenSet(
	"width", "height", "min-width", "min-height", "max-width", "max-height", "inline-size", "block-size",
	"min-inline-size", "min-block-size", "max-inline-size", "max-block-size", "inset", "inset-block", "inset-inline",
	"inset-block-start", "inset-block-end", "inset-inline-start", "inset-inline-end", "top", "right", "bottom", "left",
	"transform", "translate", "flex", "flex-basis", "grid-template", "grid-template-columns", "grid-template-rows",
	"grid-auto-columns", "grid-auto-rows",
)

// The graph owner projects GEOMETRY; the panel owner projects the observed
// product-bar height without changing its token-owned design minimum.
var designTokenGeometryProperties = designTokenSet("--graph-card-width", "--graph-card-height", "--graph-edge-stroke", "--workspace-product-bar-height")

func designTokenSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func isNumberSizeProperty(property string) bool {
	return cssNumberSizeProperties[property] || (strings.HasPrefix(property, "border") && strings.HasSuffix(property, "-width"))
}

// loadDesignTokenSources reads the shipped inputs of the grammar.
func loadDesignTokenSources() (designTokenSources, error) {
	tokens := browserdoc.TokenStylesheet()
	page := browserdoc.HTML(browserdoc.Document{})
	start, end := strings.Index(page, "<style>"), strings.Index(page, "</style>")
	if start < 0 || end < start || strings.Count(page, "<style>") != 1 {
		return designTokenSources{}, fmt.Errorf("browserdoc page has no single style element")
	}
	style := page[start+len("<style>") : end]
	if !strings.HasPrefix(style, tokens) {
		return designTokenSources{}, fmt.Errorf("browserdoc style does not begin with the token stylesheet")
	}
	sources := designTokenSources{
		tokens: tokens, staticStyle: strings.TrimPrefix(style, tokens), workspaceCSS: string(workspaceCSS),
		scripts: map[string]string{}, staticHTML: map[string]string{}, workspaceHTML: map[string]string{},
	}
	entries, err := os.ReadDir("assets")
	if err != nil {
		return designTokenSources{}, err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".js" {
			continue
		}
		source, err := os.ReadFile(filepath.Join("assets", entry.Name()))
		if err != nil {
			return designTokenSources{}, err
		}
		sources.scripts[entry.Name()] = string(source)
	}
	for _, fixture := range designTokenViewFixtures() {
		raw, err := fixture.build()
		if err != nil {
			return designTokenSources{}, err
		}
		rendered, err := render(raw, fixture.options)
		if err != nil {
			return designTokenSources{}, fmt.Errorf("%s: %w", fixture.name, err)
		}
		if fixture.options.View == "workspace" {
			sources.workspaceHTML[fixture.name] = rendered.html
		} else {
			sources.staticHTML[fixture.name] = rendered.html
		}
	}
	return sources, nil
}

type designTokenViewFixture struct {
	name    string
	build   func() (map[string]any, error)
	options Options
}

// designTokenViewFixtures are the static view fixtures and the workspace
// fixture of the browser test server.
func designTokenViewFixtures() []designTokenViewFixture {
	return []designTokenViewFixture{
		{name: "static source", build: browserfixture.StaticSource, options: Options{View: "source"}},
		{name: "static spec tree", build: browserfixture.StaticTree, options: Options{View: "spec-tree"}},
		{name: "static structured proof", build: browserfixture.StaticProof, options: Options{View: "proof"}},
		{name: "static compact proof", build: browserfixture.StaticCompactProof, options: Options{View: "proof", LocalEnvironmentClasses: []string{"local-go"}}},
		{name: "static coverage", build: func() (map[string]any, error) { return browserfixture.CoverageInput("structured") }, options: Options{View: "coverage"}},
		{name: "workspace", build: func() (map[string]any, error) { return browserfixture.CoverageWorkspace("structured", false) }, options: Options{View: "workspace"}},
	}
}

// designTokenTable is the parsed token stylesheet: the values of each token in
// the base :root context, the dark color-scheme context and the forced-colors
// context, with the category of each value.
type designTokenTable struct {
	base, dark, forced map[string]string
	category           map[string]map[string]string
	palette            map[string]bool
	breakpoints        map[string]string
}

func (table designTokenTable) declared(name string) bool {
	_, base := table.base[name]
	_, dark := table.dark[name]
	_, forced := table.forced[name]
	return base || dark || forced
}

func checkDesignTokenGrammar(sources designTokenSources) []designTokenViolation {
	violations := []designTokenViolation{}
	add := func(rule int, source, format string, args ...any) {
		violations = append(violations, designTokenViolation{rule: rule, source: source, detail: fmt.Sprintf(format, args...)})
	}
	tokenNodes, err := parseStylesheet(sources.tokens)
	if err != nil {
		add(4, tokenSourceName, "does not parse: %v", err)
		return violations
	}
	table := checkTokenStylesheet(tokenNodes, add)
	owners := []struct{ name, source string }{{staticStyleSourceName, sources.staticStyle}, {workspaceCSSSourceName, sources.workspaceCSS}}
	referenced := map[string]bool{}
	for _, owner := range owners {
		nodes, err := parseStylesheet(owner.source)
		if err != nil {
			add(1, owner.name, "does not parse: %v", err)
			continue
		}
		checkStyleOwner(owner.name, nodes, table, referenced, add)
	}
	for _, source := range []struct{ name, text string }{{tokenSourceName, sources.tokens}, {staticStyleSourceName, sources.staticStyle}, {workspaceCSSSourceName, sources.workspaceCSS}} {
		checkExternalResources(source.name, source.text, add)
	}
	for _, source := range []struct {
		name  string
		nodes func() ([]cssNode, error)
	}{
		{tokenSourceName, func() ([]cssNode, error) { return tokenNodes, nil }},
		{staticStyleSourceName, func() ([]cssNode, error) { return parseStylesheet(sources.staticStyle) }},
		{workspaceCSSSourceName, func() ([]cssNode, error) { return parseStylesheet(sources.workspaceCSS) }},
	} {
		nodes, err := source.nodes()
		if err == nil {
			checkConditionLengths(source.name, nodes, table, referenced, add)
		}
	}
	for _, name := range sortedKeys(sources.scripts) {
		checkScript(name, sources.scripts[name], table, referenced, add)
	}
	for _, name := range sortedKeys(sources.staticHTML) {
		checkRenderedHTML(name, sources.staticHTML[name], 1, table, referenced, add)
	}
	for _, name := range sortedKeys(sources.workspaceHTML) {
		checkRenderedHTML(name, sources.workspaceHTML[name], 0, table, referenced, add)
	}
	for _, name := range allTokenNames(table) {
		if !referenced[name] {
			add(2, tokenSourceName, "token %s is not used by a style owner, a matchMedia query or a media attribute of rendered HTML", name)
		}
	}
	return violations
}

// Token value categories: a value that holds a literal color, a value that
// holds a literal size, and a value that holds neither.
const (
	tokenCategoryColor   = "color"
	tokenCategorySize    = "size"
	tokenCategoryNeither = "neither"
)

func tokenValueCategory(value []cssToken) string {
	if containsLiteralColor(value) {
		return tokenCategoryColor
	}
	for _, token := range value {
		switch token.kind {
		case cssDimension, cssPercentage, cssNumber:
			if token.number != 0 {
				return tokenCategorySize
			}
		case cssIdent:
			if cssSizeKeywords[strings.ToLower(token.value)] {
				return tokenCategorySize
			}
		}
	}
	return tokenCategoryNeither
}

// checkTokenStylesheet applies rule 4 and the context parts of rule 2 to the
// token stylesheet and returns its token table. A palette token is a token
// whose base value, which both color schemes read, holds a literal color.
func checkTokenStylesheet(nodes []cssNode, add func(int, string, string, ...any)) designTokenTable {
	table := designTokenTable{
		base: map[string]string{}, dark: map[string]string{}, forced: map[string]string{},
		category: map[string]map[string]string{"base": {}, "dark": {}, "forced-colors": {}},
		palette:  map[string]bool{}, breakpoints: map[string]string{},
	}
	declare := func(context map[string]string, contextName string, rule cssNode) {
		if rule.kind != cssQualifiedRule || compactCSSText(rule.prelude) != ":root" {
			add(4, tokenSourceName, "%s context holds a rule other than :root", contextName)
			return
		}
		for _, declaration := range rule.children {
			if declaration.kind != cssDeclaration || !strings.HasPrefix(declaration.name, "--") {
				add(4, tokenSourceName, "%s :root declares %q, which is not a custom property", contextName, declaration.name)
				continue
			}
			if declaration.important || len(declaration.value) == 0 {
				add(4, tokenSourceName, "%s token %s is empty or important", contextName, declaration.name)
				continue
			}
			if _, duplicate := context[declaration.name]; duplicate {
				add(4, tokenSourceName, "%s context declares %s twice", contextName, declaration.name)
			}
			context[declaration.name] = cssText(declaration.value)
			table.category[contextName][declaration.name] = tokenValueCategory(declaration.value)
			for _, token := range declaration.value {
				if token.kind == cssFunction && strings.EqualFold(token.value, "var") {
					add(4, tokenSourceName, "token %s refers to a custom property", declaration.name)
				}
				if token.kind == cssFunction && strings.EqualFold(token.value, "attr") {
					add(4, tokenSourceName, "token %s refers to an attribute", declaration.name)
				}
				if token.kind == cssIdent && cssSystemColors[strings.ToLower(token.value)] && contextName != "forced-colors" {
					add(4, tokenSourceName, "%s token %s uses a system color outside forced-colors", contextName, declaration.name)
				}
			}
			if contextName == "forced-colors" && (len(declaration.value) != 1 || declaration.value[0].kind != cssIdent || !cssSystemColors[strings.ToLower(declaration.value[0].value)]) {
				add(4, tokenSourceName, "forced-colors token %s is not one system color", declaration.name)
			}
			if contextName == "base" && containsLiteralColor(declaration.value) {
				table.palette[declaration.name] = true
			}
		}
	}
	for _, node := range nodes {
		switch {
		case node.kind == cssQualifiedRule:
			declare(table.base, "base", node)
		case node.kind == cssAtRule && node.name == "media" && node.hasBlock && compactCSSText(node.prelude) == "(prefers-color-scheme:dark)":
			for _, child := range node.children {
				declare(table.dark, "dark", child)
			}
		case node.kind == cssAtRule && node.name == "media" && node.hasBlock && compactCSSText(node.prelude) == "(forced-colors:active)":
			for _, child := range node.children {
				declare(table.forced, "forced-colors", child)
			}
		default:
			add(4, tokenSourceName, "holds @%s %s, which is not one of the three token contexts", node.name, cssText(node.prelude))
		}
	}
	for name, value := range table.base {
		if strings.HasPrefix(name, "--breakpoint-") {
			tokens, _ := tokenizeCSS(value)
			if len(tokens) != 1 || tokens[0].kind != cssDimension {
				add(4, tokenSourceName, "breakpoint token %s is not one length", name)
			}
			table.breakpoints[name] = value
		}
	}
	for _, name := range sortedKeys(table.dark) {
		if !table.palette[name] {
			add(2, tokenSourceName, "dark token %s is not a palette token declared in the base context", name)
		}
	}
	// The palette switches with the color scheme: every palette token has a
	// dark value as well as its light base value.
	for _, name := range sortedKeys(table.palette) {
		if _, dark := table.dark[name]; !dark {
			add(2, tokenSourceName, "palette token %s has no dark color-scheme value", name)
		}
	}
	for _, name := range sortedKeys(table.forced) {
		_, base := table.base[name]
		_, dark := table.dark[name]
		if base || dark {
			add(4, tokenSourceName, "forced-colors token %s is also declared outside forced-colors", name)
		}
	}
	// A dark or forced-colors redeclaration keeps the category of the base
	// value: a color stays a color and a size stays a size.
	for _, contextName := range []string{"dark", "forced-colors"} {
		for _, name := range sortedKeys(table.category[contextName]) {
			base, ok := table.category["base"][name]
			if got := table.category[contextName][name]; ok && got != base {
				add(2, tokenSourceName, "%s token %s redeclares a %s base value with a %s value", contextName, name, base, got)
			}
		}
	}
	return table
}

func containsLiteralColor(tokens []cssToken) bool {
	for _, token := range tokens {
		switch token.kind {
		case cssHash:
			return true
		case cssFunction:
			if cssColorFunctions[strings.ToLower(token.value)] {
				return true
			}
		case cssIdent:
			if isLiteralColorKeyword(token.value) {
				return true
			}
		}
	}
	return false
}

// schemeSwitch names how CSS tokens can switch styles on the color scheme
// outside the palette tokens, or returns "": a prefers-color-scheme media
// feature, a style() query, which can test a palette token's value, or an
// if() function, which can test either inside a declaration value. Names are
// compared unescaped, so an escaped spelling such as prefers-color-sch\65me
// is the same feature.
func schemeSwitch(tokens []cssToken) string {
	for _, token := range tokens {
		name := strings.ToLower(token.value)
		switch {
		case (token.kind == cssIdent || token.kind == cssFunction) && strings.Contains(name, "prefers-color-scheme"):
			return "a prefers-color-scheme condition"
		case token.kind == cssFunction && name == "style":
			return "a style() query"
		case token.kind == cssFunction && name == "if":
			return "an if() function"
		}
	}
	return ""
}

// checkStyleOwner applies rules 1, 2 and 3 to one style owner and records
// the tokens it reads in referenced.
func checkStyleOwner(owner string, nodes []cssNode, table designTokenTable, referenced map[string]bool, add func(int, string, string, ...any)) {
	declared := map[string]bool{}
	type reference struct {
		name   string
		forced bool
	}
	references := []reference{}
	var walk func(nodes []cssNode, forced bool)
	walk = func(nodes []cssNode, forced bool) {
		for _, node := range nodes {
			switch node.kind {
			case cssAtRule:
				// The palette tokens switch the color scheme, so a style owner
				// holds no at-rule conditioned on it, in any at-rule and in any
				// spelling.
				if reason := schemeSwitch(node.prelude); reason != "" {
					add(2, owner, "holds @%s %s, %s; the palette tokens switch the color scheme", node.name, cssText(node.prelude), reason)
				}
				walk(node.children, forced || (node.name == "media" && compactCSSText(node.prelude) == "(forced-colors:active)"))
			case cssQualifiedRule:
				walk(node.children, forced)
			case cssDeclaration:
				rule := 1
				if strings.HasPrefix(node.name, "--") {
					rule = 3
					declared[node.name] = true
				}
				for _, problem := range literalProblems(node.name, node.value) {
					add(rule, owner, "%s: %s", node.name, problem)
				}
				if reason := schemeSwitch(node.value); reason != "" {
					add(2, owner, "%s holds %s; the palette tokens switch the color scheme", node.name, reason)
				}
				for _, name := range varReferences(node.value) {
					references = append(references, reference{name: name, forced: forced})
				}
			}
		}
	}
	walk(nodes, false)
	for _, name := range sortedKeys(declared) {
		if table.declared(name) || designTokenGeometryProperties[name] {
			add(2, owner, "declares %s, which shadows a token or a geometry property", name)
		}
	}
	for _, ref := range references {
		_, forcedToken := table.forced[ref.name]
		switch {
		case forcedToken && !ref.forced:
			add(2, owner, "uses forced-colors token %s outside @media (forced-colors: active)", ref.name)
		case table.declared(ref.name):
			referenced[ref.name] = true
		case declared[ref.name] || designTokenGeometryProperties[ref.name]:
		default:
			add(2, owner, "var(%s) names no token, owner custom property or geometry property", ref.name)
		}
	}
}

// literalProblems returns the literal colors and sizes of one declaration
// value, including inside calc, min, max, clamp and var fallbacks, every var()
// that is not exactly var(--name) and every attr(), which reads a value from
// the markup instead of the token set. A vendor-prefixed property is
// classified as the property without its prefix.
func literalProblems(property string, value []cssToken) []string {
	problems := []string{}
	custom := strings.HasPrefix(property, "--")
	category := unprefixedProperty(property)
	for index := 0; index < len(value); index++ {
		token := value[index]
		switch token.kind {
		case cssHash:
			problems = append(problems, "literal color "+token.text)
		case cssFunction:
			name := strings.ToLower(token.value)
			if cssColorFunctions[name] {
				problems = append(problems, "literal color "+token.text+"...)")
			}
			if name == "var" {
				arguments := significantArguments(value[index+1:])
				if len(arguments) != 2 || arguments[0].kind != cssIdent || !strings.HasPrefix(arguments[0].value, "--") || arguments[1].kind != cssCloseParen {
					problems = append(problems, "var() is not exactly var(--name)")
				}
			}
			if name == "attr" {
				problems = append(problems, "attr() reads a value outside the token set")
			}
		case cssIdent:
			name := strings.ToLower(token.value)
			switch {
			case isLiteralColorKeyword(name):
				problems = append(problems, "literal color "+token.text)
			case cssSizeKeywords[name]:
				problems = append(problems, "size keyword "+token.text)
			}
		case cssDimension:
			if token.number != 0 && (custom || strings.ToLower(token.unit) != "fr" || !cssLayoutProperties[category]) {
				problems = append(problems, "literal size "+token.text)
			}
		case cssPercentage:
			if token.number != 0 && (custom || !cssLayoutProperties[category]) {
				problems = append(problems, "literal size "+token.text)
			}
		case cssNumber:
			if token.number != 0 && (custom || isNumberSizeProperty(category)) {
				problems = append(problems, "literal size "+token.text)
			}
		}
	}
	return problems
}

// significantArguments returns the non-whitespace tokens of one function
// call, through its closing parenthesis.
func significantArguments(tokens []cssToken) []cssToken {
	arguments := []cssToken{}
	depth := 0
	for _, token := range tokens {
		switch token.kind {
		case cssWhitespace:
			continue
		case cssFunction, cssOpenParen, cssOpenSquare:
			depth++
		case cssCloseParen, cssCloseSquare:
			if depth == 0 {
				return append(arguments, token)
			}
			depth--
		}
		arguments = append(arguments, token)
	}
	return arguments
}

func varReferences(value []cssToken) []string {
	names := []string{}
	for index, token := range value {
		if token.kind == cssFunction && strings.EqualFold(token.value, "var") {
			if arguments := significantArguments(value[index+1:]); len(arguments) > 0 && arguments[0].kind == cssIdent {
				names = append(names, arguments[0].value)
			}
		}
	}
	return names
}

// checkExternalResources applies rule 5 to one stylesheet.
func checkExternalResources(source, text string, add func(int, string, string, ...any)) {
	tokens, err := tokenizeCSS(text)
	if err != nil {
		add(5, source, "does not tokenize: %v", err)
		return
	}
	for _, token := range tokens {
		switch {
		case token.kind == cssAtKeyword && (strings.EqualFold(token.value, "import") || strings.EqualFold(token.value, "font-face")):
			add(5, source, "uses @%s", token.value)
		case token.kind == cssURL || token.kind == cssBadURL:
			add(5, source, "uses url(")
		case token.kind == cssFunction && slices.Contains([]string{"url", "image-set", "-webkit-image-set"}, strings.ToLower(token.value)):
			add(5, source, "uses %s", token.text)
		}
	}
}

// checkConditionLengths applies rule 6 to the @media and @container
// conditions of one stylesheet.
func checkConditionLengths(source string, nodes []cssNode, table designTokenTable, referenced map[string]bool, add func(int, string, string, ...any)) {
	for _, node := range nodes {
		if node.kind != cssAtRule {
			continue
		}
		if node.name == "media" || node.name == "container" {
			checkLengths(source, "@"+node.name+" "+cssText(node.prelude), node.prelude, table, referenced, add)
		}
		checkConditionLengths(source, node.children, table, referenced, add)
	}
}

func checkLengths(source, condition string, tokens []cssToken, table designTokenTable, referenced map[string]bool, add func(int, string, string, ...any)) {
	for _, token := range tokens {
		if token.kind != cssDimension {
			continue
		}
		matched := ""
		for _, name := range sortedKeys(table.breakpoints) {
			if table.breakpoints[name] == token.text {
				matched = name
			}
		}
		if matched == "" {
			add(6, source, "%s: length %s equals no breakpoint token", condition, token.text)
			continue
		}
		referenced[matched] = true
	}
}

var (
	matchMediaOccurrence = regexp.MustCompile(`matchMedia`)
	matchMediaCall       = regexp.MustCompile(`^matchMedia\(\s*(?:"([^"\\\n]*)"|'([^'\\\n]*)')\s*\)`)
)

// scriptQuote matches a JavaScript string or template-literal quote.
const scriptQuote = "[\"'`]"

// scriptStyleWriteSpellings are the spellings of a style write that the
// script rule matches, each with the name a violation reports. JavaScript
// property and method names are case-sensitive; HTML attribute and element
// names are matched in any letter case. A line is matched lexically, so a
// write through a computed name, reflection or an alias is not detected.
var scriptStyleWriteSpellings = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"the style property", regexp.MustCompile(`\.style\b`)},
	{"a bracketed style key", regexp.MustCompile(`\[\s*` + scriptQuote + `style` + scriptQuote + `\s*\]`)},
	{"a style object key", regexp.MustCompile(`(?:["']style["']|(?:^|[^\w$.\-"'])style)\s*:`)},
	{"attributeStyleMap", regexp.MustCompile(`\battributeStyleMap\b`)},
	{"styleMap", regexp.MustCompile(`\bstyleMap\b`)},
	{"cssText", regexp.MustCompile(`\bcssText\b`)},
	{"insertRule", regexp.MustCompile(`\binsertRule\b`)},
	{"deleteRule", regexp.MustCompile(`\bdeleteRule\b`)},
	{"replaceSync", regexp.MustCompile(`\breplaceSync\b`)},
	{"cssRules", regexp.MustCompile(`\bcssRules\b`)},
	{"styleSheets", regexp.MustCompile(`\bstyleSheets\b`)},
	{"the sheet property", regexp.MustCompile(`\.sheet\b`)},
	{"adoptedStyleSheets", regexp.MustCompile(`\badoptedStyleSheets\b`)},
	{"CSSStyleSheet", regexp.MustCompile(`\bCSSStyleSheet\b`)},
	{"animate", regexp.MustCompile(`\.animate\s*\(`)},
	{"KeyframeEffect", regexp.MustCompile(`\bKeyframeEffect\b`)},
	{"a style attribute", regexp.MustCompile(`\b(?:setAttribute|toggleAttribute|createAttribute)\(\s*` + scriptQuote + `(?i:style)` + scriptQuote)},
	{"a namespaced style attribute", regexp.MustCompile(`\b(?:setAttributeNS|createAttributeNS)\([^,]*,\s*` + scriptQuote + `(?i:style)` + scriptQuote)},
	{"innerHTML", regexp.MustCompile(`\binnerHTML\b`)},
	{"outerHTML", regexp.MustCompile(`\bouterHTML\b`)},
	{"insertAdjacentHTML", regexp.MustCompile(`\binsertAdjacentHTML\b`)},
	{"setHTML", regexp.MustCompile(`\bsetHTML(?:Unsafe)?\b`)},
	{"parseHTML", regexp.MustCompile(`\bparseHTML(?:Unsafe)?\b`)},
	{"createContextualFragment", regexp.MustCompile(`\bcreateContextualFragment\b`)},
	{"DOMParser", regexp.MustCompile(`\bDOMParser\b`)},
	{"srcdoc", regexp.MustCompile(`\bsrcdoc\b`)},
	{"document.write", regexp.MustCompile(`\bdocument\.write(?:ln)?\b`)},
	{"a style or link element", regexp.MustCompile(`\bcreateElement(?:NS)?\([^)]*` + scriptQuote + `(?i:style|link)` + scriptQuote + `\s*\)`)},
}

// scriptStyleWrites are the only admitted style writes of the workspace
// scripts: the graph geometry owner positions and sizes its canvas, plane
// headings and nodes from GEOMETRY; the panel owner measures the product bar.
var scriptStyleWrites = []string{
	"workspace-graph.js: button.style.left = designRem(position.x);",
	"workspace-graph.js: button.style.top = designRem(position.y);",
	`workspace-graph.js: canvas.style.setProperty("--graph-card-height", designRem(GEOMETRY.cardHeight));`,
	`workspace-graph.js: canvas.style.setProperty("--graph-card-width", designRem(GEOMETRY.cardWidth));`,
	`workspace-graph.js: canvas.style.setProperty("--graph-edge-stroke", String(GEOMETRY.strokeWidth));`,
	"workspace-graph.js: canvas.style.height = designRem(height);",
	"workspace-graph.js: canvas.style.width = designRem(width);",
	"workspace-graph.js: heading.style.left = designRem(columns[column]);",
	"workspace-panels.js: document.documentElement.style.setProperty(\"--workspace-product-bar-height\", `${productBar.getBoundingClientRect().height}px`);",
}

// SVG presentation attributes other than geometry, from SVG 1.1 and SVG 2. A
// script may write only fill="none", stroke="currentColor" and the graph's
// arrowhead marker reference; CSS cannot carry that reference because rule 5
// refuses url(.
var svgPresentationAttributes = []string{
	"alignment-baseline", "baseline-shift", "clip", "clip-path", "clip-rule", "color", "color-interpolation",
	"color-interpolation-filters", "color-profile", "color-rendering", "cursor", "direction", "display",
	"dominant-baseline", "enable-background", "fill", "fill-opacity", "fill-rule", "filter", "flood-color",
	"flood-opacity", "font", "font-family", "font-size", "font-size-adjust", "font-stretch", "font-style",
	"font-variant", "font-weight", "glyph-orientation-horizontal", "glyph-orientation-vertical", "image-rendering",
	"kerning", "letter-spacing", "lighting-color", "marker-end", "marker-mid", "marker-start", "mask", "mask-type",
	"opacity", "overflow", "paint-order", "pointer-events", "shape-rendering", "stop-color", "stop-opacity", "stroke",
	"stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit",
	"stroke-opacity", "stroke-width", "text-anchor", "text-decoration", "text-overflow", "text-rendering",
	"transform", "transform-box", "transform-origin", "unicode-bidi", "vector-effect", "visibility", "white-space",
	"word-spacing", "writing-mode",
}

var admittedSVGPresentationValues = map[string]string{"fill": "none", "stroke": "currentColor", "marker-end": "url(#graph-arrow)"}

// svgAttributeWritePatterns match an attribute written as an object-literal
// key or as the name argument of setAttribute or setAttributeNS, in any letter
// case, and capture its value: one whole string literal followed by a comma or
// a closing bracket, or else the expression up to the next comma or closing
// bracket, so a value that only begins with an admitted literal is refused.
var svgAttributeWritePatterns = func() map[string]*regexp.Regexp {
	patterns := map[string]*regexp.Regexp{}
	for _, name := range append(slices.Clone(svgPresentationAttributes), "width", "height") {
		patterns[name] = svgAttributeWrites(name)
	}
	return patterns
}()

func svgAttributeWrites(name string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(name)
	key := `(?:` + scriptQuote + quoted + scriptQuote
	if !strings.Contains(name, "-") {
		key += `|(?:^|[^\w$.\-"'])` + quoted
	}
	key += `)\s*:`
	call := `(?:\bsetAttribute\(\s*|\bsetAttributeNS\([^,]*,\s*)` + scriptQuote + quoted + scriptQuote + `\s*,`
	return regexp.MustCompile(`(?mi)(?:` + key + `|` + call + `)\s*(?:("[^"\n]*"|'[^'\n]*')\s*[,)}]|([^,})]*))`)
}

// checkScript applies rules 6 and 7 to one workspace script.
func checkScript(name, source string, table designTokenTable, referenced map[string]bool, add func(int, string, string, ...any)) {
	for _, location := range matchMediaOccurrence.FindAllStringIndex(source, -1) {
		call := matchMediaCall.FindStringSubmatch(source[location[0]:])
		if call == nil {
			add(6, name, "matchMedia is not called with one string literal")
			continue
		}
		query := call[1] + call[2]
		tokens, err := tokenizeCSS(query)
		if err != nil {
			add(6, name, "matchMedia query %q does not tokenize", query)
			continue
		}
		checkLengths(name, "matchMedia("+query+")", tokens, table, referenced, add)
		if reason := schemeSwitch(tokens); reason != "" {
			add(2, name, "matchMedia(%s) holds %s; the palette tokens switch the color scheme", query, reason)
		}
	}
	for _, line := range strings.Split(source, "\n") {
		spellings := []string{}
		for _, spelling := range scriptStyleWriteSpellings {
			if spelling.pattern.MatchString(line) {
				spellings = append(spellings, spelling.name)
			}
		}
		if len(spellings) > 0 && !slices.Contains(scriptStyleWrites, name+": "+strings.TrimSpace(line)) {
			add(7, name, "writes a style outside the admitted geometry owners through %s: %s", strings.Join(spellings, ", "), strings.TrimSpace(line))
		}
	}
	nodesTable := [2]int{-1, -1}
	if name == "workspace-icons.js" {
		if start := strings.Index(source, "const nodes = {"); start >= 0 {
			if end := strings.Index(source[start:], "\n};"); end >= 0 {
				nodesTable = [2]int{start, start + end}
			}
		}
	}
	lower := strings.ToLower(source)
	for _, attribute := range append(slices.Clone(svgPresentationAttributes), "width", "height") {
		if !strings.Contains(lower, attribute) {
			continue
		}
		for offset := 0; offset <= len(source); {
			found := svgAttributeWritePatterns[attribute].FindStringSubmatchIndex(source[offset:])
			if found == nil {
				break
			}
			match := make([]int, len(found))
			for index, position := range found {
				match[index] = position
				if position >= 0 {
					match[index] += offset
				}
			}
			// The next search starts after the value, not after the comma or
			// bracket that ends a whole literal, so that delimiter can still
			// precede a repeated key.
			offset = match[1]
			if match[2] >= 0 {
				offset = match[3]
			}
			value := ""
			if match[2] >= 0 {
				value = source[match[2]:match[3]]
			} else {
				value = strings.TrimSpace(source[match[4]:match[5]])
			}
			switch attribute {
			case "width", "height":
				// A width or height is geometry inside the icon shape table,
				// in viewBox units, or the graph SVG's full extent; an icon's
				// rendered size is a CSS token.
				if (match[0] > nodesTable[0] && match[1] < nodesTable[1]) || value == `"100%"` {
					continue
				}
				add(7, name, "SVG %s %s is not viewBox geometry", attribute, value)
			default:
				if admitted, ok := admittedSVGPresentationValues[attribute]; ok && (value == `"`+admitted+`"` || value == `'`+admitted+`'`) {
					continue
				}
				add(7, name, "writes SVG presentation attribute %s=%s", attribute, value)
			}
		}
	}
}

// htmlPresentationalAttributes are the HTML attributes that the rendering
// maps to a color, size, border, spacing or alignment. Together with the SVG
// presentation attributes they may not appear in rendered HTML, so a rendered
// size, including an SVG width or height, is a CSS token; the other SVG
// geometry attributes are not presentational.
var htmlPresentationalAttributes = []string{
	"align", "alink", "background", "bgcolor", "border", "bordercolor", "bottommargin", "cellpadding", "cellspacing",
	"clear", "color", "cols", "face", "frame", "frameborder", "height", "hspace", "leftmargin", "link",
	"marginheight", "marginwidth", "noshade", "nowrap", "rightmargin", "rows", "rules", "size", "sizes", "text",
	"topmargin", "valign", "vlink", "vspace", "width",
}

var renderedPresentationalAttributes = func() map[string]bool {
	set := designTokenSet(htmlPresentationalAttributes...)
	for _, name := range svgPresentationAttributes {
		set[name] = true
	}
	return set
}()

// checkRenderedHTML applies rule 8, and rule 6 to media attributes, to one
// rendered page.
func checkRenderedHTML(name, document string, styleElements int, table designTokenTable, referenced map[string]bool, add func(int, string, string, ...any)) {
	tags, err := scanHTMLTags(document)
	if err != nil {
		add(8, name, "does not scan: %v", err)
		return
	}
	styles := 0
	for _, tag := range tags {
		if tag.name == "style" {
			styles++
		}
		for _, attribute := range tag.attributes {
			switch {
			case attribute.name == "style":
				add(8, name, "<%s> carries a style attribute", tag.name)
			case attribute.name == "media":
				tokens, err := tokenizeCSS(attribute.value)
				if err != nil {
					add(6, name, "<%s> media attribute %q does not tokenize", tag.name, attribute.value)
					continue
				}
				checkLengths(name, "<"+tag.name+"> media attribute "+attribute.value, tokens, table, referenced, add)
				if reason := schemeSwitch(tokens); reason != "" {
					add(2, name, "<%s> media attribute %q holds %s; the palette tokens switch the color scheme", tag.name, attribute.value, reason)
				}
			case renderedPresentationalAttributes[attribute.name]:
				if admitted, ok := admittedSVGPresentationValues[attribute.name]; ok && attribute.value == admitted {
					continue
				}
				add(8, name, "<%s> carries the presentational attribute %q", tag.name, attribute.name)
			}
		}
	}
	if styles != styleElements {
		add(8, name, "has %d style elements, want %d", styles, styleElements)
	}
}

type htmlTag struct {
	name       string
	attributes []htmlAttribute
}

type htmlAttribute struct {
	name, value string
}

// htmlRawTextElements are the raw-text and escapable raw-text elements, whose
// content is text in HTML content and markup inside svg and math.
var htmlRawTextElements = []string{"script", "style", "textarea", "title"}

// htmlParsedAsTextElements are the elements whose content the HTML parser reads
// as text in HTML content; noscript only when scripting is enabled.
var htmlParsedAsTextElements = []string{"xmp", "iframe", "noembed", "noframes", "noscript"}

// scanHTMLTags returns the start tags of a document with their lowercase
// attribute names and their HTML-unescaped values. It skips comments,
// declarations and end tags, and it continues after the content of a raw-text
// element where the HTML parser ends it as text. Where that content may be
// markup instead, after an svg or math start tag and for the elements parsed
// as text, it also scans the content as markup on its own.
func scanHTMLTags(document string) ([]htmlTag, error) {
	return scanHTMLTagsIn(document, false)
}

func scanHTMLTagsIn(document string, foreign bool) ([]htmlTag, error) {
	tags := []htmlTag{}
	lower := strings.ToLower(document)
	for at := 0; at < len(document); {
		next := strings.IndexByte(document[at:], '<')
		if next < 0 {
			break
		}
		at += next
		switch {
		case strings.HasPrefix(document[at:], "<!--"):
			end, err := htmlCommentEnd(document, at+4)
			if err != nil {
				return nil, err
			}
			at = end
		case strings.HasPrefix(document[at:], "<!") || strings.HasPrefix(document[at:], "</") || strings.HasPrefix(document[at:], "<?"):
			end := strings.IndexByte(document[at:], '>')
			if end < 0 {
				return nil, fmt.Errorf("unterminated markup declaration or end tag")
			}
			at += end + 1
		case at+1 < len(document) && isASCIILetter(document[at+1]):
			tag, end, err := scanStartTag(document, at+1)
			if err != nil {
				return nil, err
			}
			tags = append(tags, tag)
			at = end
			if tag.name == "svg" || tag.name == "math" {
				foreign = true
			}
			parsedAsText := slices.Contains(htmlParsedAsTextElements, tag.name)
			if parsedAsText || slices.Contains(htmlRawTextElements, tag.name) {
				closing := strings.Index(lower[at:], "</"+tag.name)
				if closing < 0 {
					return nil, fmt.Errorf("unterminated <%s>", tag.name)
				}
				if foreign || parsedAsText {
					inner, err := scanHTMLTagsIn(document[at:at+closing], foreign)
					if err != nil {
						return nil, err
					}
					tags = append(tags, inner...)
				}
				at += closing
			}
		default:
			at++
		}
	}
	return tags, nil
}

// htmlCommentEnd returns the index after a comment whose text begins at
// start, as the HTML parser ends it: <!--> and <!---> close at once, and
// otherwise the comment ends at the first --> or --!>.
func htmlCommentEnd(document string, start int) (int, error) {
	rest := document[start:]
	if strings.HasPrefix(rest, ">") {
		return start + 1, nil
	}
	if strings.HasPrefix(rest, "->") {
		return start + 2, nil
	}
	end := -1
	for _, closer := range []string{"-->", "--!>"} {
		if index := strings.Index(rest, closer); index >= 0 && (end < 0 || start+index+len(closer) < end) {
			end = start + index + len(closer)
		}
	}
	if end < 0 {
		return 0, fmt.Errorf("unterminated comment")
	}
	return end, nil
}

func scanStartTag(document string, at int) (htmlTag, int, error) {
	start := at
	for at < len(document) && !isHTMLSpace(document[at]) && document[at] != '>' && document[at] != '/' {
		at++
	}
	tag := htmlTag{name: strings.ToLower(document[start:at])}
	for at < len(document) {
		for at < len(document) && (isHTMLSpace(document[at]) || document[at] == '/') {
			at++
		}
		if at >= len(document) {
			break
		}
		if document[at] == '>' {
			return tag, at + 1, nil
		}
		nameStart := at
		for at < len(document) && !isHTMLSpace(document[at]) && document[at] != '>' && document[at] != '/' && document[at] != '=' {
			at++
		}
		attribute := htmlAttribute{name: strings.ToLower(document[nameStart:at])}
		for at < len(document) && isHTMLSpace(document[at]) {
			at++
		}
		if at < len(document) && document[at] == '=' {
			at++
			for at < len(document) && isHTMLSpace(document[at]) {
				at++
			}
			if at < len(document) && (document[at] == '"' || document[at] == '\'') {
				quote := document[at]
				end := strings.IndexByte(document[at+1:], quote)
				if end < 0 {
					return htmlTag{}, 0, fmt.Errorf("unterminated attribute value in <%s>", tag.name)
				}
				attribute.value = html.UnescapeString(document[at+1 : at+1+end])
				at += end + 2
			} else {
				valueStart := at
				for at < len(document) && !isHTMLSpace(document[at]) && document[at] != '>' {
					at++
				}
				attribute.value = html.UnescapeString(document[valueStart:at])
			}
		}
		tag.attributes = append(tag.attributes, attribute)
	}
	return htmlTag{}, 0, fmt.Errorf("unterminated <%s>", tag.name)
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isHTMLSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func allTokenNames(table designTokenTable) []string {
	names := map[string]bool{}
	for _, context := range []map[string]string{table.base, table.dark, table.forced} {
		for name := range context {
			names[name] = true
		}
	}
	return sortedKeys(names)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
