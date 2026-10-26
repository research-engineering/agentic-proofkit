package requirementbrowser

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
)

func TestDesignTokenGrammarAdmitsTheShippedStyleOwners(t *testing.T) {
	sources, err := loadDesignTokenSources()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources.scripts) == 0 || len(sources.staticHTML) != 5 || len(sources.workspaceHTML) != 1 {
		t.Fatalf("grammar inputs: %d scripts, %d static views, %d workspace views", len(sources.scripts), len(sources.staticHTML), len(sources.workspaceHTML))
	}
	for _, violation := range checkDesignTokenGrammar(sources) {
		t.Error(violation)
	}
	// The grammar's exceptions stay admitted when an input uses them: layout
	// percentages and fr, also in a vendor-prefixed layout property, unitless
	// numbers outside the size properties, the admitted vendor keywords, a
	// breakpoint length in a media attribute, fill none, stroke currentColor
	// and SVG geometry other than width and height in a script or in rendered
	// HTML, and markup inside a comment that an empty comment precedes.
	t.Run("listed exceptions", func(t *testing.T) {
		exceptions := sources
		exceptions.scripts = maps.Clone(sources.scripts)
		exceptions.workspaceHTML = maps.Clone(sources.workspaceHTML)
		exceptions.workspaceCSS += "\n.exception { width: 50%; grid-template-columns: minmax(0, 1fr) 2fr; z-index: 3; opacity: .5; flex: 1; order: 2; font-weight: 600; -webkit-line-clamp: 2; display: -webkit-box; font-family: -apple-system, sans-serif; margin: 0; -webkit-transform: translateX(50%); }\n"
		// Every layout property admits a percentage.
		exceptions.workspaceCSS += ".exception-layout { width: 50%; height: 50%; min-width: 50%; min-height: 50%; max-width: 50%; max-height: 50%; inline-size: 50%; block-size: 50%; min-inline-size: 50%; min-block-size: 50%; max-inline-size: 50%; max-block-size: 50%; inset: 50%; inset-block: 50%; inset-inline: 50%; inset-block-start: 50%; inset-block-end: 50%; inset-inline-start: 50%; inset-inline-end: 50%; top: 50%; right: 50%; bottom: 50%; left: 50%; transform: translate(50%); translate: 50%; flex: 1 1 50%; flex-basis: 50%; grid-template: 50% / 50%; grid-template-columns: 50% 1fr; grid-template-rows: 50%; grid-auto-columns: 50%; grid-auto-rows: 50%; }\n"
		exceptions.scripts["workspace.js"] = strings.Replace(exceptions.scripts["workspace.js"], "// @ts-check\n", "// @ts-check\n"+strings.Join([]string{
			`svg.setAttribute("fill", "none");`, `svg.setAttributeNS(null, "stroke", "currentColor");`, `svg.setAttribute("width", "100%");`,
			`path.setAttribute("d", "M 0 0 L 1 1");`, `rect.setAttribute("x", "2");`, `svg.setAttribute("viewBox", "0 0 24 24");`,
		}, "\n")+"\n", 1)
		page := exceptions.workspaceHTML["workspace"]
		page = strings.Replace(page, `<link rel="stylesheet" href="/assets/workspace.css">`, `<link rel="stylesheet" media="(max-width: 64rem)" href="/assets/workspace.css">`, 1)
		page = strings.Replace(page, "</header>", `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M 0 0 L 1 1"></path></svg><!----><!-- <p style="color:red"> --></header>`, 1)
		if page == sources.workspaceHTML["workspace"] {
			t.Fatal("exception anchors are absent from the workspace view")
		}
		exceptions.workspaceHTML["workspace"] = page
		for _, violation := range checkDesignTokenGrammar(exceptions) {
			t.Error(violation)
		}
	})
}

// Each mutant changes one input; the grammar must refuse it under its rule
// with every listed detail, so each mutant pins the clause that names it.
func TestDesignTokenGrammarRefusesEveryRuleMutant(t *testing.T) {
	shipped, err := loadDesignTokenSources()
	if err != nil {
		t.Fatal(err)
	}
	appendWorkspace := func(rule string) func(*designTokenSources) {
		return func(sources *designTokenSources) { sources.workspaceCSS += "\n" + rule + "\n" }
	}
	appendStatic := func(rule string) func(*designTokenSources) {
		return func(sources *designTokenSources) { sources.staticStyle += rule }
	}
	replaceIn := func(field func(*designTokenSources) *string, old, replacement string) func(*designTokenSources) {
		return func(sources *designTokenSources) {
			target := field(sources)
			if strings.Count(*target, old) < 1 {
				t.Fatalf("mutant anchor %q is absent", old)
			}
			*target = strings.Replace(*target, old, replacement, 1)
		}
	}
	tokens := func(sources *designTokenSources) *string { return &sources.tokens }
	workspace := func(sources *designTokenSources) *string { return &sources.workspaceCSS }
	static := func(sources *designTokenSources) *string { return &sources.staticStyle }
	replaceScript := func(name, old, replacement string) func(*designTokenSources) {
		return func(sources *designTokenSources) {
			value := sources.scripts[name]
			if !strings.Contains(value, old) {
				t.Fatalf("mutant anchor %q is absent from %s", old, name)
			}
			sources.scripts[name] = strings.Replace(value, old, replacement, 1)
		}
	}
	appendScript := func(lines ...string) func(*designTokenSources) {
		return replaceScript("workspace.js", "// @ts-check\n", "// @ts-check\n"+strings.Join(lines, "\n")+"\n")
	}
	staticPage := func(old, replacement string) func(*designTokenSources) {
		return func(sources *designTokenSources) {
			page := sources.staticHTML["static source"]
			if !strings.Contains(page, old) {
				t.Fatalf("mutant anchor %q is absent from the static source view", old)
			}
			sources.staticHTML["static source"] = strings.Replace(page, old, replacement, 1)
		}
	}
	workspacePage := func(old, replacement string) func(*designTokenSources) {
		return func(sources *designTokenSources) {
			page := sources.workspaceHTML["workspace"]
			if !strings.Contains(page, old) {
				t.Fatalf("mutant anchor %q is absent from the workspace view", old)
			}
			sources.workspaceHTML["workspace"] = strings.Replace(page, old, replacement, 1)
		}
	}
	type mutant struct {
		name    string
		rule    int
		details []string
		mutate  func(*designTokenSources)
	}
	mutants := []mutant{
		{"hash color in workspace.css", 1, []string{"color: literal color #202522"}, appendWorkspace(".mutant { color: #202522; }")},
		{"literal size in the static style", 1, []string{"padding-bottom: literal size 8px"}, replaceIn(static, "padding-bottom:var(--space-8)", "padding-bottom:8px")},
		{"literal size in a var() fallback", 1, []string{"padding: var() is not exactly var(--name)", "padding: literal size 13px"}, appendWorkspace(".mutant { padding: var(--space-8, 13px); }")},
		{"literal size inside calc()", 1, []string{"width: literal size 1rem"}, appendWorkspace(".mutant { width: calc(100% - 1rem); }")},
		{"size keyword", 1, []string{"border: size keyword thin"}, appendWorkspace(".mutant { border: thin solid var(--color-border); }")},
		{"transparent", 1, []string{"background: literal color transparent"}, appendStatic(".mutant{background:transparent}")},
		{"unitless line height", 1, []string{"line-height: literal size 1.55"}, appendWorkspace(".mutant { line-height: 1.55; }")},
		{"system color outside forced-colors", 1, []string{"color: literal color CanvasText"}, appendWorkspace(".mutant { color: CanvasText; }")},
		{"named color", 1, []string{"color: literal color red"}, appendWorkspace(".mutant { color: red; }")},
		{"color function", 1, []string{"color: literal color rgb(...)"}, appendStatic(".mutant{color:rgb(0 0 0)}")},
		{"percentage outside a layout property", 1, []string{"font-size: literal size 120%"}, appendWorkspace(".mutant { font-size: 120%; }")},
		{"attr() in a style owner", 1, []string{"width: attr() reads a value outside the token set"}, appendWorkspace(".mutant { width: attr(data-width px); }")},
		{"vendor-prefixed color keywords", 1, []string{"color: literal color -webkit-link", "outline-color: literal color -webkit-focus-ring-color", "color: literal color -moz-hyperlinktext"}, func(sources *designTokenSources) {
			appendWorkspace(".mutant { color: -webkit-link; outline-color: -webkit-focus-ring-color; }")(sources)
			appendStatic(".mutant{color:-moz-hyperlinktext}")(sources)
		}},
		{"unitless numbers in size properties", 1, []string{
			"font: literal size 21", "font-size: literal size 29", "font-size-adjust: literal size .5", "line-height: literal size 22", "letter-spacing: literal size 23",
			"word-spacing: literal size 24", "tab-size: literal size 8", "border-top-width: literal size 25", "outline-width: literal size 26",
			"outline-offset: literal size 27", "stroke-width: literal size 28", "stroke-dasharray: literal size 4", "stroke-dashoffset: literal size 3",
			"cx: literal size 11", "cy: literal size 12", "r: literal size 13", "rx: literal size 14", "ry: literal size 15", "x: literal size 16",
			"y: literal size 17", "zoom: literal size 2", "scale: literal size 1.25", "transform: literal size 1.5",
		}, appendWorkspace(".mutant { font: 21 serif; font-size: 29; font-size-adjust: .5; line-height: 22; letter-spacing: 23; word-spacing: 24; tab-size: 8; border-top-width: 25; outline-width: 26; outline-offset: 27; stroke-width: 28; stroke-dasharray: 4 2; stroke-dashoffset: 3; cx: 11; cy: 12; r: 13; rx: 14; ry: 15; x: 16; y: 17; zoom: 2; scale: 1.25; transform: scale(1.5); }")},
		{"contrast-color()", 1, []string{"color: literal color contrast-color(...)"}, appendWorkspace(".mutant { color: contrast-color(var(--color-canvas)); }")},
		{"every color function and size keyword", 1, []string{
			"color: literal color rgb(...)", "color: literal color rgba(...)", "color: literal color hsl(...)", "color: literal color hsla(...)",
			"color: literal color hwb(...)", "color: literal color lab(...)", "color: literal color lch(...)", "color: literal color oklab(...)",
			"color: literal color oklch(...)", "color: literal color color(...)", "color: literal color color-mix(...)",
			"color: literal color contrast-color(...)", "color: literal color light-dark(...)",
			"border-top-width: size keyword thin", "border-right-width: size keyword medium", "border-bottom-width: size keyword thick",
			"font-size: size keyword xx-small", "font-size: size keyword x-small", "font-size: size keyword smaller",
			"font-size: size keyword larger", "font-size: size keyword xxx-large", "font: size keyword small",
			"font: size keyword large", "font: size keyword x-large", "font: size keyword xx-large",
		}, appendWorkspace(".mutant { color: rgb(0 0 0); color: rgba(0, 0, 0, 0); color: hsl(0 0% 0%); color: hsla(0, 0%, 0%, 0); color: hwb(0 0% 0%); color: lab(0 0 0); color: lch(0 0 0); color: oklab(0 0 0); color: oklch(0 0 0); color: color(srgb 0 0 0); color: color-mix(in srgb, var(--canvas), var(--text)); color: contrast-color(var(--canvas)); color: light-dark(var(--canvas), var(--text)); border-top-width: thin; border-right-width: medium; border-bottom-width: thick; font-size: xx-small; font-size: x-small; font-size: smaller; font-size: larger; font-size: xxx-large; font: small serif; font: large serif; font: x-large serif; font: xx-large serif; }")},
		{"vendor-prefixed size properties", 1, []string{"-webkit-transform: literal size 1.5", "-moz-tab-size: literal size 8"}, appendWorkspace(".mutant { -webkit-transform: scale(1.5); -moz-tab-size: 8; }")},
		{"vendor-prefixed perspective", 1, []string{"-webkit-perspective: literal size 500"}, appendWorkspace(".mutant { -webkit-perspective: 500; }")},
		{"style owner that does not parse", 1, []string{"does not parse: css declaration list holds a nested rule"}, appendWorkspace(".mutant { & .nested { display: none; } }")},
		{"var() naming no token", 2, []string{"var(--unknown-token) names no token, owner custom property or geometry property"}, appendWorkspace(".mutant { color: var(--unknown-token); }")},
		{"dark token without a base declaration", 2, []string{"dark token --dark-only is not a palette token declared in the base context"}, replaceIn(tokens, "    --color-accent: #5ec4c1;\n", "    --color-accent: #5ec4c1;\n    --dark-only: #000000;\n")},
		{"dark redeclaration of a base size token", 2, []string{"dark token --space-8 is not a palette token declared in the base context"}, replaceIn(tokens, "    --color-accent: #5ec4c1;\n", "    --color-accent: #5ec4c1;\n    --space-8: .75rem;\n")},
		{"dark color for a base size token", 2, []string{"dark token --space-8 is not a palette token declared in the base context", "dark token --space-8 redeclares a size base value with a color value"}, replaceIn(tokens, "    --color-accent: #5ec4c1;\n", "    --color-accent: #5ec4c1;\n    --space-8: #000000;\n")},
		{"dark size for a base color token", 2, []string{"dark token --color-canvas redeclares a color base value with a size value"}, replaceIn(tokens, "    --color-canvas: #0e1416;", "    --color-canvas: 1rem;")},
		{"forced-colors color for a base size token", 2, []string{"forced-colors token --space-8 redeclares a size base value with a color value"}, replaceIn(tokens, "    --forced-ink: CanvasText;\n", "    --forced-ink: CanvasText;\n    --space-8: CanvasText;\n")},
		{"forced-colors size for a base color token", 2, []string{"forced-colors token --color-canvas redeclares a color base value with a size value"}, replaceIn(tokens, "    --forced-ink: CanvasText;\n", "    --forced-ink: CanvasText;\n    --color-canvas: 1rem;\n")},
		{"owner custom property shadowing a token", 2, []string{"declares --color-text, which shadows a token or a geometry property"}, replaceIn(workspace, "  --navigation-width: var(--layout-navigation-width);", "  --navigation-width: var(--layout-navigation-width);\n  --color-text: var(--color-accent);")},
		{"token used by neither owner", 2, []string{"token --space-unused is not used by a style owner, a matchMedia query or a media attribute of rendered HTML"}, replaceIn(tokens, "  --space-4: .25rem;\n", "  --space-4: .25rem;\n  --space-unused: 1rem;\n")},
		{"palette token without a dark value", 2, []string{"palette token --color-accent has no dark color-scheme value"}, replaceIn(tokens, "    --color-accent: #5ec4c1;\n", "")},
		{"color-scheme rule in a style owner", 2, []string{"holds @media (prefers-color-scheme: dark), a prefers-color-scheme condition; the palette tokens switch the color scheme", "holds @media (prefers-color-scheme:light), a prefers-color-scheme condition; the palette tokens switch the color scheme"}, func(sources *designTokenSources) {
			appendWorkspace("@media (prefers-color-scheme: dark) { .mutant { color: var(--color-text); } }")(sources)
			appendStatic("@media (prefers-color-scheme:light){.mutant{color:var(--color-text)}}")(sources)
		}},
		{"color-scheme rule with an escaped feature name", 2, []string{`holds @media (prefers-color-sch\65me: dark), a prefers-color-scheme condition; the palette tokens switch the color scheme`}, appendWorkspace(`@media (prefers-color-sch\65me: dark) { .mutant { color: var(--color-text); } }`)},
		{"color-scheme rule with an escaped first letter", 2, []string{`holds @media (\70refers-color-scheme:dark), a prefers-color-scheme condition; the palette tokens switch the color scheme`}, appendStatic(`@media (\70refers-color-scheme:dark){.mutant{color:var(--color-text)}}`)},
		{"style query on a palette token", 2, []string{"holds @container style(--color-canvas: #0e1416), a style() query; the palette tokens switch the color scheme"}, appendWorkspace("@container style(--color-canvas: #0e1416) { .mutant { padding: var(--space-48); } }")},
		{"color-scheme condition in another at-rule", 2, []string{"holds @custom-media --dark (prefers-color-scheme: dark), a prefers-color-scheme condition; the palette tokens switch the color scheme"}, appendWorkspace("@custom-media --dark (prefers-color-scheme: dark);")},
		{"if() in a declaration value", 2, []string{"color holds an if() function; the palette tokens switch the color scheme"}, appendWorkspace(".mutant { color: if(media(prefers-color-scheme: dark): var(--color-text); else: var(--color-accent)); }")},
		{"color-scheme matchMedia query", 2, []string{"matchMedia((prefers-color-scheme: dark)) holds a prefers-color-scheme condition; the palette tokens switch the color scheme"}, replaceScript("workspace-panels.js", `"(max-width: 64rem)"`, `"(prefers-color-scheme: dark)"`)},
		{"color-scheme media attribute", 2, []string{`<link> media attribute "(prefers-color-scheme: dark)" holds a prefers-color-scheme condition; the palette tokens switch the color scheme`}, workspacePage(`<link rel="stylesheet" href="/assets/workspace.css">`, `<link rel="stylesheet" media="(prefers-color-scheme: dark)" href="/assets/workspace.css">`)},
		{"forced-colors token outside forced-colors", 2, []string{"uses forced-colors token --forced-border outside @media (forced-colors: active)"}, appendWorkspace(".mutant { border-color: var(--forced-border); }")},
		{"owner custom property named like a geometry property", 2, []string{"declares --graph-card-width, which shadows a token or a geometry property"}, replaceIn(workspace, "  --navigation-width: var(--layout-navigation-width);", "  --navigation-width: var(--layout-navigation-width);\n  --graph-card-width: var(--space-8);")},
		{"owner custom property with a literal number", 3, []string{"--navigation-width: literal size 2"}, replaceIn(workspace, "--navigation-width: var(--layout-navigation-width);", "--navigation-width: 2;")},
		{"owner custom property with a literal size", 3, []string{"--navigation-width: literal size 17rem"}, replaceIn(workspace, "--navigation-width: var(--layout-navigation-width);", "--navigation-width: 17rem;")},
		{"token stylesheet that does not parse", 4, []string{"does not parse: unbalanced css block"}, func(sources *designTokenSources) { sources.tokens += "}\n" }},
		{"token stylesheet rule other than :root", 4, []string{"base context holds a rule other than :root"}, replaceIn(tokens, "@media (prefers-color-scheme: dark)", ".card { --card-gap: 1px; }\n@media (prefers-color-scheme: dark)")},
		{"token stylesheet declaration that is not a custom property", 4, []string{`base :root declares "color", which is not a custom property`}, replaceIn(tokens, ":root {\n", ":root {\n  color: var(--color-text);\n")},
		{"system color in the base context", 4, []string{"base token --color-canvas uses a system color outside forced-colors"}, replaceIn(tokens, "--color-canvas: #f3f5f5;", "--color-canvas: Canvas;")},
		{"token stylesheet context other than the three", 4, []string{"holds @media (min-width: 64rem), which is not one of the three token contexts"}, replaceIn(tokens, "@media (forced-colors: active)", "@media (min-width: 64rem) {\n  :root {\n    --space-wide: 1rem;\n  }\n}\n@media (forced-colors: active)")},
		{"token value referring to another token", 4, []string{"token --color-accent refers to a custom property"}, replaceIn(tokens, "--color-accent: #0c6670;", "--color-accent: var(--color-focus);")},
		{"token value reading an attribute", 4, []string{"token --color-accent refers to an attribute"}, replaceIn(tokens, "--color-accent: #0c6670;", "--color-accent: attr(data-accent type(<color>));")},
		{"important token", 4, []string{"base token --color-canvas is empty or important"}, replaceIn(tokens, "--color-canvas: #f3f5f5;", "--color-canvas: #f3f5f5 !important;")},
		{"empty token", 4, []string{"base token --color-surface is empty or important"}, replaceIn(tokens, "--color-surface: #ffffff;", "--color-surface: ;")},
		{"token declared twice in one context", 4, []string{"base context declares --color-canvas twice"}, replaceIn(tokens, "  --color-canvas: #f3f5f5;\n", "  --color-canvas: #f3f5f5;\n  --color-canvas: #f3f5f5;\n")},
		{"dark system color", 4, []string{"dark token --color-canvas uses a system color outside forced-colors"}, replaceIn(tokens, "    --color-canvas: #0e1416;", "    --color-canvas: Canvas;")},
		{"breakpoint token that is not one length", 4, []string{"breakpoint token --breakpoint-bar is not one length"}, replaceIn(tokens, "--breakpoint-bar: 24rem;", "--breakpoint-bar: calc(24rem);")},
		{"forced-colors token that is not one system color", 4, []string{"forced-colors token --forced-ink is not one system color"}, replaceIn(tokens, "--forced-ink: CanvasText;", "--forced-ink: #000000;")},
		{"forced-colors token also declared outside forced-colors", 4, []string{"forced-colors token --forced-ink is also declared outside forced-colors"}, replaceIn(tokens, "    --color-accent: #5ec4c1;\n", "    --color-accent: #5ec4c1;\n    --forced-ink: #000000;\n")},
		{"@import", 5, []string{"uses @import"}, replaceIn(tokens, ":root {\n", "@import \"theme.css\";\n:root {\n")},
		{"@font-face", 5, []string{"uses @font-face"}, appendWorkspace("@font-face { font-family: Mutant; }")},
		{"url(", 5, []string{"uses url("}, appendStatic(".mutant{background-image:url(mutant.png)}")},
		{"image-set(", 5, []string{"uses image-set("}, appendWorkspace(".mutant { background-image: image-set(\"mutant.png\" 1x); }")},
		{"bad url", 5, []string{"uses url("}, appendWorkspace(".mutant { background-image: url(a b); }")},
		{"stylesheet that does not tokenize", 5, []string{"does not tokenize: unterminated css comment"}, appendWorkspace("/* unterminated")},
		{"media length equal to no breakpoint token", 6, []string{"@media (max-width: 47rem): length 47rem equals no breakpoint token"}, replaceIn(workspace, "@media (max-width: 48rem)", "@media (max-width: 47rem)")},
		{"static media length equal to no breakpoint token", 6, []string{"@media (max-width:721px): length 721px equals no breakpoint token"}, replaceIn(static, "@media (max-width:48rem)", "@media (max-width:721px)")},
		{"container length equal to no breakpoint token", 6, []string{"@container (min-width: 30rem): length 30rem equals no breakpoint token"}, appendWorkspace("@container (min-width: 30rem) { .mutant { display: none; } }")},
		{"matchMedia length equal to no breakpoint token", 6, []string{"matchMedia((max-width: 63rem)): length 63rem equals no breakpoint token"}, replaceScript("workspace-panels.js", `"(max-width: 64rem)"`, `"(max-width: 63rem)"`)},
		{"matchMedia argument that is not a string literal", 6, []string{"matchMedia is not called with one string literal"}, replaceScript("workspace-panels.js", `window.matchMedia("(max-width: 64rem)")`, "window.matchMedia(query)")},
		{"media attribute length equal to no breakpoint token", 6, []string{"<link> media attribute (max-width: 10px): length 10px equals no breakpoint token"}, workspacePage(`<link rel="stylesheet" href="/assets/workspace.css">`, `<link rel="stylesheet" media="(max-width: 10px)" href="/assets/workspace.css">`)},
		{"entity-escaped media attribute length", 6, []string{"<link> media attribute (max-width: 10px): length 10px equals no breakpoint token"}, workspacePage(`<link rel="stylesheet" href="/assets/workspace.css">`, `<link rel="stylesheet" media="(max-width: 10&#112;x)" href="/assets/workspace.css">`)},
		{"entity-escaped unquoted media attribute length", 6, []string{"<link> media attribute (max-width:10px): length 10px equals no breakpoint token"}, workspacePage(`<link rel="stylesheet" href="/assets/workspace.css">`, `<link rel="stylesheet" media=(max-width:10&#112;x) href="/assets/workspace.css">`)},
		{"matchMedia query that does not tokenize", 6, []string{`matchMedia query "(max-width: 64rem) /*" does not tokenize`}, replaceScript("workspace-panels.js", `"(max-width: 64rem)"`, `"(max-width: 64rem) /*"`)},
		{"media attribute that does not tokenize", 6, []string{`<link> media attribute "/*" does not tokenize`}, workspacePage(`<link rel="stylesheet" href="/assets/workspace.css">`, `<link rel="stylesheet" media="/*" href="/assets/workspace.css">`)},
		{"unlisted graph style write", 7, []string{"through the style property: heading.style.left = designRem(columns[column]); heading.style.color"}, replaceScript("workspace-graph.js", "heading.style.left = designRem(columns[column]);", "heading.style.left = designRem(columns[column]); heading.style.color = \"red\";")},
		{"icon stroke width attribute", 7, []string{`writes SVG presentation attribute stroke-width="2"`}, replaceScript("workspace-icons.js", `fill: "none", `, `fill: "none", "stroke-width": "2", `)},
		{"icon size attribute", 7, []string{`SVG width "20" is not viewBox geometry`}, replaceScript("workspace-icons.js", `{viewBox: "0 0 24 24", `, `{width: "20", viewBox: "0 0 24 24", `)},
		{"repeated SVG attribute key after a whole literal", 7, []string{`writes SVG presentation attribute fill="red"`}, replaceScript("workspace-icons.js", `fill: "none", `, `fill: "none",fill: "red", `)},
		{"icon fill color", 7, []string{`writes SVG presentation attribute fill="red"`}, replaceScript("workspace-icons.js", `fill: "none"`, `fill: "red"`)},
		{"SVG presentation attribute value that is an expression", 7, []string{`writes SVG presentation attribute stroke="currentColor" && "red"`, `writes SVG presentation attribute fill="none" ? "red" : "none"`}, appendScript(`svg.setAttribute("stroke", "currentColor" && "red");`, `const shape = {fill: "none" ? "red" : "none"};`)},
		{"style attribute with a template-literal quote", 7, []string{"through a style attribute: document.body.setAttribute(`style`, ``);"}, appendScript("document.body.setAttribute(`style`, ``);")},
		{"SVG presentation attributes in any letter case, namespace or quote", 7, []string{
			`writes SVG presentation attribute fill="#f00"`, `writes SVG presentation attribute fill="#0f0"`, "writes SVG presentation attribute fill=`#00f`",
			`SVG height "20" is not viewBox geometry`,
		}, appendScript(`svg.setAttributeNS("", "fill", "#f00");`, `svg.setAttribute("FILL", "#0f0");`, "svg.setAttribute(`fill`, `#00f`);", `svg.setAttributeNS(svgNamespace, "Height", "20");`)},
		{"style attribute in a static view", 8, []string{"<main> carries a style attribute"}, staticPage("<main>", "<main style=\"color:red\">")},
		{"second style element in a static view", 8, []string{"has 2 style elements, want 1"}, staticPage("</head>", "<style></style></head>")},
		{"style element in the workspace", 8, []string{"has 1 style elements, want 0"}, workspacePage("</head>", "<style></style></head>")},
		{"style attribute in the workspace", 8, []string{"<main> carries a style attribute"}, workspacePage("<main id=\"workspace-main\"", "<main style=\"\" id=\"workspace-main\"")},
		{"rendered HTML that does not scan", 8, []string{"does not scan: unterminated comment"}, staticPage("</body>", "<!--</body>")},
		{"markup after an abruptly closed empty comment", 8, []string{`<main> carries the presentational attribute "bgcolor"`}, staticPage("<main>", "<!--><main bgcolor=\"red\"><!-- end -->")},
		{"markup after an abruptly closed dash comment", 8, []string{"<main> carries a style attribute"}, staticPage("<main>", "<!---><main style=\"color:red\"><!-- end -->")},
		{"markup after a comment closed by --!>", 8, []string{"<main> carries a style attribute"}, staticPage("<main>", "<!-- note --!><main style=\"color:red\"><!-- end -->")},
		{"markup inside an SVG title", 8, []string{"<a> carries a style attribute"}, workspacePage("</header>", "<svg><title><a style=\"color:red\"></a></title></svg></header>")},
		{"markup after a raw-text element that follows a closed svg", 8, []string{"does not scan: unterminated comment"}, workspacePage("</header>", `<svg></svg><title><!--</title><a style="color:red"></a><!-- --></header>`)},
		{"markup inside a raw-text element nested in svg", 8, []string{"<a> carries a style attribute"}, workspacePage("</header>", `<svg><script><textarea><a style="color:red"></a></textarea></script></svg></header>`)},
		{"markup inside noscript", 8, []string{"<a> carries a style attribute"}, workspacePage("</header>", `<noscript><a style="color:red"></a></noscript></header>`)},
		{"presentational attribute in a static view", 8, []string{`<main> carries the presentational attribute "bgcolor"`}, staticPage("<main>", "<main bgcolor=\"red\">")},
		{"presentational attributes in the workspace", 8, []string{
			`presentational attribute "align"`, `presentational attribute "alink"`, `presentational attribute "background"`, `presentational attribute "bgcolor"`,
			`presentational attribute "border"`, `presentational attribute "bordercolor"`, `presentational attribute "bottommargin"`, `presentational attribute "cellpadding"`,
			`presentational attribute "cellspacing"`, `presentational attribute "clear"`, `presentational attribute "color"`, `presentational attribute "cols"`,
			`presentational attribute "face"`, `presentational attribute "frame"`, `presentational attribute "frameborder"`, `presentational attribute "height"`,
			`presentational attribute "hspace"`, `presentational attribute "leftmargin"`, `presentational attribute "link"`, `presentational attribute "marginheight"`,
			`presentational attribute "marginwidth"`, `presentational attribute "noshade"`, `presentational attribute "nowrap"`, `presentational attribute "rightmargin"`,
			`presentational attribute "rows"`, `presentational attribute "rules"`, `presentational attribute "size"`, `presentational attribute "sizes"`,
			`presentational attribute "text"`, `presentational attribute "topmargin"`, `presentational attribute "valign"`, `presentational attribute "vlink"`,
			`presentational attribute "vspace"`, `presentational attribute "width"`,
		}, workspacePage("<main id=\"workspace-main\"", "<main align=\"left\" alink=\"red\" background=\"x.png\" bgcolor=\"red\" border=\"1\" bordercolor=\"red\" bottommargin=\"1\" cellpadding=\"1\" cellspacing=\"1\" clear=\"all\" color=\"red\" cols=\"2\" face=\"serif\" frame=\"box\" frameborder=\"1\" height=\"9\" hspace=\"1\" leftmargin=\"1\" link=\"red\" marginheight=\"1\" marginwidth=\"1\" noshade nowrap rightmargin=\"1\" rows=\"2\" rules=\"all\" size=\"2\" sizes=\"9px\" text=\"red\" topmargin=\"1\" valign=\"top\" vlink=\"red\" vspace=\"1\" width=\"9\" id=\"workspace-main\"")},
		{"SVG presentation attributes in rendered HTML", 8, []string{`<svg> carries the presentational attribute "fill"`, `<svg> carries the presentational attribute "stroke-width"`, `<svg> carries the presentational attribute "width"`}, workspacePage("</header>", "<svg fill=\"red\" stroke=\"currentColor\" stroke-width=\"2\" width=\"20\"></svg></header>")},
	}
	// Every style-write spelling has its own mutant line; the violation names
	// the spellings that matched it.
	for _, write := range []struct{ spelling, line string }{
		{"the style property", `document.body.style.color = "red";`},
		{"a bracketed style key", `document.body["style"].color = "red";`},
		{"a style object key", `Object.assign(document.body, {style: "color: red"});`},
		{"attributeStyleMap", `document.body.attributeStyleMap.clear();`},
		{"styleMap", `rule.styleMap.clear();`},
		{"cssText", `rule.cssText = "";`},
		{"insertRule", `sheet.insertRule("b {}");`},
		{"deleteRule", `sheet.deleteRule(0);`},
		{"replaceSync", `sheet.replaceSync("b {}");`},
		{"cssRules", `const rules = sheet.cssRules;`},
		{"styleSheets", `const sheets = document.styleSheets;`},
		{"the sheet property", `const sheet = link.sheet;`},
		{"adoptedStyleSheets", `document.adoptedStyleSheets = [];`},
		{"CSSStyleSheet", `const sheet = new CSSStyleSheet();`},
		{"animate", `document.body.animate([], 1);`},
		{"KeyframeEffect", `const effect = new KeyframeEffect(document.body, [], 1);`},
		{"a style attribute", `document.body.setAttribute("style", "");`},
		{"a style attribute", `document.body.setAttribute("Style", "");`},
		{"a style attribute", `document.body.toggleAttribute("style");`},
		{"a style attribute", `const attribute = document.createAttribute("STYLE");`},
		{"a namespaced style attribute", `document.body.setAttributeNS("", "style", "");`},
		{"a namespaced style attribute", `const attribute = document.createAttributeNS(null, "style");`},
		{"innerHTML", `document.body.innerHTML = "<b>mutant</b>";`},
		{"outerHTML", `document.body.outerHTML = "<b>mutant</b>";`},
		{"insertAdjacentHTML", `document.body.insertAdjacentHTML("beforeend", "<b>mutant</b>");`},
		{"setHTML", `document.body.setHTML("<b>mutant</b>");`},
		{"setHTML", `document.body.setHTMLUnsafe("<b>mutant</b>");`},
		{"parseHTML", `const parsed = Document.parseHTMLUnsafe("<b>mutant</b>");`},
		{"createContextualFragment", `document.createRange().createContextualFragment("<b>mutant</b>");`},
		{"DOMParser", `new DOMParser().parseFromString("<b>mutant</b>", "text/html");`},
		{"srcdoc", `frame.srcdoc = "<b>mutant</b>";`},
		{"document.write", `document.write("<b>mutant</b>");`},
		{"document.write", `document.writeln("<b>mutant</b>");`},
		{"a style or link element", `document.createElement("STYLE");`},
		{"a style or link element", `document.createElement("Link");`},
		{"a style or link element", `document.createElementNS("http://www.w3.org/1999/xhtml", "style");`},
	} {
		mutants = append(mutants, mutant{"script write through " + write.line, 7, []string{"through " + write.spelling + ": " + write.line}, appendScript(write.line)})
	}
	// Every SVG presentation attribute of SVG 1.1 and SVG 2 other than geometry
	// is refused when a script writes it, here with a value no rule admits.
	svgAttributes := []string{
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
	svgLines, svgDetails := []string{}, []string{}
	for index, attribute := range svgAttributes {
		svgLines = append(svgLines, fmt.Sprintf(`svg.setAttribute(%q, "v%d");`, attribute, index))
		svgDetails = append(svgDetails, fmt.Sprintf(`writes SVG presentation attribute %s="v%d"`, attribute, index))
	}
	mutants = append(mutants, mutant{"every listed SVG presentation attribute", 7, svgDetails, appendScript(svgLines...)})
	// Each element that the HTML parser reads as text ends where its end tag
	// begins, so a comment that its content opens does not hide later markup.
	for _, element := range []string{"xmp", "iframe", "noembed", "noframes", "noscript"} {
		mutants = append(mutants, mutant{"markup after " + element, 8, []string{"does not scan: unterminated comment"}, workspacePage("</header>", "<"+element+"><!--</"+element+`><a style="color:red"></a><!-- --></header>`)})
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			sources := shipped
			sources.scripts = maps.Clone(shipped.scripts)
			sources.staticHTML = maps.Clone(shipped.staticHTML)
			sources.workspaceHTML = maps.Clone(shipped.workspaceHTML)
			mutant.mutate(&sources)
			violations := checkDesignTokenGrammar(sources)
			for _, detail := range mutant.details {
				if !slices.ContainsFunc(violations, func(violation designTokenViolation) bool {
					return violation.rule == mutant.rule && strings.Contains(violation.detail, detail)
				}) {
					t.Errorf("mutant was not refused under rule %d with %q; violations: %v", mutant.rule, detail, violations)
				}
			}
		})
	}
}

// The token stylesheet has one owner, browserdoc; the static views inline its
// exact bytes before their own style and the workspace links the same bytes
// before workspace.css.
func TestStaticAndWorkspaceViewsConsumeTheOneTokenStylesheet(t *testing.T) {
	file, err := os.ReadFile("../../kernel/browserdoc/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	if browserdoc.TokenStylesheet() != string(file) || !bytes.Equal(tokensCSS, file) {
		t.Fatal("the token stylesheet and the served token asset must be the exact bytes of browserdoc/tokens.css")
	}
	sources, err := loadDesignTokenSources()
	if err != nil {
		t.Fatal(err)
	}
	style := regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	for name, page := range sources.staticHTML {
		matches := style.FindAllStringSubmatch(page, -1)
		if len(matches) != 1 || matches[0][1] != string(file)+sources.staticStyle {
			t.Fatalf("%s: the single style element must hold the token stylesheet followed by the static style", name)
		}
		if strings.Contains(page, "<link") {
			t.Fatalf("%s: a static view must not link a stylesheet", name)
		}
	}
	links := regexp.MustCompile(`<link [^>]*>`)
	for name, page := range sources.workspaceHTML {
		want := []string{`<link rel="stylesheet" href="/assets/tokens.css">`, `<link rel="stylesheet" href="/assets/workspace.css">`}
		if got := links.FindAllString(page, -1); !slices.Equal(got, want) {
			t.Fatalf("%s: stylesheet links = %q, want %q", name, got, want)
		}
	}
}
