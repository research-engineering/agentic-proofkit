package requirementbrowser

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// designTokenCategories is the closed category table of the design-token
// stylesheet: every token belongs to exactly one category by its name prefix.
// The palette category holds exactly the tokens whose base value is a literal
// color, so it is both the light and the dark palette.
var designTokenCategories = []struct {
	name     string
	prefixes []string
}{
	{"palette", []string{"--color-", "--shadow-"}},
	{"type", []string{"--font-", "--line-height-", "--letter-spacing-"}},
	{"spacing", []string{"--space-"}},
	{"radius", []string{"--radius-"}},
	{"border width", []string{"--border-width"}},
	{"layout", []string{"--layout-"}},
	{"target size", []string{"--target-"}},
	{"focus indicator", []string{"--focus-"}},
	{"breakpoint", []string{"--breakpoint-"}},
	{"forced colors", []string{"--forced-"}},
}

func designTokenCategory(name string) string {
	for _, category := range designTokenCategories {
		for _, prefix := range category.prefixes {
			if strings.HasPrefix(name, prefix) {
				return category.name
			}
		}
	}
	return ""
}

// checkDesignTokenCategories requires every token to belong to one category,
// every category to hold at least one token, the palette category to hold
// exactly the literal-color tokens, and every category to be read by both
// style owners: through var() in a declaration, or, for a breakpoint, through
// an @media or @container condition length.
func checkDesignTokenCategories(sources designTokenSources) []string {
	violations := []string{}
	ignore := func(int, string, string, ...any) {}
	nodes, err := parseStylesheet(sources.tokens)
	if err != nil {
		return []string{fmt.Sprintf("%s does not parse: %v", tokenSourceName, err)}
	}
	table := checkTokenStylesheet(nodes, ignore)
	categories := map[string]bool{}
	for _, name := range allTokenNames(table) {
		category := designTokenCategory(name)
		switch {
		case category == "":
			violations = append(violations, fmt.Sprintf("token %s belongs to no token category", name))
			continue
		case category == "palette" && !table.palette[name]:
			violations = append(violations, fmt.Sprintf("palette token %s holds no literal color", name))
		case category != "palette" && table.palette[name]:
			violations = append(violations, fmt.Sprintf("token %s holds a literal color outside the palette category", name))
		}
		categories[category] = true
	}
	for _, category := range designTokenCategories {
		if !categories[category.name] {
			violations = append(violations, fmt.Sprintf("no token belongs to category %s", category.name))
		}
	}
	for _, owner := range []struct{ name, source string }{{staticStyleSourceName, sources.staticStyle}, {workspaceCSSSourceName, sources.workspaceCSS}} {
		ownerNodes, err := parseStylesheet(owner.source)
		if err != nil {
			violations = append(violations, fmt.Sprintf("%s does not parse: %v", owner.name, err))
			continue
		}
		used := map[string]bool{}
		checkStyleOwner(owner.name, ownerNodes, table, used, ignore)
		checkConditionLengths(owner.name, ownerNodes, table, used, ignore)
		usedCategories := map[string]bool{}
		for name := range used {
			usedCategories[designTokenCategory(name)] = true
		}
		for _, category := range designTokenCategories {
			if categories[category.name] && !usedCategories[category.name] {
				violations = append(violations, fmt.Sprintf("%s uses no %s token", owner.name, category.name))
			}
		}
	}
	return violations
}

func TestEveryDesignTokenCategoryIsUsedByBothStyleOwners(t *testing.T) {
	shipped, err := loadDesignTokenSources()
	if err != nil {
		t.Fatal(err)
	}
	if violations := checkDesignTokenCategories(shipped); len(violations) > 0 {
		t.Fatalf("shipped token categories: %q", violations)
	}
	// Each mutant must be refused with exactly the listed violations.
	replace := func(field func(*designTokenSources) *string, old, replacement string) func(*designTokenSources) {
		return func(sources *designTokenSources) {
			target := field(sources)
			if !strings.Contains(*target, old) {
				t.Fatalf("mutant anchor %q is absent", old)
			}
			*target = strings.ReplaceAll(*target, old, replacement)
		}
	}
	tokens := func(sources *designTokenSources) *string { return &sources.tokens }
	static := func(sources *designTokenSources) *string { return &sources.staticStyle }
	workspace := func(sources *designTokenSources) *string { return &sources.workspaceCSS }
	for _, mutant := range []struct {
		name   string
		want   []string
		mutate func(*designTokenSources)
	}{
		{"static style reads no radius token", []string{"static style uses no radius token"}, func(sources *designTokenSources) {
			for _, radius := range []string{"var(--radius-4)", "var(--radius-6)", "var(--radius-8)"} {
				replace(static, radius, "0")(sources)
			}
		}},
		{"workspace reads no focus token", []string{"workspace.css uses no focus indicator token"}, func(sources *designTokenSources) {
			replace(workspace, "var(--focus-width)", "medium")(sources)
			replace(workspace, "var(--focus-offset)", "0")(sources)
		}},
		{"static style has no breakpoint condition", []string{"static style uses no breakpoint token"}, replace(static, "@media (max-width:48rem)", "@media print")},
		{"token outside every category", []string{"token --elevation-1 belongs to no token category"}, replace(tokens, "  --space-4: .25rem;\n", "  --space-4: .25rem;\n  --elevation-1: 1px;\n")},
		{"palette name without a color", []string{"palette token --color-gap holds no literal color"}, replace(tokens, "  --space-4: .25rem;\n", "  --space-4: .25rem;\n  --color-gap: 1px;\n")},
		{"color outside the palette category", []string{"token --space-ink holds a literal color outside the palette category"}, replace(tokens, "  --space-4: .25rem;\n", "  --space-4: .25rem;\n  --space-ink: #000000;\n")},
		{"category without a token", []string{"no token belongs to category focus indicator"}, func(sources *designTokenSources) {
			replace(tokens, "  --focus-width: 2px;\n  --focus-offset: 2px;\n", "")(sources)
			for _, owner := range []func(*designTokenSources) *string{static, workspace} {
				replace(owner, "var(--focus-width)", "var(--border-width)")(sources)
				replace(owner, "var(--focus-offset)", "var(--border-width)")(sources)
			}
		}},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			sources := shipped
			sources.scripts = maps.Clone(shipped.scripts)
			mutant.mutate(&sources)
			if got := checkDesignTokenCategories(sources); !slices.Equal(got, mutant.want) {
				t.Fatalf("violations = %q, want %q", got, mutant.want)
			}
		})
	}
}
