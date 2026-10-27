package browserdoc

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"html"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Fragment struct {
	html string
}

type DefinitionItem struct {
	Label string
	Value Fragment
}

type Document struct {
	Title             string
	Authority         string
	SummaryItems      []SummaryItem
	HierarchySections []HierarchySection
	Filters           []Filter
	Cards             []Card
	Table             *Table
	ExportFiles       []ExportFile
	NonClaims         []string
}

type SummaryItem struct {
	Label string
	Value Fragment
}

type HierarchySection struct {
	Title string
	Items []HierarchyItem
}

type HierarchyItem struct {
	Label  string
	Detail string
	Href   string
}

type Filter struct {
	Key    string
	Label  string
	Values []string
}

type Card struct {
	ID           string
	Title        string
	GroupID      string
	GroupLabel   string
	Body         Fragment
	SearchText   string
	FilterValues []FilterValue
}

type FilterValue struct {
	Key    string
	Values []string
}

type Table struct {
	Columns []Column
	Rows    []Row
}

type Column struct {
	Key   string
	Label string
}

type Row struct {
	ID           string
	Cells        []Cell
	SearchText   string
	FilterValues []FilterValue
}

type Cell struct {
	Key   string
	Value Fragment
}

type ExportFile struct {
	Label    string
	FileName string
	Content  string
}

var filterKeyPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

//go:embed browser.js
var browserScript string

//go:embed tokens.css
var tokenStylesheet string

// TokenStylesheet returns the exact bytes of the design-token stylesheet, the
// one owner of the color, size and breakpoint values of the static views and
// the requirement-browser workspace.
func TokenStylesheet() string {
	return tokenStylesheet
}

// ScriptHashSource commits to the exact inline script bytes emitted by HTML.
func ScriptHashSource() string {
	digest := sha256.Sum256([]byte(browserScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
}

func HTML(input Document) string {
	hasTable := input.Table != nil
	parts := []string{
		"<!doctype html>",
		"<html lang=\"en\" data-show-ids=\"true\">",
		"<head>",
		"<meta charset=\"utf-8\">",
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
		fmt.Sprintf("<title>%s</title>", Escape(input.Title)),
		fmt.Sprintf("<style>%s%s</style>", tokenStylesheet, css()),
		"</head>",
		"<body data-proofkit-browser-view=\"true\">",
		"<main>",
		fmt.Sprintf("<header><p class=\"eyebrow\">Proofkit rendered view</p><h1>%s</h1></header>", Escape(input.Title)),
		"<section class=\"summary\" aria-label=\"View summary\">",
		"<dl>",
		fmt.Sprintf("<dt>Authority</dt><dd>%s</dd>", Escape(input.Authority)),
	}
	for _, item := range input.SummaryItems {
		parts = append(parts, fmt.Sprintf("<dt>%s</dt><dd>%s</dd>", Escape(item.Label), item.Value.html))
	}
	parts = append(parts,
		"</dl>",
		"</section>",
		hierarchy(input.HierarchySections),
		controls(input.Filters, hasTable),
		exports(input.ExportFiles),
		fmt.Sprintf("<p class=\"result-count\"><span id=\"proofkit-visible-count\">%d</span> of %d records shown</p>", len(input.Cards), len(input.Cards)),
		cards(input.Cards),
	)
	if hasTable {
		parts = append(parts, table(*input.Table))
	}
	parts = append(parts,
		"<section class=\"non-claims\" aria-label=\"View non-claims\">",
		"<h2>View Non-Claims</h2>",
		ListOrNone(input.NonClaims, false).html,
		"</section>",
		"</main>",
		fmt.Sprintf("<script>%s</script>", browserScript),
		"</body>",
		"</html>",
		"",
	)
	return strings.Join(parts, "\n")
}

func Text(value string) Fragment {
	return Fragment{html: Escape(value)}
}

func Code(value string) Fragment {
	return Fragment{html: "<code>" + Escape(value) + "</code>"}
}

func Concat(values ...Fragment) Fragment {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, value.html)
	}
	return Fragment{html: strings.Join(parts, "\n")}
}

func Heading(level int, value string) Fragment {
	if level < 2 || level > 3 {
		level = 3
	}
	return Fragment{html: fmt.Sprintf("<h%d>%s</h%d>", level, Escape(value), level)}
}

func Definition(label string, value Fragment) DefinitionItem {
	return DefinitionItem{Label: label, Value: value}
}

func DefinitionList(items ...DefinitionItem) Fragment {
	parts := []string{"<dl>"}
	for _, item := range items {
		parts = append(parts, "<dt>"+Escape(item.Label)+"</dt><dd>"+item.Value.html+"</dd>")
	}
	parts = append(parts, "</dl>")
	return Fragment{html: strings.Join(parts, "\n")}
}

func Details(summary string, values ...Fragment) Fragment {
	return details("", summary, values)
}

// AnchoredDetails is Details whose element is the in-page target of every
// InPageLink with the same TargetKey.
func AnchoredDetails(targetKey string, summary string, values ...Fragment) Fragment {
	return details(" id=\""+Escape(FragmentID(targetKey))+"\"", summary, values)
}

func details(attributes string, summary string, values []Fragment) Fragment {
	parts := []string{"<details" + attributes + "><summary>" + Escape(summary) + "</summary>"}
	for _, value := range values {
		parts = append(parts, value.html)
	}
	parts = append(parts, "</details>")
	return Fragment{html: strings.Join(parts, "\n")}
}

func Section(title string, values ...Fragment) Fragment {
	parts := []string{"<section class=\"scenario-block\">", "<h3>" + Escape(title) + "</h3>"}
	for _, value := range values {
		parts = append(parts, value.html)
	}
	parts = append(parts, "</section>")
	return Fragment{html: strings.Join(parts, "\n")}
}

// statusTones maps a state word to the tone of its badge. The badge always
// shows the state as text, so the tone never carries the state alone; a state
// outside this table gets the neutral info tone.
var statusTones = map[string]string{"passed": "passed", "failed": "failed", "blocked": "blocked", "warning": "warning"}

// Status renders a state as a badge whose text is the state itself.
func Status(value string) Fragment {
	tone, ok := statusTones[value]
	if !ok {
		tone = "info"
	}
	return Fragment{html: "<span class=\"status-badge\" data-status=\"" + tone + "\">" + Escape(value) + "</span>"}
}

func Summary(label string, value string, code bool) SummaryItem {
	if code {
		return SummaryItem{Label: label, Value: Code(value)}
	}
	return SummaryItem{Label: label, Value: Text(value)}
}

func NewFilter(key string, label string, values []string) Filter {
	return Filter{Key: safeFilterKey(key), Label: label, Values: sortedUnique(values)}
}

func SearchText(values []string) string {
	return strings.Join(values, " ")
}

func TableCell(key string, value string, code bool) Cell {
	if code {
		return Cell{Key: key, Value: Code(value)}
	}
	return Cell{Key: key, Value: Text(value)}
}

func ListOrNone(values []string, code bool) Fragment {
	if len(values) == 0 {
		return Text("none")
	}
	items := make([]string, 0, len(values))
	for _, value := range values {
		if code {
			items = append(items, "<li><code>"+Escape(value)+"</code></li>")
			continue
		}
		items = append(items, "<li>"+Escape(value)+"</li>")
	}
	return Fragment{html: "<ul>" + strings.Join(items, "") + "</ul>"}
}

// InPageLink links to the AnchoredDetails declared with the same TargetKey in
// the same document.
type InPageLink struct {
	Label     string
	TargetKey string
}

// InPageLinkListOrNone renders code-labelled in-page links like a code
// ListOrNone.
func InPageLinkListOrNone(links []InPageLink) Fragment {
	if len(links) == 0 {
		return Text("none")
	}
	items := make([]string, 0, len(links))
	for _, link := range links {
		items = append(items, "<li><a href=\"#"+Escape(FragmentID(link.TargetKey))+"\"><code>"+Escape(link.Label)+"</code></a></li>")
	}
	return Fragment{html: "<ul>" + strings.Join(items, "") + "</ul>"}
}

func Export(label string, fileName string, content string) ExportFile {
	return ExportFile{Label: label, FileName: SafeFileName(fileName), Content: content}
}

func SafeFileName(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\\", "-"), "/", "-"))
	var builder strings.Builder
	lastDash := false
	for _, char := range strings.ToLower(value) {
		switch {
		case (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '_':
			builder.WriteRune(char)
			lastDash = false
		case char == '-' || char == ' ':
			if !lastDash && builder.Len() > 0 {
				builder.WriteByte('-')
				lastDash = true
			}
		default:
			if !lastDash && builder.Len() > 0 {
				builder.WriteByte('-')
				lastDash = true
			}
		}
	}
	result := strings.Trim(builder.String(), "-.")
	if result == "" || result == "." || result == ".." {
		return "proofkit-rendered-view"
	}
	if len(result) > 120 {
		result = strings.Trim(result[:120], "-.")
	}
	if result == "" {
		return "proofkit-rendered-view"
	}
	return result
}

func Escape(value string) string {
	return html.EscapeString(value)
}

func FragmentID(value string) string {
	return "proofkit-" + base64.RawURLEncoding.EncodeToString([]byte(value))
}

func hierarchy(sections []HierarchySection) string {
	if len(sections) == 0 {
		return ""
	}
	parts := []string{"<nav class=\"hierarchy\" aria-label=\"Specification hierarchy\">"}
	for _, section := range sections {
		parts = append(parts, "<section><h2>"+Escape(section.Title)+"</h2>", hierarchyItems(section.Items), "</section>")
	}
	parts = append(parts, "</nav>")
	return strings.Join(parts, "\n")
}

func hierarchyItems(items []HierarchyItem) string {
	if len(items) == 0 {
		return "<p>none</p>"
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		label := Escape(item.Label)
		if href := safeHref(item.Href); href != "" {
			label = fmt.Sprintf("<a href=\"%s\">%s</a>", Escape(href), label)
		}
		detail := ""
		if item.Detail != "" {
			detail = " <span>" + Escape(item.Detail) + "</span>"
		}
		parts = append(parts, "<li>"+label+detail+"</li>")
	}
	return "<ul>" + strings.Join(parts, "") + "</ul>"
}

func controls(filters []Filter, hasTable bool) string {
	parts := []string{
		"<section class=\"controls\" aria-label=\"View filters\">",
		"<div class=\"control\">",
		"<label class=\"search-label\" for=\"proofkit-search\">Search</label>",
		"<input id=\"proofkit-search\" type=\"search\" autocomplete=\"off\" placeholder=\"Filter records\">",
		"</div>",
	}
	if hasTable {
		parts = append(parts, "<div class=\"control\"><label for=\"proofkit-view-mode\">View</label><select id=\"proofkit-view-mode\"><option value=\"cards\">Cards</option><option value=\"table\">Table</option></select></div>")
	}
	parts = append(parts,
		"<div class=\"control\" role=\"group\" aria-labelledby=\"proofkit-display-label\"><span class=\"control-label\" id=\"proofkit-display-label\">Display</span><div class=\"toggles\"><label class=\"toggle\"><input id=\"proofkit-show-ids\" type=\"checkbox\" checked> Show IDs</label><label class=\"toggle\"><input id=\"proofkit-open-details\" type=\"checkbox\"> Open details</label></div></div>",
	)
	for _, filter := range filters {
		key := safeFilterKey(filter.Key)
		parts = append(parts,
			"<div class=\"control\">",
			fmt.Sprintf("<label for=\"proofkit-filter-%s\">%s</label>", Escape(key), Escape(filter.Label)),
			fmt.Sprintf("<select id=\"proofkit-filter-%s\" data-proofkit-filter data-filter-key=\"%s\">", Escape(key), Escape(key)),
			"<option value=\"\">All</option>",
		)
		for _, value := range filter.Values {
			parts = append(parts, fmt.Sprintf("<option value=\"%s\">%s</option>", Escape(value), Escape(value)))
		}
		parts = append(parts, "</select></div>")
	}
	parts = append(parts, "</section>")
	return strings.Join(parts, "\n")
}

func exports(files []ExportFile) string {
	if len(files) == 0 {
		return ""
	}
	parts := []string{"<section class=\"exports\" aria-label=\"View downloads\">", "<h2>Downloads</h2>"}
	for _, file := range files {
		fileName := SafeFileName(file.FileName)
		encoded := base64.StdEncoding.EncodeToString([]byte(file.Content))
		parts = append(parts, fmt.Sprintf("<button type=\"button\" data-proofkit-download data-download-file=\"%s\" data-download-content=\"%s\">%s</button>", Escape(fileName), Escape(encoded), Escape(file.Label)))
	}
	parts = append(parts, "</section>")
	return strings.Join(parts, "\n")
}

func cards(items []Card) string {
	groups := cardGroups(items)
	parts := []string{"<section class=\"cards\" data-proofkit-card-section aria-label=\"Rendered records\">"}
	for _, group := range groups {
		parts = append(parts,
			fmt.Sprintf("<section class=\"card-group\" data-proofkit-card-group id=\"%s\">", Escape(group.AnchorID)),
			fmt.Sprintf("<h2>%s <span>%d</span></h2>", Escape(group.Label), len(group.Cards)),
		)
		for _, card := range group.Cards {
			parts = append(parts, browserCard(card))
		}
		parts = append(parts, "</section>")
	}
	parts = append(parts, "</section>")
	return strings.Join(parts, "\n")
}

func browserCard(card Card) string {
	attributes := filterAttributes(card.FilterValues)
	return strings.Join([]string{
		fmt.Sprintf("<article class=\"card\" data-proofkit-card data-search=\"%s\"%s>", Escape(card.SearchText), attributes),
		fmt.Sprintf("<h2><span class=\"proofkit-id\">%s</span><span class=\"proofkit-title\">%s</span></h2>", Escape(card.ID), Escape(card.Title)),
		card.Body.html,
		"</article>",
	}, "\n")
}

func table(input Table) string {
	parts := []string{
		"<section class=\"table-view\" data-proofkit-table-section role=\"region\" aria-label=\"Rendered table\" tabindex=\"0\" hidden>",
		"<table>",
		"<thead>",
		"<tr>",
	}
	for _, column := range input.Columns {
		parts = append(parts, fmt.Sprintf("<th scope=\"col\">%s</th>", Escape(column.Label)))
	}
	parts = append(parts, "</tr>", "</thead>", "<tbody>")
	for _, row := range input.Rows {
		parts = append(parts, tableRow(row, input.Columns))
	}
	parts = append(parts, "</tbody>", "</table>", "</section>")
	return strings.Join(parts, "\n")
}

func tableRow(row Row, columns []Column) string {
	cells := map[string]string{}
	for _, cell := range row.Cells {
		cells[cell.Key] = cell.Value.html
	}
	parts := []string{fmt.Sprintf("<tr data-proofkit-table-row data-search=\"%s\"%s>", Escape(row.SearchText), filterAttributes(row.FilterValues))}
	for _, column := range columns {
		parts = append(parts, "<td>"+breakOpportunities(cells[column.Key])+"</td>")
	}
	parts = append(parts, "</tr>")
	return strings.Join(parts, "\n")
}

// Table cells hold identifiers such as requirement IDs, dotted names, paths
// and digests. A cell breaks only at the line-break opportunities that
// breakOpportunities adds to its text, never inside a word: after each of
// "/", ".", "_", "-" and ":" that a letter follows, and inside a run of more
// than tableBreakRun letters and digits after every tableBreakStep of them.
const (
	tableBreakSeparators = "/._-:"
	tableBreakRun        = 24
	tableBreakStep       = 12
)

// breakOpportunities inserts <wbr> into the text of an HTML fragment that
// browserdoc rendered; tags and character references pass through unchanged
// and end a run.
func breakOpportunities(fragment string) string {
	var builder strings.Builder
	text := []rune{}
	flush := func() {
		for index := 0; index < len(text); {
			run := index
			for run < len(text) && (unicode.IsLetter(text[run]) || unicode.IsDigit(text[run])) {
				run++
			}
			for offset, character := range text[index:run] {
				builder.WriteRune(character)
				if run-index > tableBreakRun && (offset+1)%tableBreakStep == 0 && index+offset+1 < run {
					builder.WriteString("<wbr>")
				}
			}
			if run > index {
				index = run
				continue
			}
			builder.WriteRune(text[index])
			if strings.ContainsRune(tableBreakSeparators, text[index]) && index+1 < len(text) && unicode.IsLetter(text[index+1]) {
				builder.WriteString("<wbr>")
			}
			index++
		}
		text = text[:0]
	}
	for index := 0; index < len(fragment); {
		var end int
		switch fragment[index] {
		case '<':
			end = strings.IndexByte(fragment[index:], '>')
		case '&':
			end = strings.IndexByte(fragment[index:], ';')
		default:
			character, size := utf8.DecodeRuneInString(fragment[index:])
			text = append(text, character)
			index += size
			continue
		}
		if end < 0 {
			end = len(fragment) - index - 1
		}
		flush()
		builder.WriteString(fragment[index : index+end+1])
		index += end + 1
	}
	flush()
	return builder.String()
}

func filterAttributes(values []FilterValue) string {
	parts := make([]string, 0, len(values))
	for _, filter := range values {
		if len(filter.Values) == 0 {
			continue
		}
		encoded, _ := json.Marshal(filter.Values)
		parts = append(parts, fmt.Sprintf(" data-filter-%s=\"%s\"", Escape(safeFilterKey(filter.Key)), Escape(string(encoded))))
	}
	return strings.Join(parts, "")
}

type cardGroup struct {
	AnchorID string
	Label    string
	Cards    []Card
}

func cardGroups(cards []Card) []cardGroup {
	byKey := map[string]cardGroup{}
	for _, card := range cards {
		label := card.GroupLabel
		if label == "" {
			label = "Records"
		}
		key := card.GroupID
		if key == "" {
			key = label
		}
		group := byKey[key]
		group.Label = label
		group.Cards = append(group.Cards, card)
		byKey[key] = group
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		leftGroup := byKey[keys[left]]
		rightGroup := byKey[keys[right]]
		if leftGroup.Label != rightGroup.Label {
			return leftGroup.Label < rightGroup.Label
		}
		return keys[left] < keys[right]
	})
	result := make([]cardGroup, 0, len(keys))
	for _, key := range keys {
		group := byKey[key]
		group.AnchorID = FragmentID(key)
		result = append(result, group)
	}
	return result
}

func sortedUnique(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func safeFilterKey(value string) string {
	if filterKeyPattern.MatchString(value) {
		return value
	}
	return "invalid-filter-key-" + stableSuffix(value)
}

func safeHref(value string) string {
	if strings.HasPrefix(value, "#proofkit-") && !strings.ContainsAny(value, "\"'<> \t\r\n") {
		return value
	}
	return ""
}

func stableSuffix(value string) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return fmt.Sprintf("%08x", hash.Sum32())
}

// css returns the static view stylesheet. Every color and size is a token of
// TokenStylesheet, which HTML emits before it in the same style element; the
// palette tokens switch with the color scheme, so the stylesheet has no
// color-scheme rules of its own.
func css() string {
	return strings.Join([]string{
		":root{color-scheme:light dark;font-family:var(--font-family-sans);font-size:var(--font-size-root);line-height:var(--line-height-body);background:var(--color-canvas);color:var(--color-text)}",
		"body{margin:0;overflow-wrap:anywhere}",
		"main{display:grid;gap:var(--space-16);max-width:var(--layout-page-width);margin:0 auto;padding:var(--space-32) var(--space-24) var(--space-48)}",
		"main>*{min-width:0;margin:0}",
		"header{display:grid;gap:var(--space-4);padding-bottom:var(--space-8)}",
		"h1{margin:0;font-size:var(--font-size-2xl);line-height:var(--line-height-tight)}",
		"h2,h3{margin:0;line-height:var(--line-height-tight)}",
		"h2{font-size:var(--font-size-lg)}",
		"h3{font-size:var(--font-size-md)}",
		".eyebrow,.hierarchy h2,.exports h2,.non-claims h2{margin:0;font-size:var(--font-size-sm);font-weight:700;letter-spacing:var(--letter-spacing-caps);text-transform:uppercase;color:var(--color-text-muted)}",
		".eyebrow{color:var(--color-accent)}",
		"a{color:var(--color-accent);text-decoration:underline}a:hover{color:var(--color-accent-hover)}",
		":focus-visible{outline:var(--focus-width) solid var(--color-focus);outline-offset:var(--focus-offset)}",
		".card{background:var(--color-surface);border:var(--border-width) solid var(--color-border);border-radius:var(--radius-8);box-shadow:var(--shadow-raised)}",
		".summary,.hierarchy,.controls,.exports{border-bottom:var(--border-width) solid var(--color-border)}",
		".table-view{border:var(--border-width) solid var(--color-border);border-radius:var(--radius-8);background:var(--color-surface)}",
		".summary{padding:var(--space-4) var(--space-24)}",
		"dl{display:grid;grid-template-columns:var(--layout-term-width) minmax(0,1fr);gap:var(--space-8) var(--space-16);margin:0}",
		"dt{font-weight:600;color:var(--color-text-muted)}",
		"dd{margin:0;min-width:0}",
		".summary dl{gap:0}",
		".summary dt,.summary dd{padding:var(--space-12) 0;border-top:var(--border-width) solid var(--color-border)}",
		".summary dt{padding-right:var(--space-16)}",
		".summary dt:has(+dd>details:first-child){padding-top:calc(var(--space-12) + var(--space-8) + var(--border-width))}",
		".summary dt:first-of-type,.summary dt:first-of-type+dd{border-top:0}",
		".hierarchy{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,var(--layout-hierarchy-width)),1fr));gap:var(--space-24);padding:var(--space-20) var(--space-24)}",
		".hierarchy section{display:grid;align-content:start;gap:var(--space-12);min-width:0}",
		".hierarchy ul{list-style:none;margin:0;padding:0}",
		".hierarchy li+li{margin-top:var(--space-8)}",
		".hierarchy span{color:var(--color-text-muted);font-size:var(--font-size-sm)}",
		".hierarchy p{margin:0}",
		"code{font-family:var(--font-family-mono);font-size:var(--font-size-code);background:var(--color-surface-subtle);border:var(--border-width) solid var(--color-border);border-radius:var(--radius-4);padding:0 var(--space-4)}",
		"code:empty{display:none}",
		".controls{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,var(--layout-control-width)),1fr));gap:var(--space-16);padding:var(--space-20) var(--space-24)}",
		".control{display:grid;grid-row:span 2;grid-template-rows:subgrid;row-gap:var(--space-8);min-width:0}",
		".control>label,.control-label{align-self:end;font-size:var(--font-size-sm);font-weight:600}",
		"input[type=search],select{width:100%;height:var(--target-size);box-sizing:border-box;border:var(--border-width) solid var(--color-border-strong);border-radius:var(--radius-6);padding:0 var(--space-12);background:var(--color-surface);color:inherit;font:inherit}",
		".toggles{display:flex;flex-wrap:wrap;align-items:center;gap:var(--space-4) var(--space-16);min-height:var(--target-size)}",
		".toggle{display:inline-flex;align-items:center;gap:var(--space-8);min-height:var(--target-size-min)}",
		"input::placeholder{color:var(--color-text-muted);opacity:1}",
		"input[type=checkbox]{width:var(--target-checkbox-size);height:var(--target-checkbox-size);margin:0;accent-color:var(--color-accent)}",
		"input[type=checkbox]:not(:focus-visible){outline:var(--border-width) solid var(--color-border-strong);outline-offset:0}",
		".exports{display:flex;flex-wrap:wrap;gap:var(--space-12);align-items:center;padding:var(--space-16) var(--space-24)}",
		".exports h2{margin-right:var(--space-8)}",
		"button{min-height:var(--target-size);border:var(--border-width) solid var(--color-border-strong);border-radius:var(--radius-6);background:var(--color-surface);color:var(--color-text);padding:0 var(--space-16);font:inherit;font-size:var(--font-size-sm);font-weight:600;cursor:pointer}button:hover{background:var(--color-surface-hover)}",
		".result-count{color:var(--color-text-muted);font-size:var(--font-size-sm)}",
		".cards{display:grid;gap:var(--space-32)}",
		".cards[hidden]{display:none}",
		".card-group[hidden]{display:none}",
		".card-group{display:grid;gap:var(--space-12);scroll-margin-top:var(--layout-scroll-margin)}",
		".card-group>h2{display:flex;flex-wrap:wrap;align-items:center;gap:var(--space-8);font-size:var(--font-size-md);padding-bottom:var(--space-8);border-bottom:var(--border-width) solid var(--color-border)}",
		".card-group>h2 span{padding:0 var(--space-8);border-radius:var(--radius-4);background:var(--color-surface-subtle);color:var(--color-text-muted);font-size:var(--font-size-sm);font-weight:600;line-height:var(--line-height-body)}",
		".card{padding:var(--space-20) var(--space-24)}",
		".card>*{margin:0}",
		".card>*+*{margin-top:var(--space-16)}",
		".card>h3+*{margin-top:var(--space-8)}",
		".card>h2{display:grid;gap:var(--space-4)}",
		".proofkit-id{display:block;font-family:var(--font-family-mono);font-size:var(--font-size-sm);font-weight:400;color:var(--color-text-muted)}",
		"html[data-show-ids=false] .proofkit-id{display:none}",
		".proofkit-title{font-weight:700}",
		".scenario-block{display:grid;gap:var(--space-8)}",
		"details{border-bottom:var(--border-width) solid var(--color-border)}",
		"summary{min-height:var(--target-size);box-sizing:border-box;padding:var(--space-8) var(--space-16);cursor:pointer;font-weight:600}",
		"details[open]>summary{border-bottom:var(--border-width) solid var(--color-border)}",
		"details>:not(summary){margin:var(--space-12) var(--space-16)}",
		".status-badge{display:inline-block;padding:0 var(--space-8);font-family:var(--font-family-sans);border:var(--border-width) solid var(--color-transparent);border-radius:var(--radius-4);font-size:var(--font-size-sm);font-weight:600;line-height:var(--line-height-body)}",
		".status-badge[data-status=passed]{color:var(--color-passed);background:var(--color-passed-surface)}",
		".status-badge[data-status=failed]{color:var(--color-failed);background:var(--color-failed-surface)}",
		".status-badge[data-status=blocked]{color:var(--color-blocked);background:var(--color-blocked-surface)}",
		".status-badge[data-status=warning]{color:var(--color-warning);background:var(--color-warning-surface)}",
		".status-badge[data-status=info]{color:var(--color-info);background:var(--color-info-surface)}",
		".table-view{max-height:var(--layout-table-height);padding:0;overflow:auto}",
		"table{width:100%;border-collapse:separate;border-spacing:0;font-size:var(--font-size-sm)}",
		"th,td{border-bottom:var(--border-width) solid var(--color-border);padding:var(--space-12);text-align:left;vertical-align:top}",
		"td{min-width:var(--layout-cell-min-width);overflow-wrap:break-word}",
		"th{position:sticky;top:0;z-index:1;background:var(--color-surface-subtle);color:var(--color-text-muted);font-weight:700;overflow-wrap:normal}",
		"tbody tr:last-child td{border-bottom:0}",
		".non-claims{display:grid;gap:var(--space-12);padding:var(--space-20) var(--space-24);border-top:var(--border-width) solid var(--color-border)}",
		"ul{margin:0;padding-left:var(--space-20)}",
		"li+li{margin-top:var(--space-4)}",
		"@media (max-width:48rem){main{padding:var(--space-20) var(--space-12) var(--space-32)}h1{font-size:var(--font-size-xl)}.summary,.hierarchy,.controls,.exports,.card,.non-claims{padding-left:var(--space-12);padding-right:var(--space-12)}summary{padding-left:var(--space-12);padding-right:var(--space-12)}details>:not(summary){margin-left:var(--space-8);margin-right:var(--space-8)}details details>:not(summary){margin-left:0;margin-right:0}ul{padding-left:var(--space-16)}dl{grid-template-columns:minmax(0,1fr);gap:var(--space-4)}dd+dt{margin-top:var(--space-8)}.summary dl{gap:0}.summary dt{padding-bottom:var(--space-4)}.summary dt:has(+dd>details:first-child){padding-top:var(--space-12)}.summary dd{border-top:0;padding-top:0}}",
		"@media (forced-colors:active){:focus-visible{outline-color:var(--forced-focus)}.status-badge{border-color:var(--forced-border)}}",
	}, "")
}
