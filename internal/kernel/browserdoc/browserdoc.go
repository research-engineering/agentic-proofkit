package browserdoc

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"html"
	"regexp"
	"sort"
	"strings"
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
	Key   string
	Value string
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
		"<label class=\"toggle\"><input id=\"proofkit-show-ids\" type=\"checkbox\" checked> Show IDs</label>",
		"<label class=\"toggle\"><input id=\"proofkit-open-details\" type=\"checkbox\"> Open details</label>",
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
		"<section class=\"table-view\" data-proofkit-table-section aria-label=\"Rendered table\" hidden>",
		"<div class=\"table-scroll\">",
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
	parts = append(parts, "</tbody>", "</table>", "</div>", "</section>")
	return strings.Join(parts, "\n")
}

func tableRow(row Row, columns []Column) string {
	cells := map[string]string{}
	for _, cell := range row.Cells {
		cells[cell.Key] = cell.Value.html
	}
	parts := []string{fmt.Sprintf("<tr data-proofkit-table-row data-search=\"%s\"%s>", Escape(row.SearchText), filterAttributes(row.FilterValues))}
	for _, column := range columns {
		parts = append(parts, "<td>"+cells[column.Key]+"</td>")
	}
	parts = append(parts, "</tr>")
	return strings.Join(parts, "\n")
}

func filterAttributes(values []FilterValue) string {
	parts := make([]string, 0, len(values))
	for _, filter := range values {
		parts = append(parts, fmt.Sprintf(" data-filter-%s=\"%s\"", Escape(safeFilterKey(filter.Key)), Escape(filter.Value)))
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
// dark color scheme keeps its own rules on the separate dark tokens.
func css() string {
	return strings.Join([]string{
		":root{color-scheme:light dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;line-height:var(--static-line-height);background:var(--static-canvas);color:var(--static-text)}",
		"body{margin:0;overflow-wrap:anywhere}",
		"main{max-width:var(--static-page-width);margin:0 auto;padding:var(--static-space-32) var(--static-space-20) var(--static-space-56)}",
		"header{margin-bottom:var(--static-space-20)}",
		"h1{font-size:var(--static-font-size-title);line-height:var(--static-line-height-title);margin:0}",
		"h2{font-size:var(--static-font-size-heading);margin:0 0 var(--static-space-12)}",
		"h3{font-size:var(--static-font-size-subheading);margin:var(--static-space-18) 0 var(--static-space-8)}",
		".eyebrow{font-size:var(--static-font-size-label);font-weight:700;letter-spacing:0;text-transform:uppercase;color:var(--static-muted-text);margin:0 0 var(--static-space-8)}",
		"a{color:var(--static-link);text-decoration:none}a:hover{text-decoration:underline}",
		".summary,.hierarchy,.controls,.exports,.card,.table-view,.non-claims{background:var(--static-surface);border:var(--border-width) solid var(--static-border);border-radius:var(--radius-8);box-shadow:var(--static-shadow)}",
		".summary{padding:var(--static-space-16);margin-bottom:var(--static-space-16)}",
		".hierarchy{display:grid;grid-template-columns:repeat(auto-fit,minmax(var(--static-hierarchy-column),1fr));gap:var(--static-space-14);padding:var(--static-space-16);margin-bottom:var(--static-space-16)}",
		".hierarchy section{min-width:0}",
		".hierarchy h2,.card-group>h2{font-size:var(--static-font-size-group);text-transform:uppercase;letter-spacing:0;color:var(--static-muted-text);margin:0 0 var(--static-space-10)}",
		".hierarchy ul{margin:0;padding-left:var(--static-space-18)}",
		".hierarchy li{margin:var(--static-space-4) 0}.hierarchy span,.card-group>h2 span{font-weight:400;color:var(--static-muted-text)}",
		"dl{display:grid;grid-template-columns:minmax(var(--static-term-column-min),var(--static-term-column-max)) 1fr;gap:var(--static-space-8) var(--static-space-14);margin:0}",
		"dt{font-weight:700;color:var(--static-term-text)}",
		"dd{margin:0;min-width:0}",
		"code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--static-font-size-code);background:var(--static-code-surface);border-radius:var(--radius-4);padding:var(--static-code-padding-block) var(--static-code-padding-inline)}",
		".controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(var(--static-control-column),1fr));gap:var(--static-space-10);align-items:end;padding:var(--static-space-14);margin-bottom:var(--static-space-10);position:sticky;top:0;z-index:1}",
		".control{display:grid;gap:var(--static-space-6);min-width:0}",
		".search-label{position:absolute;left:var(--static-offscreen)}",
		"input[type=search],select{width:100%;box-sizing:border-box;border:var(--border-width) solid var(--static-control-border);border-radius:var(--radius-6);padding:var(--static-space-8) var(--static-space-10);background:var(--static-surface);color:inherit}",
		".toggle{white-space:nowrap;font-size:var(--static-font-size-control)}",
		".exports{display:flex;flex-wrap:wrap;gap:var(--static-space-10);align-items:center;padding:var(--static-space-14);margin-bottom:var(--static-space-10)}",
		".exports h2{font-size:var(--static-font-size-group);text-transform:uppercase;letter-spacing:0;color:var(--static-muted-text);margin:0 var(--static-space-8) 0 0}",
		"button{border:var(--border-width) solid var(--static-control-border);border-radius:var(--radius-6);background:var(--static-secondary-surface);color:inherit;padding:var(--static-space-8) var(--static-space-10);cursor:pointer}button:hover{background:var(--static-secondary-hover)}",
		".result-count{margin:var(--static-space-12) var(--static-space-2);color:var(--static-muted-text)}",
		".cards{display:grid;gap:var(--static-space-18)}",
		".cards[hidden]{display:none}",
		".card-group[hidden]{display:none}",
		".card-group{display:grid;gap:var(--static-space-12);scroll-margin-top:var(--static-scroll-margin)}",
		".card-group>h2{border-bottom:var(--border-width) solid var(--static-border);padding-bottom:var(--static-space-8)}",
		".card{padding:var(--static-space-18)}",
		".proofkit-id{display:inline-block;margin-right:var(--static-space-8);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--static-font-size-code)}",
		"html[data-show-ids=false] .proofkit-id{display:none}",
		".proofkit-title{font-weight:700}",
		"details{border:var(--border-width) solid var(--static-border);border-radius:var(--radius-6);margin-top:var(--static-space-12);padding:var(--static-space-10) var(--static-space-12)}",
		"summary{cursor:pointer;font-weight:700}",
		".table-view{padding:0;overflow:hidden}",
		".table-scroll{overflow:auto}",
		"table{width:100%;border-collapse:collapse;font-size:var(--static-font-size-control)}",
		"th,td{border-bottom:var(--border-width) solid var(--static-border);padding:var(--static-space-10) var(--static-space-12);text-align:left;vertical-align:top}",
		"th{position:sticky;top:0;background:var(--static-secondary-surface);font-size:var(--static-font-size-label);text-transform:uppercase;letter-spacing:0;color:var(--static-muted-text)}",
		".non-claims{margin-top:var(--static-space-18);padding:var(--static-space-18)}",
		"ul{margin:var(--static-space-8) 0 0;padding-left:var(--static-space-22)}",
		"@media (max-width:720px){main{padding:var(--static-space-24) var(--static-space-12) var(--static-space-40)}.controls{grid-template-columns:1fr;position:static}dl{grid-template-columns:1fr}.summary,.controls,.exports,.card,.non-claims{border-radius:var(--radius-6)}}",
		"@media (prefers-color-scheme:dark){:root{background:var(--static-dark-canvas);color:var(--static-dark-text)}.summary,.hierarchy,.controls,.exports,.card,.table-view,.non-claims{background:var(--static-dark-surface);border-color:var(--static-dark-border)}.eyebrow,.result-count,dt,.hierarchy h2,.card-group>h2,.hierarchy span,.card-group>h2 span,th,.exports h2{color:var(--static-dark-muted-text)}input[type=search],select,th{background:var(--static-dark-inset-surface)}input[type=search],select,button{border-color:var(--static-dark-control-border)}button{background:var(--static-dark-secondary-surface)}button:hover{background:var(--static-dark-secondary-hover)}code{background:var(--static-dark-inset-surface)}details,th,td,.card-group>h2{border-color:var(--static-dark-border)}a{color:var(--static-dark-link)}}",
	}, "")
}
