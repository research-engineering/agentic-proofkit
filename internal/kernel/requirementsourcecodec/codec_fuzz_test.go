package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func FuzzParseCanonicalRoundTrip(f *testing.F) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(f, modelLimits)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schemaVersion":2,"kind":"proofkit.requirement-source"}`))
	model, err := requirementsourcemodel.NormalizeWithLimits(testDraft(), modelLimits)
	if err == nil {
		payload, formatErr := FormatWithLimits(model, codecLimits, modelLimits)
		if formatErr == nil {
			f.Add(payload)
		}
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		assertCodecFuzzProperties(t, source, codecLimits, modelLimits)
	})
}

func TestFuzzSeedCorpusRoundTrips(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"schemaVersion":2,"kind":"proofkit.requirement-source"}`),
		mustPayload(t),
	}
	for _, seed := range seeds {
		assertCodecFuzzProperties(t, seed, codecLimits, modelLimits)
	}
}

func assertCodecFuzzProperties(t testing.TB, source []byte, codecLimits Limits, modelLimits requirementsourcemodel.Limits) {
	t.Helper()
	first, firstErr := ParseWithLimits(source, codecLimits, modelLimits)
	second, secondErr := ParseWithLimits(source, codecLimits, modelLimits)
	if ErrorCode(firstErr) != ErrorCode(secondErr) {
		t.Fatalf("nondeterministic error code: %q != %q", ErrorCode(firstErr), ErrorCode(secondErr))
	}
	if firstErr != nil || secondErr != nil {
		if firstErr == nil || secondErr == nil || firstErr.Error() != secondErr.Error() {
			t.Fatalf("nondeterministic error: %v != %v", firstErr, secondErr)
		}
		return
	}
	if !projectionsEqual(first.Model, second.Model) {
		t.Fatal("same bytes produced different models")
	}
	canonical, err := FormatWithLimits(first.Model, codecLimits, modelLimits)
	if err != nil {
		t.Fatalf("Format(admitted model) error = %v", err)
	}
	reparsed, err := ParseWithLimits(canonical, codecLimits, modelLimits)
	if err != nil {
		t.Fatalf("Parse(canonical) error = %v", err)
	}
	if !projectionsEqual(first.Model, reparsed.Model) {
		t.Fatal("canonical round trip changed model")
	}
	secondCanonical, err := FormatWithLimits(reparsed.Model, codecLimits, modelLimits)
	if err != nil || !bytes.Equal(canonical, secondCanonical) {
		t.Fatal("canonical formatting is not idempotent")
	}
	assertFuzzSourceMap(t, source, first.SourceMap)
}

func assertFuzzSourceMap(t testing.TB, source []byte, sourceMap SourceMap) {
	t.Helper()
	if err := sourceMapReplayError(source, sourceMap); err != nil {
		t.Fatal(err)
	}
}

type sourceMapReplay struct {
	source    []byte
	locations SourceMap
	positions map[int64]Position
	seen      []string
}

func sourceMapReplayError(source []byte, locations SourceMap) error {
	value, err := decodeReplayJSON(source)
	if err != nil || !utf8.Valid(source) {
		return errors.New("invalid source-map replay input")
	}
	replay := sourceMapReplay{source: source, locations: locations, positions: replayPositions(source, locations)}
	if err := replay.walk("", value, nil, nil); err != nil {
		return err
	}
	sort.Strings(replay.seen)
	if !reflect.DeepEqual(locations.Pointers(), replay.seen) {
		return errors.New("source-map pointer inventory differs")
	}
	return nil
}

func decodeReplayJSON(source []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	var value, extra any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid replay token")
	}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("replay token has trailing data")
	}
	return value, nil
}

func (replay *sourceMapReplay) gap(start, end int64, expected string) bool {
	return start >= 0 && start <= end && end <= int64(len(replay.source)) &&
		string(bytes.TrimSpace(replay.source[start:end])) == expected
}

func (replay *sourceMapReplay) walk(pointer string, expected any, parent *ByteSpan, key *string) error {
	location, ok := replay.locations.Location(pointer)
	if !ok {
		return errors.New("source-map pointer is missing")
	}
	span := location.ValueSpan
	if !validReplaySpan(span, len(replay.source)) {
		return errors.New("source-map value span is invalid")
	}
	if parent == nil {
		if !replay.gap(0, span.Start, "") || !replay.gap(span.End, int64(len(replay.source)), "") {
			return errors.New("source-map root omits input")
		}
	} else if span.Start <= parent.Start || span.End >= parent.End {
		return errors.New("source-map value escapes its parent")
	}
	if key == nil {
		if location.KeySpan != nil {
			return errors.New("source-map has an unexpected key span")
		}
	} else {
		if location.KeySpan == nil || !validReplaySpan(*location.KeySpan, len(replay.source)) {
			return errors.New("source-map key span is missing or invalid")
		}
		keySpan := *location.KeySpan
		if parent == nil || keySpan.Start <= parent.Start || !replay.gap(keySpan.End, span.Start, ":") {
			return errors.New("source-map key/value separation differs")
		}
		actual, err := decodeReplayJSON(replay.source[keySpan.Start:keySpan.End])
		if err != nil || actual != *key {
			return errors.New("source-map key replay differs")
		}
	}
	if replay.positions[span.Start] != location.Start || replay.positions[span.End] != location.End {
		return errors.New("source-map scalar coordinates differ")
	}
	replay.seen = append(replay.seen, pointer)
	childPointer := func(key string) string {
		return pointer + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
	}
	raw := replay.source[span.Start:span.End]
	switch value := expected.(type) {
	case map[string]any:
		if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
			return errors.New("source-map object delimiters differ")
		}
		keys := make([]string, 0, len(value))
		for name := range value {
			if err := replay.walk(childPointer(name), value[name], &span, &name); err != nil {
				return err
			}
			keys = append(keys, name)
		}
		sort.Slice(keys, func(a, b int) bool {
			left, _ := replay.locations.Location(childPointer(keys[a]))
			right, _ := replay.locations.Location(childPointer(keys[b]))
			return left.KeySpan.Start < right.KeySpan.Start
		})
		cursor := span.Start + 1
		for index, name := range keys {
			child, _ := replay.locations.Location(childPointer(name))
			separator := ""
			if index > 0 {
				separator = ","
			}
			if !replay.gap(cursor, child.KeySpan.Start, separator) {
				return errors.New("source-map object coverage differs")
			}
			cursor = child.ValueSpan.End
		}
		if !replay.gap(cursor, span.End-1, "") {
			return errors.New("source-map object coverage differs")
		}
	case []any:
		if len(raw) < 2 || raw[0] != '[' || raw[len(raw)-1] != ']' {
			return errors.New("source-map array delimiters differ")
		}
		cursor := span.Start + 1
		for index, item := range value {
			path := childPointer(strconv.Itoa(index))
			if err := replay.walk(path, item, &span, nil); err != nil {
				return err
			}
			child, _ := replay.locations.Location(path)
			separator := ""
			if index > 0 {
				separator = ","
			}
			if !replay.gap(cursor, child.ValueSpan.Start, separator) {
				return errors.New("source-map array order or coverage differs")
			}
			cursor = child.ValueSpan.End
		}
		if !replay.gap(cursor, span.End-1, "") {
			return errors.New("source-map array coverage differs")
		}
	default:
		actual, err := decodeReplayJSON(raw)
		if err != nil || !bytes.Equal(raw, bytes.TrimSpace(raw)) || !reflect.DeepEqual(actual, expected) {
			return errors.New("source-map scalar replay differs")
		}
	}
	return nil
}

func validReplaySpan(span ByteSpan, length int) bool {
	return span.Start >= 0 && span.Start < span.End && span.End <= int64(length)
}

// Line-break intervals and scalar ranks are independent of the indexer's
// requested-offset sweep. Keep work linear in source size, not fields * bytes.
func replayPositions(source []byte, locations SourceMap) map[int64]Position {
	requested := map[int64]bool{}
	for _, pointer := range locations.Pointers() {
		location, _ := locations.Location(pointer)
		requested[location.ValueSpan.Start], requested[location.ValueSpan.End] = true, true
	}
	breaks := regexp.MustCompile("\r\n|\r|\n").FindAllIndex(source, -1)
	result := map[int64]Position{}
	line, rank, lineRank := 0, 0, 0
	observe := func(offset int) {
		for line < len(breaks) && breaks[line][0] < offset {
			line++
		}
		if line > 0 && offset <= breaks[line-1][1] {
			lineRank = rank
		}
		if requested[int64(offset)] {
			result[int64(offset)] = Position{Line: line + 1, ScalarColumn: rank - lineRank + 1}
		}
	}
	for offset := range string(source) {
		observe(offset)
		rank++
	}
	observe(len(source))
	return result
}

func TestSourceMapReplayRejectsIsolatedCoordinateFaults(t *testing.T) {
	// Independent lexical fixture: identical siblings make an order fault
	// invisible to value comparison; the escaped key also exercises RFC6901.
	const source = `{"a/b~":["x","x"]}`
	const array = "/a~1b~0"
	location := func(start, end int64, key *ByteSpan) Location {
		return Location{KeySpan: key, ValueSpan: ByteSpan{Start: start, End: end},
			Start: Position{Line: 1, ScalarColumn: int(start) + 1},
			End:   Position{Line: 1, ScalarColumn: int(end) + 1}}
	}
	fresh := func() SourceMap {
		return SourceMap{entries: map[string]Location{
			"":           location(0, 18, nil),
			array:        location(8, 17, &ByteSpan{Start: 1, End: 7}),
			array + "/0": location(9, 12, nil),
			array + "/1": location(13, 16, nil),
		}}
	}
	if err := sourceMapReplayError([]byte(source), fresh()); err != nil {
		t.Fatalf("independent positive map: %v", err)
	}
	for _, test := range []struct {
		name, path, want string
		change           func(Location) Location
		inventory        func(map[string]Location)
	}{
		{name: "missing pointer", want: "source-map pointer is missing", inventory: func(entries map[string]Location) { delete(entries, array+"/1") }},
		{name: "phantom pointer", want: "source-map pointer inventory differs", inventory: func(entries map[string]Location) { entries[array+"/2"] = entries[array+"/1"] }},
		{name: "wrong escaping", want: "source-map pointer is missing", inventory: func(entries map[string]Location) { entries["/a/b~"] = entries[array]; delete(entries, array) }},
		{name: "empty span", path: array + "/0", want: "source-map value span is invalid", change: func(l Location) Location { l.ValueSpan.End = l.ValueSpan.Start; return l }},
		{name: "negative span", path: array + "/0", want: "source-map value span is invalid", change: func(l Location) Location { l.ValueSpan.Start = -1; return l }},
		{name: "oversize span", path: array + "/0", want: "source-map value span is invalid", change: func(l Location) Location { l.ValueSpan.End = 19; return l }},
		{name: "parent escape", path: array + "/0", want: "source-map value escapes its parent", change: func(l Location) Location { l.ValueSpan.Start = 8; return l }},
		{name: "root omission", want: "source-map root omits input", change: func(l Location) Location { l.ValueSpan.Start = 1; return l }},
		{name: "missing key", path: array, want: "source-map key span is missing or invalid", change: func(l Location) Location { l.KeySpan = nil; return l }},
		{name: "wrong key", path: array, want: "source-map key replay differs", change: func(l Location) Location { l.KeySpan.Start = 2; return l }},
		{name: "lost colon", path: array, want: "source-map key/value separation differs", change: func(l Location) Location { l.KeySpan.End = 8; return l }},
		{name: "unexpected key", path: array + "/0", want: "source-map has an unexpected key span", change: func(l Location) Location { l.KeySpan = &ByteSpan{Start: 1, End: 7}; return l }},
		{name: "start line", path: array + "/0", want: "source-map scalar coordinates differ", change: func(l Location) Location { l.Start.Line++; return l }},
		{name: "start column", path: array + "/0", want: "source-map scalar coordinates differ", change: func(l Location) Location { l.Start.ScalarColumn++; return l }},
		{name: "end line", path: array + "/0", want: "source-map scalar coordinates differ", change: func(l Location) Location { l.End.Line++; return l }},
		{name: "end column", path: array + "/0", want: "source-map scalar coordinates differ", change: func(l Location) Location { l.End.ScalarColumn++; return l }},
		{name: "scalar token", path: array + "/0", want: "source-map scalar replay differs", change: func(l Location) Location { return location(10, 11, nil) }},
		{name: "equal sibling swap", want: "source-map array order or coverage differs", inventory: func(entries map[string]Location) {
			entries[array+"/0"], entries[array+"/1"] = entries[array+"/1"], entries[array+"/0"]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := fresh()
			if test.inventory != nil {
				test.inventory(candidate.entries)
			} else {
				candidate.entries[test.path] = test.change(candidate.entries[test.path])
			}
			if err := sourceMapReplayError([]byte(source), candidate); err == nil || err.Error() != test.want {
				t.Fatalf("isolated fault = %v; want %s", err, test.want)
			}
		})
	}
}

func TestAdmittedSourceMapReplaysUnicodeLineEndingsAndExactIntegers(t *testing.T) {
	const statement = "Preserve \u03b1 and \U0001d11e without changing coordinates."
	const integer = "9007199254740993"
	compact := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		root["sourceNonClaims"] = []any{statement}
		selector := root["derivations"].([]any)[0].(map[string]any)["selector"].(map[string]any)
		selector["end"] = json.Number(integer)
	})
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", "  "); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{"compact", compact},
		{"LF", indented.Bytes()},
		{"CRLF", bytes.ReplaceAll(indented.Bytes(), []byte("\n"), []byte("\r\n"))},
		{"CR", bytes.ReplaceAll(indented.Bytes(), []byte("\n"), []byte("\r"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			assertFuzzSourceMap(t, test.wire, parsed.SourceMap)
			for _, check := range []struct{ path, lexeme string }{
				{"/sourceNonClaims/0", `"` + statement + `"`},
				{"/derivations/0/selector/end", integer},
			} {
				location, ok := parsed.SourceMap.Location(check.path)
				if !ok || string(test.wire[location.ValueSpan.Start:location.ValueSpan.End]) != check.lexeme {
					t.Fatal("exact source lexeme changed")
				}
			}
		})
	}
}
