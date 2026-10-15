// Package schemadefs owns direct local JSON Schema definition references and
// the publication transform that shares repeated schema subtrees through them.
//
// Hoist and Expand operate on one JSON Schema document (draft 2020-12). Hoist
// moves repeated object subschemas of the document's root resource into root
// $defs entries named SharedPrefix plus a content digest and replaces every
// occurrence with a pure reference. Expand inlines exactly those reserved
// entries again, so Expand(Hoist(S)) is canonically equal to S. Hoist checks
// that equality itself before it returns.
package schemadefs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// SharedPrefix reserves the root $defs names that Hoist creates. Source
// documents must not use it; Expand inlines exactly these names.
const SharedPrefix = "shared-"

const (
	referencePrefix       = "#/$defs/"
	sharedDigestHexLength = 16
)

// Keywords that bind identity or dynamic scope. A subtree containing one of
// them anywhere, including inside annotation or literal data, is never moved.
var scopeKeywords = map[string]struct{}{
	"$anchor": {}, "$dynamicAnchor": {}, "$dynamicRef": {}, "$id": {}, "$recursiveAnchor": {}, "$recursiveRef": {},
}

// Keywords that name a target schema. A JSON-pointer fragment in $dynamicRef
// or $recursiveRef resolves exactly like $ref (draft 2020-12 section 8.2.3.2),
// so a moved target would dangle for any of them.
var referenceKeywords = []string{"$dynamicRef", "$recursiveRef", "$ref"}

// SubschemaForm classifies how a draft 2020-12 keyword value holds subschemas.
type SubschemaForm uint8

const (
	// NoSubschema marks keyword values that are data, not schemas (const, enum,
	// required, default, annotations and unknown keywords).
	NoSubschema SubschemaForm = iota
	SingleSubschema
	SubschemaList
	SubschemaMap
)

var subschemaForms = map[string]SubschemaForm{
	"additionalProperties": SingleSubschema, "contains": SingleSubschema, "contentSchema": SingleSubschema,
	"else": SingleSubschema, "if": SingleSubschema, "items": SingleSubschema, "not": SingleSubschema,
	"propertyNames": SingleSubschema, "then": SingleSubschema, "unevaluatedItems": SingleSubschema,
	"unevaluatedProperties": SingleSubschema,
	"allOf":                 SubschemaList, "anyOf": SubschemaList, "oneOf": SubschemaList, "prefixItems": SubschemaList,
	"$defs": SubschemaMap, "dependentSchemas": SubschemaMap, "patternProperties": SubschemaMap, "properties": SubschemaMap,
}

// KeywordSubschemaForm returns where keyword holds subschemas, if anywhere.
func KeywordSubschemaForm(keyword string) SubschemaForm {
	return subschemaForms[keyword]
}

// Reference returns the direct local reference to the named definition.
func Reference(name string) string {
	return referencePrefix + name
}

// Resolve returns the definition that ref names in resource. resource is the
// nearest enclosing schema resource root ($id or document root). Only a URI
// fragment naming one direct $defs entry is admitted; the fragment is percent-
// decoded and the entry name JSON-pointer-unescaped. Resolution never follows
// further references, fetches URLs or evaluates schemas.
func Resolve(resource map[string]any, ref any) (any, error) {
	text, ok := ref.(string)
	if !ok || !strings.HasPrefix(text, "#") {
		return nil, fmt.Errorf("schema reference must be a local fragment")
	}
	pointer, err := url.PathUnescape(strings.TrimPrefix(text, "#"))
	token, direct := strings.CutPrefix(pointer, "/$defs/")
	if err != nil || !direct || token == "" || strings.Contains(token, "/") {
		return nil, fmt.Errorf("schema reference must name one direct local definition")
	}
	definitions, ok := resource["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema reference has no local definition")
	}
	target, err := jsonpointer.Select(definitions, "/"+token)
	if err != nil {
		return nil, fmt.Errorf("schema reference has no local definition")
	}
	switch target.(type) {
	case map[string]any, bool:
		return target, nil
	default:
		return nil, fmt.Errorf("schema reference target must be an object or boolean schema")
	}
}

// Hoist returns a document equivalent to document in which every repeated
// object subschema of the root resource whose sharing saves canonical bytes is
// replaced by a reference to one root $defs entry. The input is not modified.
func Hoist(document map[string]any) (map[string]any, error) {
	source, canonical, err := normalize(document)
	if err != nil {
		return nil, err
	}
	if err := admitHoistSource(source); err != nil {
		return nil, err
	}
	hoisted, err := share(source)
	if err != nil {
		return nil, err
	}
	expanded, err := Expand(hoisted)
	if err != nil {
		return nil, err
	}
	restored, err := canonicalJSON(expanded)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(restored, canonical) {
		return nil, fmt.Errorf("shared schema expansion differs from its source document")
	}
	return hoisted, nil
}

// Expand inlines every reference to a shared definition and removes the shared
// definitions. Other references, definitions and embedded resources are kept.
// The input is not modified.
func Expand(document map[string]any) (map[string]any, error) {
	root, _ := cloneJSON(document).(map[string]any)
	definitions, _ := root["$defs"].(map[string]any)
	shared := map[string]any{}
	for name, value := range definitions {
		if strings.HasPrefix(name, SharedPrefix) {
			shared[name] = value
			delete(definitions, name)
		}
	}
	expander := sharedExpander{shared: shared, expanded: map[string]any{}, active: map[string]bool{}}
	if err := expander.children(root); err != nil {
		return nil, err
	}
	if len(shared) != 0 && len(definitions) == 0 {
		delete(root, "$defs")
	}
	return root, nil
}

type sharedExpander struct {
	shared   map[string]any
	expanded map[string]any
	active   map[string]bool
}

func (e sharedExpander) children(schema map[string]any) error {
	return eachSubschema(schema, func(_ string, value any, replace func(any)) error {
		return e.schema(value, replace)
	})
}

func (e sharedExpander) schema(value any, replace func(any)) error {
	node, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if _, resource := node["$id"]; resource {
		return nil
	}
	if ref, ok := node["$ref"].(string); ok && strings.HasPrefix(ref, referencePrefix+SharedPrefix) {
		if len(node) != 1 {
			return fmt.Errorf("shared schema reference must be a pure alias")
		}
		definition, err := e.definition(strings.TrimPrefix(ref, referencePrefix))
		if err != nil {
			return err
		}
		replace(cloneJSON(definition))
		return nil
	}
	return e.children(node)
}

func (e sharedExpander) definition(name string) (any, error) {
	if value, done := e.expanded[name]; done {
		return value, nil
	}
	if e.active[name] {
		return nil, fmt.Errorf("shared schema definitions form a reference cycle")
	}
	raw, exists := e.shared[name]
	if !exists {
		return nil, fmt.Errorf("shared schema reference has no shared definition")
	}
	e.active[name] = true
	value := cloneJSON(raw)
	if err := e.schema(value, func(replacement any) { value = replacement }); err != nil {
		return nil, err
	}
	delete(e.active, name)
	e.expanded[name] = value
	return value, nil
}

// eachSubschema visits the subschemas directly below schema in sorted keyword
// and member order. replace substitutes the visited value in its container.
func eachSubschema(schema map[string]any, visit func(keyword string, value any, replace func(any)) error) error {
	for _, keyword := range sortedKeys(schema) {
		switch KeywordSubschemaForm(keyword) {
		case SingleSubschema:
			if err := visit(keyword, schema[keyword], func(value any) { schema[keyword] = value }); err != nil {
				return err
			}
		case SubschemaList:
			members, _ := schema[keyword].([]any)
			for index := range members {
				if err := visit(keyword, members[index], func(value any) { members[index] = value }); err != nil {
					return err
				}
			}
		case SubschemaMap:
			members, _ := schema[keyword].(map[string]any)
			for _, name := range sortedKeys(members) {
				if err := visit(keyword, members[name], func(value any) { members[name] = value }); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// A source may already use direct local references and embedded resources, but
// it must not use the reserved shared names, and every reference keyword must
// name a direct $defs entry of its own resource. Such targets are pinned root
// entries or lie in embedded resources, so they never move, and moving the
// reference inside the root resource keeps its meaning. A JSON-pointer
// fragment never selects dynamic scope, so $dynamicRef semantics are kept.
func admitHoistSource(root map[string]any) error {
	if raw, present := root["$defs"]; present {
		if definitions, ok := raw.(map[string]any); !ok || len(definitions) == 0 {
			return fmt.Errorf("schema root $defs must be a nonempty object when present")
		}
	}
	if err := rejectReservedNames(root); err != nil {
		return err
	}
	var admit func(map[string]any, map[string]any) error
	admit = func(resource, schema map[string]any) error {
		for _, keyword := range referenceKeywords {
			if ref, present := schema[keyword]; present {
				if _, err := Resolve(resource, ref); err != nil {
					return fmt.Errorf("%s: %w", keyword, err)
				}
			}
		}
		return eachSubschema(schema, func(_ string, value any, _ func(any)) error {
			child, ok := value.(map[string]any)
			if !ok {
				return nil
			}
			if _, embedded := child["$id"]; embedded {
				return admit(child, child)
			}
			return admit(resource, child)
		})
	}
	return admit(root, root)
}

// The reserved names are refused anywhere, including literal data, so Expand
// cannot confuse a source value with a shared definition.
func rejectReservedNames(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		if ref, ok := typed["$ref"].(string); ok && strings.HasPrefix(ref, referencePrefix+SharedPrefix) {
			return fmt.Errorf("schema source uses the reserved shared definition prefix")
		}
		if definitions, ok := typed["$defs"].(map[string]any); ok {
			for name := range definitions {
				if strings.HasPrefix(name, SharedPrefix) {
					return fmt.Errorf("schema source uses the reserved shared definition prefix")
				}
			}
		}
		for _, member := range typed {
			if err := rejectReservedNames(member); err != nil {
				return err
			}
		}
	case []any:
		for _, member := range typed {
			if err := rejectReservedNames(member); err != nil {
				return err
			}
		}
	}
	return nil
}

// occurrence is one shareable object subschema of the root resource.
type occurrence struct {
	enclosing *occurrence
	replace   func(any)
	node      map[string]any
	length    int
	digest    [sha256.Size]byte
	discarded bool
}

// Positions differ in what may be shared: candidate positions are shareable,
// pinned positions (the root and its direct $defs entries) keep their place but
// their descendants are shareable, and foreign positions lie in an embedded
// resource whose references resolve against that resource.
type position uint8

const (
	candidatePosition position = iota
	pinnedPosition
	foreignPosition
)

type sharer struct {
	groups map[[sha256.Size]byte][]*occurrence
}

// share hoists repeated subschemas largest first. Every occurrence still has
// its source content when its group is considered: a strictly contained
// subtree encodes strictly shorter, so no group processed earlier lies inside
// it. Each applied step strictly shrinks the canonical encoding.
func share(root map[string]any) (map[string]any, error) {
	s := sharer{groups: map[[sha256.Size]byte][]*occurrence{}}
	if _, _, err := s.encodeSchema(root, pinnedPosition, true, nil, nil); err != nil {
		return nil, err
	}
	digests := make([][sha256.Size]byte, 0, len(s.groups))
	for digest := range s.groups {
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(i, j int) bool {
		left, right := s.groups[digests[i]][0].length, s.groups[digests[j]][0].length
		if left != right {
			return left > right
		}
		return bytes.Compare(digests[i][:], digests[j][:]) < 0
	})
	definitions, _ := root["$defs"].(map[string]any)
	names := map[string]struct{}{}
	for _, digest := range digests {
		live := liveOccurrences(s.groups[digest])
		if len(live) < 2 {
			continue
		}
		name := SharedPrefix + hex.EncodeToString(digest[:])[:sharedDigestHexLength]
		// Source names never carry the reserved prefix, so only two shared
		// digests with one name prefix can collide.
		if _, used := names[name]; used {
			return nil, fmt.Errorf("shared schema definition name collision")
		}
		if !sharingSaves(len(live), live[0].length, name, definitions) {
			continue
		}
		if definitions == nil {
			definitions = map[string]any{}
			root["$defs"] = definitions
		}
		names[name] = struct{}{}
		definitions[name] = live[0].node
		for index, occurrence := range live {
			occurrence.replace(map[string]any{"$ref": Reference(name)})
			occurrence.discarded = index > 0
		}
	}
	return root, nil
}

// An occurrence is live unless it lies inside a discarded copy. The first copy
// of a shared group moves into $defs, so its descendants stay live.
func liveOccurrences(group []*occurrence) []*occurrence {
	live := make([]*occurrence, 0, len(group))
	for _, occurrence := range group {
		alive := true
		for enclosing := occurrence.enclosing; enclosing != nil; enclosing = enclosing.enclosing {
			if enclosing.discarded {
				alive = false
				break
			}
		}
		if alive {
			live = append(live, occurrence)
		}
	}
	return live
}

// sharingSaves compares exact canonical compact byte counts: count copies of
// length bytes become count references plus one "name":value entry, plus a
// separating comma or, for the first entry, the new root "$defs" member.
func sharingSaves(count, length int, name string, definitions map[string]any) bool {
	reference := len(`{"$ref":"`) + len(Reference(name)) + len(`"}`)
	entry := len(`"`) + len(name) + len(`":`) + length
	switch {
	case definitions == nil:
		entry += len(`,"$defs":{}`)
	case len(definitions) != 0:
		entry += len(`,`)
	}
	return count*length > count*reference+entry
}

// encodeSchema returns the canonical compact encoding of a schema value and
// whether it contains a scope keyword, registering shareable occurrences.
func (s *sharer) encodeSchema(value any, at position, documentRoot bool, enclosing *occurrence, replace func(any)) ([]byte, bool, error) {
	node, ok := value.(map[string]any)
	if !ok {
		return encodeData(value)
	}
	var current *occurrence
	if at == candidatePosition {
		current = &occurrence{enclosing: enclosing, replace: replace, node: node}
		enclosing = current
	}
	var out bytes.Buffer
	scoped := false
	out.WriteByte('{')
	for index, key := range sortedKeys(node) {
		if index > 0 {
			out.WriteByte(',')
		}
		if err := writeKey(&out, key); err != nil {
			return nil, false, err
		}
		_, scope := scopeKeywords[key]
		scoped = scoped || scope
		member := node[key]
		var encoded []byte
		var memberScoped bool
		var err error
		switch KeywordSubschemaForm(key) {
		case SingleSubschema:
			encoded, memberScoped, err = s.encodeSchema(member, childPosition(at, member), false, enclosing, func(replacement any) { node[key] = replacement })
		case SubschemaList:
			encoded, memberScoped, err = s.encodeSchemaList(member, at, enclosing)
		case SubschemaMap:
			encoded, memberScoped, err = s.encodeSchemaMap(member, entryPosition(at, key, documentRoot), enclosing)
		default:
			encoded, memberScoped, err = encodeData(member)
		}
		if err != nil {
			return nil, false, err
		}
		scoped = scoped || memberScoped
		out.Write(encoded)
	}
	out.WriteByte('}')
	encoded := out.Bytes()
	if current != nil && !scoped {
		current.length = len(encoded)
		current.digest = sha256.Sum256(encoded)
		s.groups[current.digest] = append(s.groups[current.digest], current)
	}
	return encoded, scoped, nil
}

func (s *sharer) encodeSchemaList(value any, parent position, enclosing *occurrence) ([]byte, bool, error) {
	members, ok := value.([]any)
	if !ok {
		return encodeData(value)
	}
	var out bytes.Buffer
	scoped := false
	out.WriteByte('[')
	for index := range members {
		if index > 0 {
			out.WriteByte(',')
		}
		encoded, memberScoped, err := s.encodeSchema(members[index], childPosition(parent, members[index]), false, enclosing, func(replacement any) { members[index] = replacement })
		if err != nil {
			return nil, false, err
		}
		scoped = scoped || memberScoped
		out.Write(encoded)
	}
	out.WriteByte(']')
	return out.Bytes(), scoped, nil
}

// entries is the position of the map's entries before embedded-resource checks.
func (s *sharer) encodeSchemaMap(value any, entries position, enclosing *occurrence) ([]byte, bool, error) {
	members, ok := value.(map[string]any)
	if !ok {
		return encodeData(value)
	}
	var out bytes.Buffer
	scoped := false
	out.WriteByte('{')
	for index, name := range sortedKeys(members) {
		if index > 0 {
			out.WriteByte(',')
		}
		if err := writeKey(&out, name); err != nil {
			return nil, false, err
		}
		encoded, memberScoped, err := s.encodeSchema(members[name], embeddedPosition(entries, members[name]), false, enclosing, func(replacement any) { members[name] = replacement })
		if err != nil {
			return nil, false, err
		}
		scoped = scoped || memberScoped
		out.Write(encoded)
	}
	out.WriteByte('}')
	return out.Bytes(), scoped, nil
}

// childPosition derives a direct subschema position from its parent position.
func childPosition(parent position, child any) position {
	if parent == foreignPosition {
		return foreignPosition
	}
	return embeddedPosition(candidatePosition, child)
}

// The root's own $defs entries are pinned so existing references keep their
// targets; entries of every other subschema map are ordinary candidates.
func entryPosition(parent position, keyword string, documentRoot bool) position {
	switch {
	case parent == foreignPosition:
		return foreignPosition
	case documentRoot && keyword == "$defs":
		return pinnedPosition
	default:
		return candidatePosition
	}
}

// A subschema with $id starts an embedded resource; nothing inside it moves.
func embeddedPosition(at position, child any) position {
	if node, ok := child.(map[string]any); ok {
		if _, embedded := node["$id"]; embedded {
			return foreignPosition
		}
	}
	return at
}

func encodeData(value any) ([]byte, bool, error) {
	switch typed := value.(type) {
	case map[string]any:
		var out bytes.Buffer
		scoped := false
		out.WriteByte('{')
		for index, key := range sortedKeys(typed) {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeKey(&out, key); err != nil {
				return nil, false, err
			}
			_, scope := scopeKeywords[key]
			encoded, memberScoped, err := encodeData(typed[key])
			if err != nil {
				return nil, false, err
			}
			scoped = scoped || scope || memberScoped
			out.Write(encoded)
		}
		out.WriteByte('}')
		return out.Bytes(), scoped, nil
	case []any:
		var out bytes.Buffer
		scoped := false
		out.WriteByte('[')
		for index, member := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			encoded, memberScoped, err := encodeData(member)
			if err != nil {
				return nil, false, err
			}
			scoped = scoped || memberScoped
			out.Write(encoded)
		}
		out.WriteByte(']')
		return out.Bytes(), scoped, nil
	default:
		encoded, err := canonicalJSON(value)
		return encoded, false, err
	}
}

func writeKey(out *bytes.Buffer, key string) error {
	encoded, err := canonicalJSON(key)
	if err != nil {
		return err
	}
	out.Write(encoded)
	out.WriteByte(':')
	return nil
}

// normalize decodes the canonical encoding again, so the transform sees only
// generic JSON values and the equivalence check compares canonical bytes.
func normalize(document map[string]any) (map[string]any, []byte, error) {
	canonical, err := canonicalJSON(document)
	if err != nil {
		return nil, nil, err
	}
	value, err := admission.DecodeJSON(bytes.NewReader(canonical), int64(len(canonical))+1)
	if err != nil {
		return nil, nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("schema document must be an object")
	}
	return root, canonical, nil
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded, []byte{'\n'}), nil
}

func cloneJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, member := range typed {
			result[key] = cloneJSON(member)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, member := range typed {
			result[index] = cloneJSON(member)
		}
		return result
	default:
		return value
	}
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
