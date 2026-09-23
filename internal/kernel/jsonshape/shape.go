// Package jsonshape shares a bounded structural declaration between native
// admission and JSON Schema projection. It does not load or interpret schemas.
package jsonshape

import (
	"slices"
)

type kind uint8

const (
	objectKind kind = iota + 1
	arrayKind
	stringKind
	numberKind
	integerLiteralKind
	integerMinimumKind
	tupleKind
	booleanKind
	stringLiteralKind
	decimalIntegerKind
	stringMapKind
	oneOfKind
	nullKind
)

// Shape is immutable. Constructors copy supplied slices and maps.
type Shape struct{ node *node }

type node struct {
	kind          kind
	nullable      bool
	properties    []Property
	allowed       map[string]struct{}
	exactlyOne    []string
	element       Shape
	minItems      int
	maxItems      int
	enum          []string
	integer       int64
	tuple         []Shape
	text          string
	boolean       *bool
	alternatives  []Shape
	discriminator string
	branches      map[string]Shape
}

type Property struct {
	name     string
	shape    Shape
	optional bool
}

func Required(name string, shape Shape) Property {
	return Property{name: name, shape: shape}
}

func Optional(name string, shape Shape) Property {
	return Property{name: name, shape: shape, optional: true}
}

// Object declares a closed object. Invalid declarations are programmer errors;
// no caller input is admitted through constructors.
func Object(properties ...Property) Shape {
	fields := slices.Clone(properties)
	slices.SortFunc(fields, func(a, b Property) int {
		if a.name < b.name {
			return -1
		}
		if a.name > b.name {
			return 1
		}
		return 0
	})
	for i, field := range fields {
		if field.name == "" || field.shape.node == nil || (i > 0 && fields[i-1].name == field.name) {
			panic("invalid JSON object shape declaration")
		}
	}
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field.name] = struct{}{}
	}
	return Shape{node: &node{kind: objectKind, properties: fields, allowed: allowed}}
}

func String() Shape { return Shape{node: &node{kind: stringKind}} }

func Boolean() Shape { return Shape{node: &node{kind: booleanKind}} }

func Null() Shape { return Shape{node: &node{kind: nullKind}} }

func BooleanLiteral(value bool) Shape { return Shape{node: &node{kind: booleanKind, boolean: &value}} }

func OneOf(alternatives ...Shape) Shape {
	if len(alternatives) < 2 {
		panic("JSON sum requires at least two alternatives")
	}
	items := slices.Clone(alternatives)
	for _, item := range items {
		if item.node == nil {
			panic("invalid JSON sum alternative")
		}
	}
	return Shape{node: &node{kind: oneOfKind, alternatives: items}}
}

// DiscriminatedUnion is an exclusive sum of closed objects whose required
// literal tags are disjoint. The same alternatives own native and schema rules.
func DiscriminatedUnion(key string, alternatives ...Shape) Shape {
	shape := OneOf(alternatives...)
	if key == "" {
		panic("JSON discriminator must name a property")
	}
	branches := make(map[string]Shape, len(alternatives))
	for _, alternative := range alternatives {
		if alternative.node.kind != objectKind || alternative.node.nullable {
			panic("JSON tagged alternatives must be non-null objects")
		}
		found := false
		for _, property := range alternative.node.properties {
			if property.name != key {
				continue
			}
			tag := property.shape.node
			if property.optional || tag.nullable || tag.kind != stringLiteralKind {
				panic("JSON discriminator must be a required non-null string literal")
			}
			if _, duplicate := branches[tag.text]; duplicate {
				panic("JSON discriminator literals must be unique")
			}
			branches[tag.text], found = alternative, true
		}
		if !found {
			panic("JSON alternative has no discriminator")
		}
	}
	shape.node.discriminator, shape.node.branches = key, branches
	return shape
}

// NonNullable removes the explicit Nullable wrapper, not null alternatives
// inside a OneOf. A null-only declaration cannot have this wrapper removed.
func NonNullable(shape Shape) Shape {
	if shape.node == nil || shape.node.kind == nullKind {
		panic("invalid non-null JSON shape declaration")
	}
	copy := *shape.node
	copy.nullable = false
	return Shape{node: &copy}
}

func StringLiteral(value string) Shape {
	return Shape{node: &node{kind: stringLiteralKind, text: value}}
}

// DecimalIntegerString preserves a canonical signed int64 as JSON text.
func DecimalIntegerString() Shape { return Shape{node: &node{kind: decimalIntegerKind}} }

func StringMap(maxProperties int) Shape {
	if maxProperties < 0 {
		panic("invalid JSON map shape declaration")
	}
	return Shape{node: &node{kind: stringMapKind, maxItems: maxProperties}}
}

// Number preserves the decoded json.Number token. Framing, range and integer
// spelling belong to the decoder and native numeric owner, not this shape.
func Number() Shape { return Shape{node: &node{kind: numberKind}} }

func Enum(values map[string]struct{}) Shape {
	if len(values) == 0 {
		panic("empty JSON enum shape declaration")
	}
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	slices.Sort(items)
	return Shape{node: &node{kind: stringKind, enum: items}}
}

// IntegerLiteral requires canonical JSON int64 spelling as well as value.
// Standard JSON Schema's mathematical integer semantics alone do not prove it.
func IntegerLiteral(value int64) Shape {
	return Shape{node: &node{kind: integerLiteralKind, integer: value}}
}

// IntegerMinimum requires canonical int64 spelling, not a floating-point token.
func IntegerMinimum(minimum int64) Shape {
	return Shape{node: &node{kind: integerMinimumKind, integer: minimum}}
}

// Tuple owns an exact ordered array, including the empty tuple.
func Tuple(elements ...Shape) Shape {
	items := slices.Clone(elements)
	for _, item := range items {
		if item.node == nil {
			panic("invalid JSON tuple shape declaration")
		}
	}
	return Shape{node: &node{kind: tupleKind, tuple: items}}
}

func Array(element Shape, minItems int) Shape {
	if element.node == nil || minItems < 0 {
		panic("invalid JSON array shape declaration")
	}
	return Shape{node: &node{kind: arrayKind, element: element, minItems: minItems, maxItems: -1}}
}

func BoundedArray(element Shape, minItems, maxItems int) Shape {
	shape := Array(element, minItems)
	if maxItems < minItems {
		panic("invalid JSON array shape bounds")
	}
	shape.node.maxItems = maxItems
	return shape
}

// Property and Element expose immutable child declarations for owner-defined
// projections. Absence is explicit, not an unconstrained fallback shape.
func (shape Shape) Property(name string) (Shape, bool) {
	if shape.node != nil && shape.node.kind == objectKind {
		for _, field := range shape.node.properties {
			if field.name == name {
				return field.shape, true
			}
		}
	}
	return Shape{}, false
}

func (shape Shape) Element() (Shape, bool) {
	if shape.node != nil && shape.node.kind == arrayKind {
		return shape.node.element, true
	}
	return Shape{}, false
}

func Nullable(shape Shape) Shape {
	if shape.node == nil {
		panic("invalid nullable JSON shape declaration")
	}
	copy := *shape.node
	copy.nullable = true
	return Shape{node: &copy}
}

// ExactlyOne selects by key presence, including keys whose values are null.
func ExactlyOne(object Shape, names ...string) Shape {
	if object.node == nil || object.node.kind != objectKind || len(object.node.exactlyOne) != 0 || len(names) < 2 {
		panic("invalid exactly-one JSON shape declaration")
	}
	keys := slices.Clone(names)
	slices.Sort(keys)
	for i, name := range keys {
		if i > 0 && keys[i-1] == name {
			panic("duplicate exactly-one JSON shape key")
		}
		found := false
		for _, field := range object.node.properties {
			if field.name == name && field.optional {
				found = true
			}
		}
		if !found {
			panic("exactly-one JSON shape key must name an optional property")
		}
	}
	copy := *object.node
	copy.exactlyOne = keys
	return Shape{node: &copy}
}
