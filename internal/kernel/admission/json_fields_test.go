package admission

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type privateJSONFields struct {
	Value string `json:"value"`
}

type privateJSONValue struct {
	privateJSONFields
}

func checkJSONFieldDecode[T any](t *testing.T, input string, want T, reject bool) {
	t.Helper()
	var native T
	if err := json.Unmarshal([]byte(input), &native); err != nil {
		t.Fatalf("stdlib decode: %v", err)
	}
	if !reflect.DeepEqual(native, want) {
		t.Fatalf("stdlib decoded %#v, want %#v", native, want)
	}
	got, err := DecodeTypedJSON[T](strings.NewReader(input), int64(len(input)))
	if reject {
		if err == nil || !strings.Contains(err.Error(), "exact declared field") {
			t.Fatalf("admission error = %v, want exact-case rejection; stdlib populated %#v", err, native)
		}
		return
	}
	if err != nil || !reflect.DeepEqual(got, native) {
		t.Fatalf("admission decoded %#v, error = %v; stdlib decoded %#v", got, err, native)
	}
}

func TestJSONFieldsPrivateValuePromotion(t *testing.T) {
	want := privateJSONValue{privateJSONFields{Value: "set"}}
	t.Run("canonical", func(t *testing.T) {
		checkJSONFieldDecode(t, `{"value":"set"}`, want, false)
	})
	t.Run("wrong-case", func(t *testing.T) {
		checkJSONFieldDecode(t, `{"VALUE":"set"}`, want, true)
	})
}

func TestJSONFieldsIntegerMapValues(t *testing.T) {
	type record struct {
		Value string `json:"value"`
	}
	want := map[int]record{1: {Value: "x"}}
	t.Run("canonical", func(t *testing.T) {
		checkJSONFieldDecode(t, `{"1":{"value":"x","extension":true}}`, want, false)
	})
	t.Run("wrong-case", func(t *testing.T) {
		checkJSONFieldDecode(t, `{"1":{"VALUE":"x"}}`, want, true)
	})
}

func TestJSONFieldsIntegerMapKeyConversionErrors(t *testing.T) {
	type record struct {
		Value string `json:"value"`
	}
	for _, key := range []string{"not-an-int", "99999999999999999999999999999999"} {
		t.Run(key, func(t *testing.T) {
			input := `{"` + key + `":{"value":"x"}}`
			var native map[int]record
			nativeErr := json.Unmarshal([]byte(input), &native)
			_, admittedErr := DecodeTypedJSON[map[int]record](strings.NewReader(input), int64(len(input)))
			var nativeKeyErr, admittedKeyErr *json.UnmarshalTypeError
			if !errors.As(nativeErr, &nativeKeyErr) || !errors.As(admittedErr, &admittedKeyErr) {
				t.Fatalf("key conversion errors: stdlib = %v; admission = %v", nativeErr, admittedErr)
			}
			if nativeKeyErr.Type != reflect.TypeOf(int(0)) || admittedKeyErr.Type != nativeKeyErr.Type ||
				admittedKeyErr.Value != nativeKeyErr.Value {
				t.Fatalf("key conversion error changed: stdlib = %#v; admission = %#v", nativeKeyErr, admittedKeyErr)
			}
		})
	}
}

func TestJSONFieldsCaseFoldedDiagnosticsDeterministic(t *testing.T) {
	type record struct {
		First  string `json:"aA"`
		Second string `json:"Aa"`
	}
	checkJSONFieldDecode(t, `{"aA":"first","Aa":"second"}`, record{First: "first", Second: "second"}, false)
	checkJSONFieldDecode(t, `{"aA":"first","extension":true}`, record{First: "first"}, false)
	checkJSONFieldDecode(t, `{"Aa":"second"}`, record{Second: "second"}, false)
	checkJSONFieldDecode(t, `{"AA":"set"}`, record{First: "set"}, true)

	const input = `{"AA":"set"}`
	const want = `invalid JSON input: object key must use exact declared field "Aa"`
	diagnostics := map[string]int{}
	for range 256 {
		_, err := DecodeTypedJSON[record](strings.NewReader(input), int64(len(input)))
		if err == nil {
			t.Fatal("wrong-case key was accepted")
		}
		diagnostics[err.Error()]++
	}
	if len(diagnostics) != 1 || diagnostics[want] != 256 {
		t.Fatalf("diagnostics = %v, want only %q", diagnostics, want)
	}
}

func TestJSONFieldsPrivatePointerPromotion(t *testing.T) {
	type record struct{ *privateJSONFields }
	for _, key := range []string{"value", "VALUE"} {
		t.Run(key, func(t *testing.T) {
			input := `{"` + key + `":"set"}`
			// The stdlib can populate an existing private pointer, but cannot
			// allocate one. Field discovery must not depend on pointer state.
			native := record{&privateJSONFields{}}
			if err := json.Unmarshal([]byte(input), &native); err != nil || native.Value != "set" {
				t.Fatalf("initialized stdlib pointer = %#v, error = %v", native, err)
			}
			var value any
			if err := json.Unmarshal([]byte(input), &value); err != nil {
				t.Fatal(err)
			}
			guardErr := rejectCaseFoldedTypedKeys(value, reflect.TypeOf(native))
			_, typedErr := DecodeTypedJSON[record](strings.NewReader(input), int64(len(input)))
			if key == "VALUE" {
				for _, err := range []error{guardErr, typedErr} {
					if err == nil || !strings.Contains(err.Error(), "exact declared field") {
						t.Fatalf("wrong-case error = %v, want exact-case rejection", err)
					}
				}
				return
			}
			if guardErr != nil {
				t.Fatalf("canonical guard error = %v", guardErr)
			}
			var zero record
			nativeErr := json.Unmarshal([]byte(input), &zero)
			if nativeErr == nil || !strings.Contains(nativeErr.Error(), "cannot set embedded pointer") ||
				typedErr == nil || !strings.Contains(typedErr.Error(), nativeErr.Error()) {
				t.Fatalf("nil pointer errors: stdlib = %v; admission = %v", nativeErr, typedErr)
			}
		})
	}
}

type privateJSONScalar string

func TestJSONFieldsIgnoredAndExtensionKeys(t *testing.T) {
	type record struct {
		privateJSONScalar `json:"hidden"`
		private           string `json:"private"`
		Ignored           string `json:"-"`
		privateJSONFields
	}
	checkJSONFieldDecode(t, `{"HIDDEN":"x","PRIVATE":"x","IGNORED":"x","extension":{"VALUE":1},"value":"set"}`,
		record{privateJSONFields: privateJSONFields{Value: "set"}}, false)
}

type jsonLeftPayload struct {
	Left string `json:"left"`
}

type jsonRightPayload struct {
	Right string `json:"right"`
}

type jsonLeftFields struct{ Value jsonLeftPayload }
type jsonRightFields struct{ Value jsonRightPayload }
type jsonTaggedFields struct {
	Picked jsonRightPayload `json:"Value"`
}
type jsonOtherTaggedFields struct {
	Other jsonLeftPayload `json:"Value"`
}

func TestJSONFieldsSiblingAmbiguity(t *testing.T) {
	type plain struct {
		jsonLeftFields
		jsonRightFields
	}
	type tagged struct {
		jsonTaggedFields
		jsonOtherTaggedFields
	}
	for _, input := range []string{`{"Value":{"LEFT":"set"}}`, `{"VALUE":{"RIGHT":"set"}}`} {
		checkJSONFieldDecode(t, input, plain{}, false)
		checkJSONFieldDecode(t, input, tagged{}, false)
	}
}

func TestJSONFieldsShallowerDominance(t *testing.T) {
	type record struct {
		Value jsonLeftPayload
		jsonTaggedFields
	}
	want := record{Value: jsonLeftPayload{Left: "set"}}
	checkJSONFieldDecode(t, `{"Value":{"left":"set","RIGHT":"extension"}}`, want, false)
	checkJSONFieldDecode(t, `{"VALUE":{"left":"set"}}`, want, true)
	checkJSONFieldDecode(t, `{"Value":{"LEFT":"set"}}`, want, true)

	type reverse struct {
		jsonTaggedFields
		Value jsonLeftPayload
	}
	checkJSONFieldDecode(t, `{"Value":{"left":"set","RIGHT":"extension"}}`, reverse{Value: want.Value}, false)
}

func TestJSONFieldsTaggedDominance(t *testing.T) {
	type record struct {
		jsonTaggedFields
		jsonLeftFields
	}
	want := record{jsonTaggedFields: jsonTaggedFields{Picked: jsonRightPayload{Right: "set"}}}
	checkJSONFieldDecode(t, `{"Value":{"right":"set","LEFT":"extension"}}`, want, false)
	checkJSONFieldDecode(t, `{"VALUE":{"right":"set"}}`, want, true)
	checkJSONFieldDecode(t, `{"Value":{"RIGHT":"set"}}`, want, true)

	type reverse struct {
		jsonLeftFields
		jsonTaggedFields
	}
	checkJSONFieldDecode(t, `{"Value":{"right":"set","LEFT":"extension"}}`, reverse{jsonTaggedFields: want.jsonTaggedFields}, false)

	type overAmbiguity struct {
		jsonLeftFields
		jsonRightFields
		jsonTaggedFields
	}
	checkJSONFieldDecode(t, `{"Value":{"right":"set"}}`, overAmbiguity{jsonTaggedFields: want.jsonTaggedFields}, false)
}

func TestJSONFieldsTagNamesOverrideGoAmbiguity(t *testing.T) {
	type left struct {
		Value string `json:"left"`
	}
	type right struct {
		Value string `json:"right"`
	}
	type record struct {
		left
		right
	}
	want := record{left{Value: "a"}, right{Value: "b"}}
	checkJSONFieldDecode(t, `{"left":"a","right":"b"}`, want, false)
	checkJSONFieldDecode(t, `{"LEFT":"a","right":"b"}`, want, true)
	checkJSONFieldDecode(t, `{"left":"a","RIGHT":"b"}`, want, true)
}

func TestJSONFieldsRepeatedEmbedding(t *testing.T) {
	type left struct{ privateJSONFields }
	type right struct{ privateJSONFields }
	type diamond struct {
		left
		right
	}
	checkJSONFieldDecode(t, `{"value":"ignored","VALUE":"ignored"}`, diamond{}, false)

	type otherFields struct {
		Other string `json:"value"`
	}
	type middle struct{ otherFields }
	type deeper struct{ middle }
	type shallowAmbiguity struct {
		left
		right
		deeper
	}
	checkJSONFieldDecode(t, `{"value":"ignored","VALUE":"ignored"}`, shallowAmbiguity{}, false)
}

type JSONRecursiveFields struct {
	*JSONRecursiveFields
	Value string `json:"value"`
}

type JSONMutualFieldsA struct {
	*JSONMutualFieldsB
	Value string `json:"value"`
}

type JSONMutualFieldsB struct {
	*JSONMutualFieldsA
	Note string `json:"note"`
}

func TestJSONFieldsRecursiveEmbeddings(t *testing.T) {
	checkJSONFieldDecode(t, `{}`, JSONRecursiveFields{}, false)
	checkJSONFieldDecode(t, `{"value":"set"}`, JSONRecursiveFields{Value: "set"}, false)
	checkJSONFieldDecode(t, `{"VALUE":"set"}`, JSONRecursiveFields{Value: "set"}, true)
	want := JSONMutualFieldsA{JSONMutualFieldsB: &JSONMutualFieldsB{Note: "b"}, Value: "a"}
	checkJSONFieldDecode(t, `{"value":"a","note":"b"}`, want, false)
	checkJSONFieldDecode(t, `{"VALUE":"a","note":"b"}`, want, true)
	checkJSONFieldDecode(t, `{"value":"a","NOTE":"b"}`, want, true)
}

func TestJSONFieldsTaggedEmbedding(t *testing.T) {
	type named struct {
		privateJSONFields `json:"payload"`
	}
	want := named{privateJSONFields{Value: "set"}}
	checkJSONFieldDecode(t, `{"payload":{"value":"set"},"VALUE":"extension"}`, want, false)
	checkJSONFieldDecode(t, `{"PAYLOAD":{"value":"set"}}`, want, true)
	checkJSONFieldDecode(t, `{"payload":{"VALUE":"set"}}`, want, true)

	type dashName struct {
		Value   string `json:"-,omitempty"`
		Ignored string `json:"-"`
	}
	checkJSONFieldDecode(t, `{"-":"set","Ignored":"ignored","IGNORED":"ignored"}`, dashName{Value: "set"}, false)
}

func checkUnsupportedJSONTarget[T any](t *testing.T, input string) {
	t.Helper()
	const want = "invalid JSON target schema: unsupported field tag name"
	_, err := DecodeTypedJSON[T](strings.NewReader(input), int64(len(input)))
	if err == nil || err.Error() != want {
		t.Fatalf("schema error = %v, want sanitized %q", err, want)
	}
}

func TestJSONFieldsUnsupportedTagDeclarations(t *testing.T) {
	type leading struct {
		Value string `json:"\\private-marker"`
	}
	type prefix struct {
		Value string `json:"private-marker\\name"`
	}
	type quoted struct {
		Value string `json:"'private-marker'"`
	}
	type doubleQuoted struct {
		Value string `json:"\"private-marker\""`
	}
	type backtick struct {
		Value string `json:"\x60private-marker"`
	}
	for _, input := range []string{`{}`, `{"Value":"set"}`, `{"VALUE":"set"}`, `{"extension":true}`} {
		t.Run(input, func(t *testing.T) {
			// This object needs a field table even if none of its keys match.
			// Unsupported names are not interpreted as a partial tag grammar.
			checkUnsupportedJSONTarget[leading](t, input)
			checkUnsupportedJSONTarget[prefix](t, input)
			checkUnsupportedJSONTarget[quoted](t, input)
			checkUnsupportedJSONTarget[doubleQuoted](t, input)
			checkUnsupportedJSONTarget[backtick](t, input)
		})
	}
	checkJSONFieldDecode(t, `null`, leading{}, false)
	checkJSONFieldDecode(t, `null`, prefix{}, false)
	checkJSONFieldDecode(t, `null`, quoted{}, false)
	checkJSONFieldDecode(t, `null`, doubleQuoted{}, false)
	checkJSONFieldDecode(t, `null`, backtick{}, false)
	type embedded struct {
		privateJSONFields `json:"\\private-marker"`
	}
	checkUnsupportedJSONTarget[embedded](t, `{}`)
	type nested struct {
		Child *leading `json:"child"`
		Next  *nested  `json:"next"`
	}
	checkJSONFieldDecode(t, `{}`, nested{}, false)
	checkJSONFieldDecode(t, `{"child":null}`, nested{}, false)
	checkJSONFieldDecode(t, `[]`, []leading{}, false)
	checkJSONFieldDecode(t, `[]`, [0]leading{}, false)
	checkJSONFieldDecode(t, `{}`, map[string]leading{}, false)
	checkJSONFieldDecode(t, `[null]`, []*leading{nil}, false)
	checkJSONFieldDecode(t, `{"x":null}`, map[string]*leading{"x": nil}, false)
	checkUnsupportedJSONTarget[nested](t, `{"child":{}}`)
	checkUnsupportedJSONTarget[[]leading](t, `[{}]`)
	checkUnsupportedJSONTarget[[1]leading](t, `[{}]`)
	checkUnsupportedJSONTarget[map[string]leading](t, `{"x":{}}`)
}

func TestJSONFieldsOrdinaryTagNamesAndOptions(t *testing.T) {
	type record struct {
		Unicode     string `json:"caf\u00e9,omitempty"`
		Punctuation string `json:"name.!#$%&()*+-/:;<=>?@[]^_{|}~ "`
		Number      int    `json:"number,string"`
		Default     string `json:",omitempty"`
		Zero        string `json:"zero,omitzero"`
	}
	want := record{Unicode: "u", Punctuation: "p", Number: 7, Default: "d"}
	checkJSONFieldDecode(t, `{"caf\u00e9":"u","name.!#$%&()*+-/:;<=>?@[]^_{|}~ ":"p","number":"7","Default":"d"}`, want, false)
	checkJSONFieldDecode(t, `{"CAF\u00c9":"u","name.!#$%&()*+-/:;<=>?@[]^_{|}~ ":"p","number":"7","Default":"d"}`, want, true)
}

type jsonOpaqueFields struct {
	Value string `json:"value"`
	Raw   string
}

func (value *jsonOpaqueFields) UnmarshalJSON(source []byte) error {
	value.Raw = string(source)
	return nil
}

func TestJSONFieldsOpaqueUnmarshalerBoundaries(t *testing.T) {
	input := `{"VALUE":"owned by unmarshaler"}`
	want := jsonOpaqueFields{Raw: input}
	checkJSONFieldDecode(t, input, want, false)
	type embedded struct{ jsonOpaqueFields }
	checkJSONFieldDecode(t, input, embedded{want}, false)
	type record struct {
		Payload jsonOpaqueFields `json:"payload"`
	}
	checkJSONFieldDecode(t, `{"payload":`+input+`}`, record{want}, false)
	checkJSONFieldDecode(t, `{"PAYLOAD":`+input+`}`, record{want}, true)
}

func TestJSONFieldsUnsupportedTagsRespectIgnoredAndOpaqueBoundaries(t *testing.T) {
	type ignored struct {
		private string `json:"\\private-marker"`
		Hidden  struct {
			Value string `json:"\\private-marker"`
		} `json:"-"`
		privateJSONScalar `json:"\\private-marker"`
	}
	checkJSONFieldDecode(t, `{"extension":true}`, ignored{}, false)

	type opaque struct {
		jsonOpaqueFields
		Invalid string `json:"\\private-marker"`
	}
	input := `{"VALUE":"owned by unmarshaler"}`
	want := opaque{jsonOpaqueFields: jsonOpaqueFields{Raw: input}}
	checkJSONFieldDecode(t, input, want, false)
	type record struct {
		Payload *opaque `json:"payload"`
	}
	checkJSONFieldDecode(t, `{"payload":`+input+`}`, record{Payload: &want}, false)
	checkJSONFieldDecode(t, `{}`, record{}, false)
}
