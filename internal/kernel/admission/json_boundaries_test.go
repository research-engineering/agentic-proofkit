package admission

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

type jsonSelfPointer *jsonSelfPointer
type jsonMutualPointerA *jsonMutualPointerB
type jsonMutualPointerB *jsonMutualPointerA

func TestJSONFieldsPointerCycles(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the built test executable; deadlines cover decoding, not building.
	for _, kind := range []string{"self", "mutual"} {
		for _, mode := range []string{"ignored", "private", "absent", "null", "empty", "non-null", "ordinary"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestJSONFieldsPointerCycleChild$", "-test.count=1")
				cmd.Env = append(os.Environ(), "PROOFKIT_JSON_CYCLE="+kind+"/"+mode)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("bounded child: %v (deadline: %v)\n%s", err, ctx.Err(), output)
				}
			})
		}
	}
}

func TestJSONFieldsPointerCycleChild(t *testing.T) {
	kind, mode, found := strings.Cut(os.Getenv("PROOFKIT_JSON_CYCLE"), "/")
	if !found {
		t.Skip("subprocess only")
	}
	switch kind {
	case "self":
		target := reflect.TypeFor[jsonSelfPointer]()
		if target.Kind() != reflect.Pointer || target.Elem() != target {
			t.Fatal("self-cycle witness is not a pointer fixed point")
		}
		checkJSONPointerBoundary[jsonSelfPointer](t, mode)
	case "mutual":
		target := reflect.TypeFor[jsonMutualPointerA]()
		if target.Elem() == target || target.Elem().Elem() != target {
			t.Fatal("mutual-cycle witness does not return to its starting type")
		}
		checkJSONPointerBoundary[jsonMutualPointerA](t, mode)
	default:
		t.Fatal("unknown pointer witness")
	}
}

func checkJSONPointerBoundary[T any](t *testing.T, mode string) {
	t.Helper()
	type record struct {
		Next  T      `json:"next"`
		Value string `json:"value"`
	}
	switch mode {
	case "ignored":
		type ignored struct {
			Hidden T      `json:"-"`
			Value  string `json:"value"`
		}
		checkJSONFieldDecode(t, `{"Hidden":{},"HIDDEN":{},"value":"ok"}`, ignored{Value: "ok"}, false)
	case "private":
		type private struct {
			hidden T
			Value  string `json:"value"`
		}
		checkJSONFieldDecode(t, `{"hidden":{},"HIDDEN":{},"value":"ok"}`, private{Value: "ok"}, false)
	case "absent":
		checkJSONFieldDecode(t, `{"value":"ok"}`, record{Value: "ok"}, false)
	case "null":
		var zero T
		checkJSONFieldDecode(t, `null`, zero, false)
		checkJSONFieldDecode(t, `{"next":null,"value":"ok"}`, record{Value: "ok"}, false)
	case "empty":
		checkJSONFieldDecode(t, `[]`, []T{}, false)
		checkJSONFieldDecode(t, `[]`, [0]T{}, false)
		checkJSONFieldDecode(t, `{}`, map[string]T{}, false)
	case "non-null":
		// Native null is the preservation control. Native non-null pointer
		// cycles are not a termination oracle; admission rejects that schema.
		var zero T
		checkJSONFieldDecode(t, `null`, zero, false)
		for _, input := range []string{`{}`, `[]`, `0`, `"value"`} {
			const want = "invalid JSON target schema: unsupported pointer cycle"
			_, err := DecodeTypedJSON[T](strings.NewReader(input), int64(len(input)))
			if err == nil || err.Error() != want {
				t.Fatalf("root cycle: %v, want %q", err, want)
			}
			nested := `{"next":` + input + `}`
			_, err = DecodeTypedJSON[record](strings.NewReader(nested), int64(len(nested)))
			if err == nil || err.Error() != want {
				t.Fatalf("nested cycle: %v, want %q", err, want)
			}
		}
	case "ordinary":
		type payload struct {
			Value string `json:"value"`
		}
		one := &payload{Value: "ok"}
		two := &one
		checkJSONFieldDecode(t, `{"value":"ok"}`, &two, false)
		checkJSONFieldDecode(t, `{"VALUE":"ok"}`, &two, true)
	default:
		t.Fatal("unknown boundary mode")
	}
}

type jsonFromFields struct {
	Invalid string `json:"\\reserved"`
	Raw     string
}

func (value *jsonFromFields) UnmarshalJSONFrom(decoder *jsontext.Decoder) error {
	raw, err := decoder.ReadValue()
	value.Raw = string(raw)
	return err
}

type jsonTextFields struct {
	Invalid string `json:"\\reserved"`
	Raw     string
}

func (value *jsonTextFields) UnmarshalText(source []byte) error {
	value.Raw = string(source)
	return nil
}

type jsonTextObject struct {
	Value string `json:"value"`
}

func (value *jsonTextObject) UnmarshalText(source []byte) error {
	value.Value = string(source)
	return nil
}

func TestJSONFieldsJSONFromOpacity(t *testing.T) {
	for _, input := range []string{`{"VALUE":"owned"}`, `"owned"`, `7`, `[]`, `null`} {
		want := jsonFromFields{Raw: input}
		checkJSONFieldDecode(t, input, want, false)
		type promoted struct{ jsonFromFields }
		checkJSONFieldDecode(t, input, promoted{want}, false)
		type nested struct {
			Payload jsonFromFields `json:"payload"`
		}
		checkJSONFieldDecode(t, `{"payload":`+input+`}`, nested{want}, false)
		checkJSONFieldDecode(t, `{"PAYLOAD":`+input+`}`, nested{want}, true)
	}
	const input = `{"VALUE":"owned"}`
	want := jsonFromFields{Raw: input}
	checkJSONFieldDecode(t, input, &want, false)
	checkJSONFieldDecode(t, `[`+input+`]`, []jsonFromFields{want}, false)
	checkJSONFieldDecode(t, `{"x":`+input+`}`, map[string]jsonFromFields{"x": want}, false)
}

func TestJSONFieldsTextStringAndObjectBoundaries(t *testing.T) {
	want := jsonTextFields{Raw: "owned"}
	checkJSONFieldDecode(t, `"owned"`, want, false)
	checkJSONFieldDecode(t, `"owned"`, &want, false)
	type nested struct {
		Payload jsonTextFields `json:"payload"`
	}
	checkJSONFieldDecode(t, `{"payload":"owned"}`, nested{want}, false)
	checkJSONFieldDecode(t, `{"PAYLOAD":"owned"}`, nested{want}, true)
	checkJSONFieldDecode(t, `["owned"]`, []jsonTextFields{want}, false)
	checkJSONFieldDecode(t, `{"x":"owned"}`, map[string]jsonTextFields{"x": want}, false)
	checkUnsupportedJSONTarget[jsonTextFields](t, `{}`)
	for _, input := range []string{`{"value":"x"}`, `{"VALUE":"x"}`} {
		var native jsonTextObject
		nativeErr := json.Unmarshal([]byte(input), &native)
		var nativeTypeErr *json.UnmarshalTypeError
		if !errors.As(nativeErr, &nativeTypeErr) {
			t.Fatalf("native Text-only object control: %v", nativeErr)
		}
		_, err := DecodeTypedJSON[jsonTextObject](strings.NewReader(input), int64(len(input)))
		if strings.Contains(input, "VALUE") {
			if err == nil || !strings.Contains(err.Error(), "exact declared field") {
				t.Fatalf("Text-only object must retain exact-key checking: %v", err)
			}
		} else {
			var admittedTypeErr *json.UnmarshalTypeError
			if !errors.As(err, &admittedTypeErr) || admittedTypeErr.Type != nativeTypeErr.Type || admittedTypeErr.Value != nativeTypeErr.Value {
				t.Fatalf("canonical Text object: native = %v, admission = %v", nativeErr, err)
			}
		}
	}
}

func TestJSONFieldsOpaqueValuesStillValidateSyntax(t *testing.T) {
	for _, input := range []string{`{"a":1,"a":2}`, `{"x":}`, `{} {}`, `"\ud800"`} {
		t.Run(input, func(t *testing.T) {
			from, err := DecodeTypedJSON[jsonFromFields](strings.NewReader(input), int64(len(input)))
			if err == nil || from.Raw != "" {
				t.Fatalf("JSONFrom invoked before syntax admission: %#v, %v", from, err)
			}
			text, err := DecodeTypedJSON[jsonTextFields](strings.NewReader(input), int64(len(input)))
			if err == nil || text.Raw != "" {
				t.Fatalf("Text invoked before syntax admission: %#v, %v", text, err)
			}
		})
	}
}

func TestJSONFieldsUnsupportedOptions(t *testing.T) {
	type payload struct {
		Value string `json:"value"`
	}
	type embedded struct {
		Payload payload `json:",embed"`
	}
	var native embedded
	if err := json.Unmarshal([]byte(`{"VALUE":"set"}`), &native); err != nil || native.Payload.Value != "set" {
		t.Fatalf("native explicit embed control: %#v, %v", native, err)
	}
	for _, input := range []string{`{}`, `{"value":"set"}`, `{"VALUE":"set"}`, `{"PAYLOAD":{}}`} {
		_, err := DecodeTypedJSON[embedded](strings.NewReader(input), int64(len(input)))
		if err == nil || err.Error() != "invalid JSON target schema: unsupported field tag option" {
			t.Fatalf("embed schema error: %v", err)
		}
	}
	type nested struct {
		Child *embedded `json:"child"`
	}
	checkJSONFieldDecode(t, `{}`, nested{}, false)
	checkJSONFieldDecode(t, `{"child":null}`, nested{}, false)
	checkJSONFieldDecode(t, `null`, embedded{}, false)
	checkJSONFieldDecode(t, `[]`, []embedded{}, false)
	checkJSONFieldDecode(t, `{}`, map[string]embedded{}, false)
	for _, option := range []string{"embed", "inline", "unknown", "case:ignore", "case:strict", "format:emitnull", "future", "'omitempty'", ""} {
		t.Run(option, func(t *testing.T) {
			target := reflect.StructOf([]reflect.StructField{{Name: "Value", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"value,` + option + `"`)}})
			err := rejectCaseFoldedTypedKeys(map[string]any{}, target)
			if err == nil || err.Error() != "invalid JSON target schema: unsupported field tag option" {
				t.Fatalf("unsupported option error: %v", err)
			}
		})
	}
}

type jsonPrivatePayload struct {
	Value string `json:"value"`
}

type jsonPrivateMarshal jsonPrivatePayload
type jsonPrivateMarshalTo jsonPrivatePayload
type jsonPrivateUnmarshal jsonPrivatePayload
type jsonPrivateFrom jsonPrivatePayload
type jsonPrivateTextMarshal jsonPrivatePayload
type jsonPrivateTextAppend jsonPrivatePayload
type jsonPrivateTextUnmarshal jsonPrivatePayload
type jsonPrivateZero jsonPrivatePayload

func (jsonPrivateMarshal) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (*jsonPrivateMarshalTo) MarshalJSONTo(encoder *jsontext.Encoder) error {
	return encoder.WriteValue(jsontext.Value(`{}`))
}
func (*jsonPrivateUnmarshal) UnmarshalJSON([]byte) error {
	return errors.New("inaccessible JSON method called")
}
func (*jsonPrivateFrom) UnmarshalJSONFrom(*jsontext.Decoder) error {
	return errors.New("inaccessible JSONFrom method called")
}
func (jsonPrivateTextMarshal) MarshalText() ([]byte, error) { return []byte("text"), nil }
func (*jsonPrivateTextAppend) AppendText(dst []byte) ([]byte, error) {
	return append(dst, "text"...), nil
}
func (*jsonPrivateTextUnmarshal) UnmarshalText([]byte) error {
	return errors.New("inaccessible Text method called")
}
func (*jsonPrivateZero) IsZero() bool { return false }

func checkJSONPrivateMethodField[T any](t *testing.T, want T) {
	t.Helper()
	for _, input := range []string{
		`{"payload":{"value":"ignored"},"public":"set"}`,
		`{"PAYLOAD":{"value":"ignored"},"public":"set"}`,
		`{"payload":{"VALUE":"ignored"},"public":"set"}`,
	} {
		checkJSONFieldDecode(t, input, want, false)
	}
}

func TestJSONFieldsPrivateTaggedMethods(t *testing.T) {
	t.Run("MarshalJSON", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateMarshal `json:"payload"`
			Public             string `json:"public"`
		}{Public: "set"})
	})
	t.Run("pointer-MarshalJSON", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			*jsonPrivateMarshal `json:"payload"`
			Public              string `json:"public"`
		}{Public: "set"})
	})
	t.Run("MarshalJSONTo", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateMarshalTo `json:"payload"`
			Public               string `json:"public"`
		}{Public: "set"})
	})
	// Shadow promoted decoders so only the private normal-field rule is tested.
	t.Run("UnmarshalJSON", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateUnmarshal `json:"payload"`
			UnmarshalJSON        bool   `json:"-"`
			Public               string `json:"public"`
		}{Public: "set"})
	})
	t.Run("UnmarshalJSONFrom", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateFrom   `json:"payload"`
			UnmarshalJSONFrom bool   `json:"-"`
			Public            string `json:"public"`
		}{Public: "set"})
	})
	t.Run("MarshalText", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateTextMarshal `json:"payload"`
			Public                 string `json:"public"`
		}{Public: "set"})
	})
	t.Run("AppendText", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateTextAppend `json:"payload"`
			Public                string `json:"public"`
		}{Public: "set"})
	})
	t.Run("UnmarshalText", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateTextUnmarshal `json:"payload"`
			UnmarshalText            bool   `json:"-"`
			Public                   string `json:"public"`
		}{Public: "set"})
	})
	t.Run("IsZero-with-omitzero", func(t *testing.T) {
		checkJSONPrivateMethodField(t, struct {
			jsonPrivateZero `json:"payload,omitzero"`
			Public          string `json:"public"`
		}{Public: "set"})
	})
	t.Run("IsZero-without-omitzero", func(t *testing.T) {
		type record struct {
			jsonPrivateZero `json:"payload,omitempty"`
		}
		want := record{jsonPrivateZero{Value: "set"}}
		checkJSONFieldDecode(t, `{"payload":{"value":"set"}}`, want, false)
		checkJSONFieldDecode(t, `{"PAYLOAD":{"value":"set"}}`, want, true)
		checkJSONFieldDecode(t, `{"payload":{"VALUE":"set"}}`, want, true)
	})
}

func TestJSONFieldsMarshalOnlyStillChecksObjectsAndPromotion(t *testing.T) {
	want := jsonPrivateMarshal{Value: "set"}
	checkJSONFieldDecode(t, `{"value":"set"}`, want, false)
	checkJSONFieldDecode(t, `{"VALUE":"set"}`, want, true)
	type promoted struct{ jsonPrivateMarshal }
	checkJSONFieldDecode(t, `{"value":"set"}`, promoted{want}, false)
	checkJSONFieldDecode(t, `{"VALUE":"set"}`, promoted{want}, true)
	type promotedWithOption struct {
		jsonPrivateMarshal `json:",omitempty"`
	}
	checkJSONFieldDecode(t, `{"value":"set"}`, promotedWithOption{want}, false)
	checkJSONFieldDecode(t, `{"VALUE":"set"}`, promotedWithOption{want}, true)
	type named struct {
		Payload jsonPrivateMarshal `json:"payload"`
	}
	checkJSONFieldDecode(t, `{"payload":{"value":"set"}}`, named{want}, false)
	checkJSONFieldDecode(t, `{"payload":{"VALUE":"set"}}`, named{want}, true)
}

func TestJSONFieldsTablesAreValueDirected(t *testing.T) {
	type unused struct {
		Invalid string `json:"\\reserved"`
	}
	type record struct {
		Child *unused `json:"child"`
		Value string  `json:"value"`
	}
	tables := map[reflect.Type]map[string]reflect.Type{}
	for _, value := range []any{nil, []any{}, []any{map[string]any{"child": nil, "value": "x"}, map[string]any{"value": "y"}}} {
		if err := rejectCaseFoldedKeys(value, reflect.TypeFor[[]record](), tables); err != nil {
			t.Fatal(err)
		}
	}
	if len(tables) != 1 || tables[reflect.TypeFor[record]()]["child"] != reflect.TypeFor[*unused]() {
		t.Fatalf("unexpected lazy field tables: %v", tables)
	}
}
