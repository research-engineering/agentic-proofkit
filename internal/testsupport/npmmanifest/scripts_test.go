package npmmanifest

import (
	"reflect"
	"testing"
)

func TestScriptsSelectExactNPMObject(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"canonical", `{"scripts":{"check":"owned check"}}`, map[string]string{"check": "owned check"}},
		{"later case variant", `{"scripts":{"check":"true"},"Scripts":{"check":"owned check"}}`, map[string]string{"check": "true"}},
		{"earlier case variant", `{"Scripts":{"check":"owned check"},"scripts":{"check":"true"}}`, map[string]string{"check": "true"}},
		{"whole last object", `{"scripts":{"check":"old check","old":"old only"},"scripts":{"check":"new check","new":"new only"}}`, map[string]string{"check": "new check", "new": "new only"}},
		{"empty last object", `{"scripts":{"check":"old check"},"scripts":{}}`, map[string]string{}},
		{"explicit empty command", `{"scripts":{"postpython:verify":""}}`, map[string]string{"postpython:verify": ""}},
		{"last command", `{"scripts":{"check":"old","check":"new"}}`, map[string]string{"check": "new"}},
		{"overwritten number", `{"scripts":{"check":0,"check":"owned check"}}`, map[string]string{"check": "owned check"}},
		{"overwritten oversized number", `{"scripts":{"check":1e400,"check":"owned check"}}`, map[string]string{"check": "owned check"}},
		{"overwritten null", `{"scripts":{"check":null,"check":"owned check"}}`, map[string]string{"check": "owned check"}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			got, err := Scripts([]byte(item.raw))
			if err != nil || !reflect.DeepEqual(got, item.want) {
				t.Fatalf("selected scripts=%v error=%v, want %v", got, err, item.want)
			}
		})
	}
	for _, raw := range []string{
		`{`, `null`, `[]`, `{}`, `{"Scripts":{"check":"owned check"}}`,
		`{"scripts":null}`, `{"scripts":[]}`, `{"scripts":"check"}`,
		`{"scripts":{"check":null}}`, `{"scripts":{"check":false}}`,
		`{"scripts":{"check":0}}`, `{"scripts":{"check":{}}}`,
		`{"scripts":{"check":[]}}`, `{"scripts":{"check":"old","check":1e400}}`,
		`{"scripts":{"check":"old","check":null}}`, `{"scripts":{},"scripts":null}`,
	} {
		if got, err := Scripts([]byte(raw)); err == nil || got != nil {
			t.Fatal("malformed or non-string script owner was admitted")
		}
	}
}
