package main

import "testing"

func TestEqualStringsUsesElementwiseEquality(t *testing.T) {
	for _, test := range []struct {
		name        string
		left, right []string
		want        bool
	}{
		{"delimiter collision", []string{"a\x00b", "c"}, []string{"a", "b\x00c"}, false},
		{"equal embedded delimiter", []string{"a\x00b", "c"}, []string{"a\x00b", "c"}, true},
		{"order", []string{"a", "b"}, []string{"b", "a"}, false},
		{"length", []string{"a"}, []string{"a", ""}, false},
		{"nil and empty", nil, []string{}, true},
		{"equal values", []string{"a", "b"}, []string{"a", "b"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := equalStrings(test.left, test.right); got != test.want {
				t.Fatalf("equalStrings(%q, %q)=%v, want %v", test.left, test.right, got, test.want)
			}
		})
	}
}
