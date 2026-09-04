package pathidentity

import "testing"

func TestPortableEquivalenceAndContainment(t *testing.T) {
	tests := []struct {
		left    string
		right   string
		overlap bool
	}{
		{left: "proofkit/A.json", right: "proofkit/a.json", overlap: true},
		{left: "proofkit/caf\u00e9.json", right: "proofkit/cafe\u0301.json", overlap: true},
		{left: "proofkit", right: "proofkit/a.json", overlap: true},
		{left: "proofkit/a.json", right: "docs/a.json", overlap: false},
	}
	for _, test := range tests {
		actual, err := Overlaps(test.left, test.right)
		if err != nil || actual != test.overlap {
			t.Fatalf("Overlaps(%q, %q)=%t,%v, want %t,nil", test.left, test.right, actual, err, test.overlap)
		}
	}
	if _, err := Key(string([]byte{0xff})); err == nil {
		t.Fatal("Key() admitted invalid UTF-8")
	}
	if left, _ := Key("proofkit/\u03c3.json"); left != mustKey(t, "proofkit/\u03c2.json") {
		t.Fatal("Key() did not apply Unicode case folding")
	}
	for _, value := range []string{"", "/absolute", "a/../b", "a//b", "a\\b", "./a"} {
		if _, err := Key(value); err == nil {
			t.Fatalf("Key(%q) admitted a non-canonical path", value)
		}
	}
	prefixes, err := Prefixes("Proofkit/specs/a.json")
	if err != nil || len(prefixes) != 3 || prefixes[0].Key != "proofkit" || prefixes[1].Path != "Proofkit/specs" {
		t.Fatalf("Prefixes() = %#v, %v", prefixes, err)
	}
}

func mustKey(t *testing.T, value string) string {
	t.Helper()
	key, err := Key(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
