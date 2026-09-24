package semversion

import "testing"

func TestIsExact(t *testing.T) {
	for _, test := range []struct {
		version string
		valid   bool
	}{
		{"0.0.0", true},
		{"1.2.3", true},
		{"1.2.3-alpha.1+build.01", true},
		{"1.2.3-0", true},
		{"1.2.3+01", true},
		{"1", false},
		{"1.2", false},
		{"v1.2.3", false},
		{"01.2.3", false},
		{"1.02.3", false},
		{"1.2.03", false},
		{"1.2.3-alpha..x", false},
		{"1.2.3-01", false},
		{"1.2.3+build..x", false},
	} {
		if got := IsExact(test.version); got != test.valid {
			t.Fatalf("IsExact(%q)=%t, want %t", test.version, got, test.valid)
		}
	}
}
