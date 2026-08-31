package nodetestselector

import (
	"strings"
	"testing"
)

const selectedTestName = "selected test"

func TestAdmitTAPRequiresExactlyOneSelectedPass(t *testing.T) {
	valid := "TAP version 13\n# Subtest: selected test\nok 1 - selected test\n1..1\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"
	if err := admitTAP(valid, selectedTestName); err != nil {
		t.Fatalf("admitTAP(valid) error = %v", err)
	}
	for _, mutant := range []string{
		"TAP version 13\n1..0\n# Subtest: fixture.mjs\nok 1 - fixture.mjs\n1..1\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n",
		strings.Replace(valid, "ok 1", "not ok 1", 1),
		strings.Replace(valid, "# tests 1", "# tests 2", 1),
		valid + "# Subtest: selected test\nok 2 - selected test\n",
	} {
		if err := admitTAP(mutant, selectedTestName); err == nil {
			t.Fatalf("admitTAP accepted mutant %q", mutant)
		}
	}
}

func TestBoundedBufferRejectsOneByteOverLimit(t *testing.T) {
	var buffer boundedBuffer
	if _, err := buffer.Write(make([]byte, maximumTAPBytes)); err != nil {
		t.Fatalf("boundary write failed: %v", err)
	}
	if _, err := buffer.Write([]byte{'x'}); err == nil {
		t.Fatal("one-byte-over write succeeded")
	}
}
