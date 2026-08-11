package commandcoverage

import "testing"

const validMarker = "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001"

func TestSemanticRouteEmitsAttributeOnlyAfterSuccessfulCleanup(t *testing.T) {
	context := &fakeTestContext{}
	SemanticRoute(context, validMarker)
	if len(context.attributes) != 0 || len(context.cleanups) != 1 {
		t.Fatalf("registration state = %#v", context)
	}
	context.cleanups[0]()
	if len(context.attributes) != 1 || context.attributes[0] != [2]string{ExecutionAttributeKey, validMarker} {
		t.Fatalf("attributes = %#v", context.attributes)
	}
}

func TestSemanticRouteSuppressesFailedAndSkippedEvidence(t *testing.T) {
	for _, item := range []struct {
		name    string
		failed  bool
		skipped bool
	}{
		{name: "failed", failed: true},
		{name: "skipped", skipped: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			context := &fakeTestContext{failed: item.failed, skipped: item.skipped}
			SemanticRoute(context, validMarker)
			context.cleanups[0]()
			if len(context.attributes) != 0 {
				t.Fatalf("attributes = %#v", context.attributes)
			}
		})
	}
}

func TestSemanticRouteRejectsMalformedMarker(t *testing.T) {
	context := &fakeTestContext{}
	SemanticRoute(context, "invalid")
	if context.fatalCount != 1 || len(context.cleanups) != 0 {
		t.Fatalf("malformed marker state = %#v", context)
	}
}

type fakeTestContext struct {
	attributes [][2]string
	cleanups   []func()
	failed     bool
	fatalCount int
	skipped    bool
}

func (context *fakeTestContext) Attr(key, value string) {
	context.attributes = append(context.attributes, [2]string{key, value})
}

func (context *fakeTestContext) Cleanup(cleanup func()) {
	context.cleanups = append(context.cleanups, cleanup)
}

func (context *fakeTestContext) Failed() bool { return context.failed }

func (context *fakeTestContext) Fatalf(string, ...any) { context.fatalCount++ }

func (context *fakeTestContext) Helper() {}

func (context *fakeTestContext) Skipped() bool { return context.skipped }
