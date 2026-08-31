package diagnostic

import (
	"fmt"
	"strings"
	"sync"
)

const maxCapturedStderrBytes = 64 << 10

// CaptureStderr retains bounded child-process stderr for whole-value
// sanitization after the child reaches a terminal state.
type CaptureStderr struct {
	content  []byte
	mu       sync.Mutex
	overflow bool
}

// NewStderrCapture returns an empty bounded stderr capture.
func NewStderrCapture() *CaptureStderr {
	return &CaptureStderr{content: make([]byte, 0, 4096)}
}

// Write implements io.Writer while retaining at most the admitted byte bound.
func (capture *CaptureStderr) Write(value []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	remaining := maxCapturedStderrBytes - len(capture.content)
	if remaining > 0 {
		retained := len(value)
		if retained > remaining {
			retained = remaining
		}
		capture.content = append(capture.content, value[:retained]...)
	}
	if len(value) > remaining {
		capture.overflow = true
	}
	return len(value), nil
}

// Failure returns one bounded, already-sanitized summary for a failed child
// process. Empty child stderr returns nil; successful child stderr is not a
// report-visible diagnostic.
func (capture *CaptureStderr) Failure(label string) error {
	capture.mu.Lock()
	content := append([]byte(nil), capture.content...)
	overflow := capture.overflow
	capture.mu.Unlock()
	if len(content) == 0 && !overflow {
		return nil
	}
	if overflow {
		return fmt.Errorf("%s exceeded the stderr capture limit", label)
	}
	value := strings.TrimSpace(string(content))
	if value == "" {
		return fmt.Errorf("%s emitted empty-or-whitespace stderr", label)
	}
	return fmt.Errorf("%s: %s", label, Text(fmt.Errorf("%s", value)))
}
