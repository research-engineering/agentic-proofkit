//go:build !darwin && !linux

package repositorysnapshot

import "testing"

func testCaptureContextTerminatesGitProcessGroupOnOutputOverflow(t *testing.T) {
	t.Skip("process-group absence proof requires the supported Darwin or Linux process-group primitive")
}
