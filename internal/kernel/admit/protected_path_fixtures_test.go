package admit

import "testing"

func TestMaterializedPathsRefuseEveryProtectedReportFixture(t *testing.T) {
	fixtures := ReportVisibleRedactionFixtures()
	if len(fixtures) == 0 {
		t.Fatal("protected fixture catalog is empty")
	}
	for _, fixture := range fixtures {
		for _, prefix := range []string{"inputs/", "inputs/prefix"} {
			if _, err := MaterializedInputPath(prefix+fixture.Input+"suffix.json", "prepared input"); err == nil {
				t.Fatalf("protected fixture %s reached a materialized path", fixture.Name)
			}
		}
	}
}
