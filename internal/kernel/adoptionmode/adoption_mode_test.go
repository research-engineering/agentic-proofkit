package adoptionmode

import (
	"encoding/json"
	"testing"
)

func TestValuesMapIsDefensiveAndSortedForDiagnostics(t *testing.T) {
	if AllowedText() != "enforce-all, enforce-touched, observe, warn" {
		t.Fatalf("AllowedText() = %q", AllowedText())
	}
	if AllowedScopeText() != "all, none, touched" {
		t.Fatalf("AllowedScopeText() = %q", AllowedScopeText())
	}
	if CLIAllowedText() != "observe, warn, enforce-touched, or enforce-all" {
		t.Fatalf("CLIAllowedText() = %q", CLIAllowedText())
	}
	if CLIScopeText() != "none, touched, or all" {
		t.Fatalf("CLIScopeText() = %q", CLIScopeText())
	}
	first := ValuesMap()
	delete(first, Observe)
	second := ValuesMap()
	if _, ok := second[Observe]; !ok {
		t.Fatal("ValuesMap exposed mutable vocabulary owner")
	}
}

func TestAdmitAndValidateRejectUnknownModes(t *testing.T) {
	if got, err := Admit(Observe, "mode"); err != nil || got != Observe {
		t.Fatalf("Admit(observe) = %q, %v", got, err)
	}
	if _, err := Admit(json.Number("1"), "mode"); err == nil {
		t.Fatal("Admit accepted non-string mode")
	}
	if _, err := Validate("audit", "mode"); err == nil {
		t.Fatal("Validate accepted unknown mode")
	}
	if _, err := ValidateCLI("audit", "--guidance-mode"); err == nil {
		t.Fatal("ValidateCLI accepted unknown mode")
	}
	if got, err := AdmitScope(ScopeTouched, "checkedScope"); err != nil || got != ScopeTouched {
		t.Fatalf("AdmitScope(touched) = %q, %v", got, err)
	}
	if _, err := ValidateScopeValue("partial", "checkedScope"); err == nil {
		t.Fatal("ValidateScopeValue accepted unknown checked scope")
	}
	if _, err := ValidateScopeCLI("partial", "--checked-scope"); err == nil {
		t.Fatal("ValidateScopeCLI accepted unknown checked scope")
	}
}

func TestIsEnforcingAndNonEnforcingStatus(t *testing.T) {
	for _, mode := range []string{EnforceAll, EnforceTouched} {
		if !IsEnforcing(mode) {
			t.Fatalf("%s should be enforcing", mode)
		}
	}
	for _, mode := range []string{Observe, Warn} {
		if IsEnforcing(mode) {
			t.Fatalf("%s should not be enforcing", mode)
		}
	}
	if NonEnforcingStatus(Warn) != "warning" {
		t.Fatalf("warn non-enforcing status = %q", NonEnforcingStatus(Warn))
	}
	if NonEnforcingStatus(Observe) != "skipped" {
		t.Fatalf("observe non-enforcing status = %q", NonEnforcingStatus(Observe))
	}
}

func TestScopeFailures(t *testing.T) {
	cases := []struct {
		mode         string
		checkedScope string
		wantFailure  string
	}{
		{mode: EnforceAll, checkedScope: ScopeTouched, wantFailure: "enforce-all requires checkedScope all"},
		{mode: EnforceTouched, checkedScope: ScopeNone, wantFailure: "enforce-touched requires checkedScope touched or all"},
		{mode: EnforceAll, checkedScope: ScopeAll},
		{mode: EnforceTouched, checkedScope: ScopeTouched},
		{mode: EnforceTouched, checkedScope: ScopeAll},
		{mode: Observe, checkedScope: ScopeNone},
		{mode: Warn, checkedScope: ScopeNone},
	}
	for _, item := range cases {
		t.Run(item.mode+"/"+item.checkedScope, func(t *testing.T) {
			failures := ScopeFailures(item.mode, item.checkedScope)
			if item.wantFailure == "" {
				if len(failures) != 0 {
					t.Fatalf("ScopeFailures() = %#v, want none", failures)
				}
				if err := ValidateScope(item.mode, item.checkedScope, "adoption doctor"); err != nil {
					t.Fatalf("ValidateScope() error = %v", err)
				}
				return
			}
			if len(failures) != 1 || failures[0] != item.wantFailure {
				t.Fatalf("ScopeFailures() = %#v, want %q", failures, item.wantFailure)
			}
			if err := ValidateScope(item.mode, item.checkedScope, "adoption doctor"); err == nil {
				t.Fatal("ValidateScope accepted invalid mode/scope pair")
			}
		})
	}
}
