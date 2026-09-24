package admit

import "testing"

func TestSecretAssignmentQuotedKeysAndNormalization(t *testing.T) {
	for _, value := range []string{
		`password=synthetic-fixture-value`,
		`"password": "synthetic-fixture-value"`,
		`'access-token': 'synthetic-fixture-value'`,
		`\"api_key\": \"synthetic-fixture-value\"`,
		`"Authorization": "Basic synthetic-fixture-value"`,
		"api_\u200bkey=synthetic-fixture-value",
	} {
		if !ContainsSecretLikeValue(value) || !ContainsSecretTokenLikeValue(value) {
			t.Fatal("assignment escaped shared scalar or typed-token detection")
		}
		if RedactDiagnosticValue(value) != redactedValueLabel || RedactSecretLikeValue(value) != redactedValueLabel {
			t.Fatal("recognized assignment escaped redaction")
		}
	}
	for _, value := range []string{`password`, `"password"`, `tokenName`, `function password() {}`, "A caf\u00e9 label has no credential assignment."} {
		if ContainsSecretLikeValue(value) || RedactSecretLikeValue(value) != value {
			t.Fatal("safe label or text was classified as a credential assignment")
		}
	}
	url := "https:\u200b//user:synthetic-fixture-value@example.test/path"
	if !ContainsURLCredentialValue(url) || !ContainsSecretLikeValue(url) || ContainsSecretTokenLikeValue(url) {
		t.Fatal("normalization lost the distinct URL-credential class")
	}
	patterns := SecretLikeValuePatternSources()
	patterns[0] = "caller mutation"
	if SecretLikeValuePatternSources()[0] == patterns[0] {
		t.Fatal("pattern projection aliases shared policy")
	}
}
