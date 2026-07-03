package cliexec

import "testing"

func TestDisplayCommandQuotesAmbiguousArgs(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{
			args: []string{"gradual-adoption", "--input", "proofkit/profile.json"},
			want: "agentic-proofkit gradual-adoption --input proofkit/profile.json",
		},
		{
			args: []string{"gradual-adoption", "--input", "proofkit/adoption profile.v1.json"},
			want: "agentic-proofkit gradual-adoption --input 'proofkit/adoption profile.v1.json'",
		},
		{
			args: []string{"text-policy", "--input", "proofkit/owner's file.json"},
			want: "agentic-proofkit text-policy --input 'proofkit/owner'\"'\"'s file.json'",
		},
		{
			args: []string{"self-check", "--input", ""},
			want: "agentic-proofkit self-check --input ''",
		},
	}
	for _, item := range cases {
		if got := DisplayCommand(item.args...); got != item.want {
			t.Fatalf("DisplayCommand(%#v) = %q, want %q", item.args, got, item.want)
		}
	}
}
