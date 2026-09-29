package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
)

func TestWheelContractResourceLimitDoesNotRaiseOtherEntryLimits(t *testing.T) {
	for _, test := range []struct {
		path  string
		limit int
	}{
		{embeddedCLIContractPath, 2 << 20},
		{"agentic_proofkit/cli.py", 1 << 20},
		{"agentic_proofkit/proofkit/other.json", 1 << 20},
		{"agentic_proofkit/proofkit/cli-contract.v2.json.extra", 1 << 20},
	} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", test.path, extra), func(t *testing.T) {
				var buffer bytes.Buffer
				writer := zip.NewWriter(&buffer)
				entry, err := writer.Create(test.path)
				if err != nil {
					t.Fatal(err)
				}
				content := bytes.Repeat([]byte(" "), test.limit+extra)
				if _, err := entry.Write(content); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
				if err != nil {
					t.Fatal(err)
				}
				got, err := readZipFile(reader.File[0])
				if extra == 1 {
					if err == nil || got != nil {
						t.Fatal("one-over entry returned bytes")
					}
				} else if err != nil || !bytes.Equal(got, content) {
					t.Fatalf("exact-bound entry failed: %v", err)
				}
			})
		}
	}
	if maximumWheelEntryBytes("agentic_proofkit/bin/agentic-proofkit") != 64<<20 || installedclicontract.MaximumContractBytes != 2<<20 {
		t.Fatal("binary or contract bound differs from its explicit resource policy")
	}
}
