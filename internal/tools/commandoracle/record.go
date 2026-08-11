package commandoracle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
)

const maxRecordBytes = 32 << 20

func InvalidateDiagnostic(root string) error {
	return artifactfile.Remove(root, RecordPath)
}

func WriteDiagnostic(root string, evidence Evidence) error {
	if err := validateRecordShape(evidence.Record); err != nil {
		return err
	}
	canonical, digest, err := encodeRecord(evidence.Record)
	if err != nil {
		return err
	}
	if !bytes.Equal(evidence.RecordBytes, canonical) || evidence.RecordDigest != digest {
		return decision("record.bytes_invalid")
	}
	return artifactfile.WriteAtomic(root, RecordPath, evidence.RecordBytes, 0o644)
}

func EvidenceForRecord(record Record) (Evidence, error) {
	if err := validateRecordShape(record); err != nil {
		return Evidence{}, err
	}
	content, digest, err := encodeRecord(record)
	if err != nil {
		return Evidence{}, err
	}
	candidates := make([]app.CommandCoverageOracleCandidate, 0, len(record.Entries))
	for _, entry := range record.Entries {
		candidates = append(candidates, entry.Candidate)
	}
	return Evidence{
		Candidates:   candidates,
		Record:       record,
		RecordBytes:  content,
		RecordDigest: digest,
	}, nil
}

func ReadDiagnostic(root string) (Evidence, error) {
	content, err := artifactfile.ReadBounded(root, RecordPath, maxRecordBytes)
	if err != nil {
		return Evidence{}, err
	}
	if len(content) == 0 {
		return Evidence{}, decision("record.resource_limit")
	}
	return admitRecordBytes(content)
}

func admitRecordBytes(content []byte) (Evidence, error) {
	if len(content) == 0 || len(content) > maxRecordBytes {
		return Evidence{}, decision("record.resource_limit")
	}
	if _, err := admission.DecodeJSON(bytes.NewReader(content), maxRecordBytes); err != nil {
		return Evidence{}, decision("record.json_invalid")
	}
	var record Record
	if err := json.Unmarshal(content, &record); err != nil {
		return Evidence{}, decision("record.type_invalid")
	}
	evidence, err := EvidenceForRecord(record)
	if err != nil {
		return Evidence{}, err
	}
	if !bytes.Equal(content, evidence.RecordBytes) {
		return Evidence{}, decision("record.canonical_bytes_mismatch")
	}
	evidence.RecordBytes = content
	return evidence, nil
}

func encodeRecord(record Record) ([]byte, string, error) {
	content, err := stablejson.Marshal(recordValue(record))
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(content)
	return content, hex.EncodeToString(digest[:]), nil
}
