package digest

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func SHA256TextRef(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func StableJSONSHA256Ref(value any) (string, error) {
	serialized, err := stablejson.Marshal(value)
	if err != nil {
		return "", err
	}
	return SHA256TextRef(string(serialized)), nil
}
