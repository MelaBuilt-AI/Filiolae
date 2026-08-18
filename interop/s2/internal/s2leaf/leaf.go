package s2leaf

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	LeafSchema      = "filiolae.receipt-transparency-leaf.v1"
	ReceiptSchema   = "filiolae.ledger-head-receipt.v1"
	LocalAnchorKind = "local_ed25519_checkpoint"
	MaxLeafBytes    = 64 * 1024
)

var (
	signatureDomain = []byte("filiolae-ledger-head-receipt-v1\x00")
	keyIDDomain     = []byte("filiolae-ed25519-key-id-v1\x00")
	outerFields     = map[string]bool{"receipt_b64": true, "schema": true, "signer_public_key_b64": true, "witness_enrollment_sha256": true}
	receiptFields   = map[string]bool{"schema": true, "anchor_kind": true, "anchor_seq": true, "run_id": true, "ledger_schema": true, "ledger_seq": true, "ledger_head_sha256": true, "previous_receipt_sha256": true, "signer_key_id": true, "signed_at": true, "signature": true}
	nonnegativeInt  = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
	lowerHex64      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Trust struct {
	Schema             string `json:"schema"`
	SignerPublicKeyB64 string `json:"signer_public_key_b64"`
	RunIDPrefix        string `json:"run_id_prefix"`
}

type Metadata struct {
	RunID      string
	ReceiptB64 string
}

func canonicalObject(raw []byte, fields map[string]bool) (map[string]any, error) {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if len(value) != len(fields) {
		return nil, fmt.Errorf("unexpected field count")
	}
	for key := range value {
		if !fields[key] {
			return nil, fmt.Errorf("unexpected field")
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, raw) {
		return nil, fmt.Errorf("noncanonical JSON")
	}
	return value, nil
}

func strictBase64(value any) ([]byte, string, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return nil, "", fmt.Errorf("base64 field is empty")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, "", fmt.Errorf("base64 field is not canonical")
	}
	return decoded, text, nil
}

func LoadTrust(raw []byte) (Trust, error) {
	var trust Trust
	if err := json.Unmarshal(raw, &trust); err != nil {
		return trust, err
	}
	if trust.Schema != "filiolae.transparency-s2-trust.v1" || trust.RunIDPrefix != "synthetic-s2-" {
		return trust, fmt.Errorf("unapproved S2 trust fixture")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(trust.SignerPublicKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != trust.SignerPublicKeyB64 {
		return trust, fmt.Errorf("invalid fixture public key")
	}
	return trust, nil
}

func Validate(raw []byte, trust Trust) (Metadata, error) {
	var result Metadata
	if len(raw) == 0 || len(raw) > MaxLeafBytes || raw[len(raw)-1] != '\n' || bytes.Contains(raw[:len(raw)-1], []byte{'\n'}) {
		return result, fmt.Errorf("leaf must be bounded canonical JSON with one newline")
	}
	outer, err := canonicalObject(raw[:len(raw)-1], outerFields)
	if err != nil {
		return result, fmt.Errorf("leaf: %w", err)
	}
	if outer["schema"] != LeafSchema || outer["witness_enrollment_sha256"] != nil {
		return result, fmt.Errorf("leaf schema or enrollment is invalid")
	}
	key, keyText, err := strictBase64(outer["signer_public_key_b64"])
	if err != nil || keyText != trust.SignerPublicKeyB64 {
		return result, fmt.Errorf("leaf key is not the synthetic fixture key")
	}
	receiptRaw, receiptText, err := strictBase64(outer["receipt_b64"])
	if err != nil || len(receiptRaw) == 0 || receiptRaw[len(receiptRaw)-1] != '\n' {
		return result, fmt.Errorf("invalid receipt encoding")
	}
	receipt, err := canonicalObject(receiptRaw[:len(receiptRaw)-1], receiptFields)
	if err != nil {
		return result, fmt.Errorf("receipt: %w", err)
	}
	if receipt["schema"] != ReceiptSchema || receipt["anchor_kind"] != LocalAnchorKind || receipt["ledger_schema"] != "filiolae.ledger.v1" {
		return result, fmt.Errorf("receipt schema is invalid")
	}
	for _, field := range []string{"anchor_seq", "ledger_seq"} {
		number, ok := receipt[field].(json.Number)
		if !ok || !nonnegativeInt.MatchString(number.String()) {
			return result, fmt.Errorf("receipt sequence is invalid")
		}
	}
	for _, field := range []string{"ledger_head_sha256", "previous_receipt_sha256"} {
		digest, ok := receipt[field].(string)
		if !ok || !lowerHex64.MatchString(digest) {
			return result, fmt.Errorf("receipt digest is invalid")
		}
	}
	runID, ok := receipt["run_id"].(string)
	if !ok || !strings.HasPrefix(runID, trust.RunIDPrefix) || len(runID) > 128 {
		return result, fmt.Errorf("receipt run ID is not synthetic S2 material")
	}
	signedAt, ok := receipt["signed_at"].(string)
	if !ok || !strings.HasSuffix(signedAt, "Z") {
		return result, fmt.Errorf("receipt signed time is invalid")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, signedAt)
	if err != nil || timestamp.Location() != time.UTC {
		return result, fmt.Errorf("receipt signed time is invalid")
	}
	keyDigestInput := append(append([]byte{}, keyIDDomain...), key...)
	keyDigest := sha256.Sum256(keyDigestInput)
	wantKeyID := "sha256:" + hex.EncodeToString(keyDigest[:])
	if receipt["signer_key_id"] != wantKeyID {
		return result, fmt.Errorf("receipt signer key ID mismatch")
	}
	signature, _, err := strictBase64(receipt["signature"])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return result, fmt.Errorf("receipt signature encoding is invalid")
	}
	delete(receipt, "signature")
	body, err := json.Marshal(receipt)
	if err != nil {
		return result, err
	}
	message := append(append([]byte{}, signatureDomain...), body...)
	if !ed25519.Verify(ed25519.PublicKey(key), message, signature) {
		return result, fmt.Errorf("receipt signature is invalid")
	}
	return Metadata{RunID: runID, ReceiptB64: receiptText}, nil
}
