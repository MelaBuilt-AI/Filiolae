package s2leaf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func syntheticLeaf(t *testing.T) ([]byte, Trust) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	keyInput := append(append([]byte{}, keyIDDomain...), public...)
	keyDigest := sha256.Sum256(keyInput)
	body := map[string]any{
		"anchor_kind": LocalAnchorKind, "anchor_seq": 0,
		"ledger_head_sha256": "ab" + string(make([]byte, 0)),
		"ledger_schema":      "filiolae.ledger.v1", "ledger_seq": 1,
		"previous_receipt_sha256": string(make([]byte, 0)),
		"run_id":                  "synthetic-s2-test", "schema": ReceiptSchema,
		"signed_at":     "2026-08-13T14:00:00.000000Z",
		"signer_key_id": "sha256:" + hex.EncodeToString(keyDigest[:]),
	}
	body["ledger_head_sha256"] = "abababababababababababababababababababababababababababababababab"
	body["previous_receipt_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
	bodyRaw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append(append([]byte{}, signatureDomain...), bodyRaw...))
	receipt := make(map[string]any, len(body)+1)
	for key, value := range body {
		receipt[key] = value
	}
	receipt["signature"] = base64.StdEncoding.EncodeToString(signature)
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw = append(receiptRaw, '\n')
	outer := map[string]any{
		"receipt_b64":               base64.StdEncoding.EncodeToString(receiptRaw),
		"schema":                    LeafSchema,
		"signer_public_key_b64":     base64.StdEncoding.EncodeToString(public),
		"witness_enrollment_sha256": nil,
	}
	leaf, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	leaf = append(leaf, '\n')
	trust := Trust{Schema: "filiolae.transparency-s2-trust.v1", SignerPublicKeyB64: base64.StdEncoding.EncodeToString(public), RunIDPrefix: "synthetic-s2-"}
	return leaf, trust
}

func TestValidateSyntheticLeaf(t *testing.T) {
	leaf, trust := syntheticLeaf(t)
	metadata, err := Validate(leaf, trust)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if metadata.RunID != "synthetic-s2-test" {
		t.Fatalf("RunID=%q", metadata.RunID)
	}
}

func TestRejectTamperAndMalformedSignedFields(t *testing.T) {
	leaf, trust := syntheticLeaf(t)
	altered := append([]byte{}, leaf...)
	altered[len(altered)/2] ^= 1
	if _, err := Validate(altered, trust); err == nil {
		t.Fatal("accepted tampered leaf")
	}

	var outer map[string]any
	if err := json.Unmarshal(leaf, &outer); err != nil {
		t.Fatal(err)
	}
	receiptRaw, _ := base64.StdEncoding.DecodeString(outer["receipt_b64"].(string))
	var receipt map[string]any
	if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["anchor_seq"] = -1
	malformed, _ := json.Marshal(receipt)
	outer["receipt_b64"] = base64.StdEncoding.EncodeToString(append(malformed, '\n'))
	outerRaw, _ := json.Marshal(outer)
	if _, err := Validate(append(outerRaw, '\n'), trust); err == nil {
		t.Fatal("accepted malformed signed receipt")
	}
}
