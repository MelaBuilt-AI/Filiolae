package interop

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

const vectorPath = "../../tests/vectors/transparency-interop-v1.json"

type rootVector struct {
	TreeSize uint64 `json:"tree_size"`
	RootHex  string `json:"root_hex"`
}

type inclusionVector struct {
	TreeSize  uint64   `json:"tree_size"`
	LeafIndex uint64   `json:"leaf_index"`
	ProofHex  []string `json:"proof_hex"`
}

type consistencyVector struct {
	OldSize  uint64   `json:"old_size"`
	NewSize  uint64   `json:"new_size"`
	ProofHex []string `json:"proof_hex"`
}

type checkpointVector struct {
	Origin        string `json:"origin"`
	TreeSize      uint64 `json:"tree_size"`
	RootHex       string `json:"root_hex"`
	VerifierKey   string `json:"verifier_key"`
	SignedNoteB64 string `json:"signed_note_b64"`
}

type vectors struct {
	Schema            string              `json:"schema"`
	LeavesB64         []string            `json:"leaves_b64"`
	LeafHashesHex     []string            `json:"leaf_hashes_hex"`
	Roots             []rootVector        `json:"roots"`
	InclusionProofs   []inclusionVector   `json:"inclusion_proofs"`
	ConsistencyProofs []consistencyVector `json:"consistency_proofs"`
	Checkpoint        checkpointVector    `json:"checkpoint"`
}

type treeSnapshot struct {
	root  []byte
	nodes map[compact.NodeID][]byte
}

func mustDecodeHex(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func decodeProof(t testing.TB, encoded []string) [][]byte {
	t.Helper()
	result := make([][]byte, len(encoded))
	for i, item := range encoded {
		result[i] = mustDecodeHex(t, item)
	}
	return result
}

func loadVectors(t testing.TB) (vectors, [][]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Schema != "filiolae.transparency-interop-v1" {
		t.Fatalf("unexpected schema %q", v.Schema)
	}
	leaves := make([][]byte, len(v.LeavesB64))
	for i, encoded := range v.LeavesB64 {
		leaves[i], err = base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode leaf %d: %v", i, err)
		}
	}
	return v, leaves
}

func buildSnapshots(t testing.TB, leaves [][]byte) []treeSnapshot {
	t.Helper()
	hasher := rfc6962.DefaultHasher
	factory := &compact.RangeFactory{Hash: hasher.HashChildren}
	rangeTree := factory.NewEmptyRange(0)
	nodes := make(map[compact.NodeID][]byte)
	snapshots := make([]treeSnapshot, len(leaves)+1)
	snapshots[0] = treeSnapshot{root: hasher.EmptyRoot(), nodes: map[compact.NodeID][]byte{}}
	for i, leaf := range leaves {
		if err := rangeTree.Append(hasher.HashLeaf(leaf), func(id compact.NodeID, hash []byte) {
			nodes[id] = bytes.Clone(hash)
		}); err != nil {
			t.Fatalf("append leaf %d: %v", i, err)
		}
		root, err := rangeTree.GetRootHash(nil)
		if err != nil {
			t.Fatalf("root at size %d: %v", i+1, err)
		}
		copyNodes := make(map[compact.NodeID][]byte, len(nodes))
		for id, hash := range nodes {
			copyNodes[id] = bytes.Clone(hash)
		}
		snapshots[i+1] = treeSnapshot{root: bytes.Clone(root), nodes: copyNodes}
	}
	return snapshots
}

func materializeProof(t testing.TB, plan proof.Nodes, nodes map[compact.NodeID][]byte) [][]byte {
	t.Helper()
	hashes := make([][]byte, len(plan.IDs))
	for i, id := range plan.IDs {
		hash, ok := nodes[id]
		if !ok {
			t.Fatalf("independent proof builder requested absent node %+v", id)
		}
		hashes[i] = bytes.Clone(hash)
	}
	result, err := plan.Rehash(hashes, rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		t.Fatalf("rehash proof: %v", err)
	}
	return result
}

func TestFrozenVectorsMatchIndependentGoImplementations(t *testing.T) {
	v, leaves := loadVectors(t)
	hasher := rfc6962.DefaultHasher
	snapshots := buildSnapshots(t, leaves)

	if len(v.LeafHashesHex) != len(leaves) {
		t.Fatalf("leaf hash count %d != leaf count %d", len(v.LeafHashesHex), len(leaves))
	}
	for i, leaf := range leaves {
		if got, want := hasher.HashLeaf(leaf), mustDecodeHex(t, v.LeafHashesHex[i]); !bytes.Equal(got, want) {
			t.Errorf("leaf hash %d differs\ngot  %x\nwant %x", i, got, want)
		}
	}
	for _, item := range v.Roots {
		if item.TreeSize >= uint64(len(snapshots)) {
			t.Fatalf("root size %d out of range", item.TreeSize)
		}
		if got, want := snapshots[item.TreeSize].root, mustDecodeHex(t, item.RootHex); !bytes.Equal(got, want) {
			t.Errorf("root size %d differs\ngot  %x\nwant %x", item.TreeSize, got, want)
		}
	}

	for _, item := range v.InclusionProofs {
		want := decodeProof(t, item.ProofHex)
		leafHash := hasher.HashLeaf(leaves[item.LeafIndex])
		root := snapshots[item.TreeSize].root
		if err := proof.VerifyInclusion(hasher, item.LeafIndex, item.TreeSize, leafHash, want, root); err != nil {
			t.Errorf("verify inclusion size=%d index=%d: %v", item.TreeSize, item.LeafIndex, err)
		}
		plan, err := proof.Inclusion(item.LeafIndex, item.TreeSize)
		if err != nil {
			t.Fatalf("plan inclusion: %v", err)
		}
		if got := materializeProof(t, plan, snapshots[item.TreeSize].nodes); !equalProof(got, want) {
			t.Errorf("generated inclusion size=%d index=%d differs\ngot  %x\nwant %x", item.TreeSize, item.LeafIndex, got, want)
		}
	}

	for _, item := range v.ConsistencyProofs {
		want := decodeProof(t, item.ProofHex)
		oldRoot := snapshots[item.OldSize].root
		newRoot := snapshots[item.NewSize].root
		if err := proof.VerifyConsistency(hasher, item.OldSize, item.NewSize, want, oldRoot, newRoot); err != nil {
			t.Errorf("verify consistency %d->%d: %v", item.OldSize, item.NewSize, err)
		}
		plan, err := proof.Consistency(item.OldSize, item.NewSize)
		if err != nil {
			t.Fatalf("plan consistency: %v", err)
		}
		if got := materializeProof(t, plan, snapshots[item.NewSize].nodes); !equalProof(got, want) {
			t.Errorf("generated consistency %d->%d differs\ngot  %x\nwant %x", item.OldSize, item.NewSize, got, want)
		}
	}

	verifier, err := note.NewVerifier(v.Checkpoint.VerifierKey)
	if err != nil {
		t.Fatalf("construct independent signed-note verifier: %v", err)
	}
	signed, err := base64.StdEncoding.Strict().DecodeString(v.Checkpoint.SignedNoteB64)
	if err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	opened, err := note.Open(signed, note.VerifierList(verifier))
	if err != nil {
		t.Fatalf("independent signed-note verification: %v", err)
	}
	wantText := fmt.Sprintf("%s\n%d\n%s\n", v.Checkpoint.Origin, v.Checkpoint.TreeSize,
		base64.StdEncoding.EncodeToString(mustDecodeHex(t, v.Checkpoint.RootHex)))
	if opened.Text != wantText {
		t.Fatalf("checkpoint text differs\ngot  %q\nwant %q", opened.Text, wantText)
	}
	if !bytes.Equal(snapshots[v.Checkpoint.TreeSize].root, mustDecodeHex(t, v.Checkpoint.RootHex)) {
		t.Fatal("checkpoint root does not match independent tree root")
	}
}

func TestIndependentVerifiersRejectFrozenVectorTampering(t *testing.T) {
	v, leaves := loadVectors(t)
	hasher := rfc6962.DefaultHasher
	snapshots := buildSnapshots(t, leaves)
	for _, item := range v.InclusionProofs {
		original := decodeProof(t, item.ProofHex)
		if len(original) == 0 {
			continue
		}
		altered := cloneProof(original)
		altered[0][0] ^= 1
		err := proof.VerifyInclusion(hasher, item.LeafIndex, item.TreeSize,
			hasher.HashLeaf(leaves[item.LeafIndex]), altered, snapshots[item.TreeSize].root)
		if err == nil {
			t.Fatalf("accepted altered inclusion proof size=%d index=%d", item.TreeSize, item.LeafIndex)
		}
	}
	for _, item := range v.ConsistencyProofs {
		original := decodeProof(t, item.ProofHex)
		if len(original) == 0 {
			continue
		}
		altered := cloneProof(original)
		altered[0][0] ^= 1
		err := proof.VerifyConsistency(hasher, item.OldSize, item.NewSize, altered,
			snapshots[item.OldSize].root, snapshots[item.NewSize].root)
		if err == nil {
			t.Fatalf("accepted altered consistency proof %d->%d", item.OldSize, item.NewSize)
		}
	}
	verifier, err := note.NewVerifier(v.Checkpoint.VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := base64.StdEncoding.Strict().DecodeString(v.Checkpoint.SignedNoteB64)
	if err != nil {
		t.Fatal(err)
	}
	signed[len(signed)-3] ^= 1
	if _, err := note.Open(signed, note.VerifierList(verifier)); err == nil {
		t.Fatal("accepted altered signed checkpoint")
	}
}

func FuzzIndependentInclusionVerifier(f *testing.F) {
	v, leaves := loadVectors(f)
	item := v.InclusionProofs[len(v.InclusionProofs)-2]
	original := decodeProof(f, item.ProofHex)
	flat := bytes.Join(original, nil)
	f.Add(flat)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, len(flat)))
	root := buildSnapshots(f, leaves)[item.TreeSize].root
	leafHash := rfc6962.DefaultHasher.HashLeaf(leaves[item.LeafIndex])
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}
		parts := splitHashes(raw)
		_ = proof.VerifyInclusion(rfc6962.DefaultHasher, item.LeafIndex, item.TreeSize, leafHash, parts, root)
	})
}

func FuzzIndependentSignedNoteParser(f *testing.F) {
	v, _ := loadVectors(f)
	verifier, err := note.NewVerifier(v.Checkpoint.VerifierKey)
	if err != nil {
		f.Fatal(err)
	}
	signed, err := base64.StdEncoding.Strict().DecodeString(v.Checkpoint.SignedNoteB64)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(signed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		_, _ = note.Open(raw, note.VerifierList(verifier))
	})
}

func cloneProof(value [][]byte) [][]byte {
	result := make([][]byte, len(value))
	for i, item := range value {
		result[i] = bytes.Clone(item)
	}
	return result
}

func equalProof(first, second [][]byte) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if !bytes.Equal(first[i], second[i]) {
			return false
		}
	}
	return true
}

func splitHashes(raw []byte) [][]byte {
	if len(raw)%rfc6962.DefaultHasher.Size() != 0 {
		return [][]byte{raw}
	}
	result := make([][]byte, 0, len(raw)/rfc6962.DefaultHasher.Size())
	for len(raw) > 0 {
		result = append(result, raw[:rfc6962.DefaultHasher.Size()])
		raw = raw[rfc6962.DefaultHasher.Size():]
	}
	return result
}
