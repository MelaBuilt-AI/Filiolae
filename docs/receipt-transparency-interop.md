# Receipt-transparency S1 interoperability report

Status: **passed offline; frozen vectors and independent verifier retained in-tree**

Date: 2026-08-13

## Scope and boundary

S1 tests Filiolae's RFC 9162 Merkle and C2SP checkpoint bytes against maintained
implementations outside the Python package. All leaves are synthetic. The frozen
fixture contains one correctly signed synthetic Filiolae transparency leaf plus
binary edge cases; the deterministic private seeds in the generator are public
test material and are forbidden for any real signer.

The validation performed no log submission, external receipt disclosure, service
start, credential use, paid compute, Gate coupling, or publication. Network access
was used only to inspect upstream source metadata and fetch public Go modules; the
actual vector tests ran with `GOPROXY=off` and `GOSUMDB=off` after dependency fetch.

## Independent implementations

The Go harness in `interop/go/` pins:

- `github.com/transparency-dev/merkle`
  `v0.0.3-0.20260810124916-18521bfa2091`, exact commit
  `18521bfa2091e6ca34f242106002c33184098429`, for RFC 6962/9162 hashing,
  root construction, proof construction, and proof verification;
- `golang.org/x/mod/sumdb/note` `v0.39.0` for independent signed-note
  parsing and Ed25519 verification;
- Go `1.25.12` in CI.

At selection time, the Merkle repository was active and its pinned commit was on
its maintained main branch. Exact module content hashes are locked by
`interop/go/go.sum`; CI downloads dependencies before switching module and checksum
lookups off for execution.

## Frozen vectors

`tests/vectors/transparency-interop-v1.json` freezes:

- seven exact leaves, including a canonical synthetic receipt leaf, an empty leaf,
  UTF-8, binary/NUL, and non-block-sized data;
- every leaf hash and roots for sizes 0 through 7;
- inclusion proofs for every leaf at non-power-of-two sizes 3, 5, and 7, plus size 1;
- consistency proofs for selected growth endpoints through size 7;
- a seven-leaf C2SP signed-note checkpoint and verifier key.

`scripts/generate_transparency_interop_vectors.py --check` proves the checked-in
fixture still matches Filiolae. The Go test independently computes leaf hashes and
roots, independently constructs every frozen proof, verifies every Python proof,
and verifies the checkpoint through `sumdb/note`. Python then consumes the same
frozen bytes and verifies every Go-compared value in the opposite direction.

## Negative and bounded fuzz validation

Both languages reject single-bit changes to proofs and the signed checkpoint.
Python runs a deterministic 512-case parser mutation corpus plus proof mutations.
The Go harness retains fuzz targets for the independent inclusion verifier and
signed-note parser. A bounded local run with one worker completed more than 20,000
inclusion-verifier executions and more than 90,000 signed-note parser executions
without a crash or false acceptance. CI repeats a two-second, one-worker smoke for
each fuzz target.

## Reproduction

```bash
uv run python scripts/generate_transparency_interop_vectors.py --check
uv run pytest tests/test_transparency.py tests/test_transparency_interop.py

cd interop/go
go mod download
GOPROXY=off GOSUMDB=off GOMAXPROCS=2 go test ./...
GOPROXY=off GOSUMDB=off GOMAXPROCS=2 \
  go test -run='^$' -fuzz='^FuzzIndependentInclusionVerifier$' -fuzztime=3s -parallel=1
GOPROXY=off GOSUMDB=off GOMAXPROCS=2 \
  go test -run='^$' -fuzz='^FuzzIndependentSignedNoteParser$' -fuzztime=3s -parallel=1
```

S1 establishes byte-level interoperability, not independent operation, trusted
time, witness observation, public retention, or non-equivocation across clients.
Those claims remain outside the current boundary.
