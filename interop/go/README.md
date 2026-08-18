# Offline transparency interoperability harness

This module independently validates the frozen synthetic vectors in
`tests/vectors/transparency-interop-v1.json` using maintained Go ecosystem
implementations:

- `github.com/transparency-dev/merkle` for RFC 6962/9162 hashing and proofs;
- `golang.org/x/mod/sumdb/note` for C2SP-compatible signed-note verification.

The dependencies are exactly pinned in `go.mod`/`go.sum`. The harness performs
no network I/O at runtime and contains no production receipt, key, or secret.
From this directory, run `go test ./...`. The repository CI fetches modules and
then executes the same offline tests.
