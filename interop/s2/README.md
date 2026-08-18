# Tessera loopback shadow laboratory (S2)

This Go module pins Tessera `v1.0.4` and contains the bounded S2 components:

- `cmd/personality`: strict synthetic Filiolae receipt personality over Tessera POSIX storage;
- `cmd/monitor-go`: independent complete-mirror monitor using Transparency.Dev Merkle/tile clients;
- `cmd/keygen`: ephemeral synthetic signed-note key generator; and
- `internal/s2leaf`: bounded canonical leaf and Ed25519 receipt validation.

The Python monitor, synthetic fixture generator, fault shim, and coordinator are in `scripts/`.
The accepted procedure and result are documented in `docs/tessera-loopback-shadow-plan.md` and
`docs/tessera-loopback-shadow-acceptance.md`.

This is test infrastructure, not a persistent service. The personality has no configurable listen
address and binds only `tcp4` `127.0.0.1:0`. It accepts only the checked-in synthetic trust fixture.
Do not adapt it to production receipts or external interfaces without a new architecture/security
review and authorization.

After fetching exact locked modules, offline validation is:

```bash
GOPROXY=off GOSUMDB=off GOMAXPROCS=2 GOFLAGS=-p=1 go mod verify
env GOPROXY=off GOSUMDB=off GOMAXPROCS=2 GOFLAGS=-p=1 go test ./...
```
