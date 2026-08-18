# r18 two-A6000 acceptance evidence index

This directory anchors the small, machine-readable preservation metadata in Git. The approximately
12 GB happy/tamper evidence archives and the immutable payload are intentionally **not** stored in
Git or Git LFS. Their exact sizes and SHA-256 values are recorded in `manifest.json` and
`SHA256SUMS`.

The bounded acceptance result and non-claims are documented in
[`../../../docs/live-two-gpu-acceptance.md`](../../../docs/live-two-gpu-acceptance.md). The complete
external MSP360 upload directory is anchored by [`preservation-package/`](preservation-package/).
Restore is successful only after the recovered files pass the package and core checksum sets and the
happy/tamper audit and anchor checks described there. Object-store retention configuration is outside
this repository.
