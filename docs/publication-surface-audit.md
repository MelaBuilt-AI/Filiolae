# Public-preview surface audit

Status: **accepted pre-publication surface audit; live visibility and post-open checks are verified separately from GitHub**

Date: 2026-08-17

## Publication topology

The evidence-bearing development repository and its historical private Actions runs remain private.
The public preview is built as a **fresh-history export of one reviewed tree**, not by changing the
visibility of the development history. This prevents old working paths, deleted material, private run
logs/artifacts, and operational refs from becoming public merely because current `main` is clean.

The destination source tree may identify old private run numbers and tested commits as provenance,
but it does not link to or claim public access to the private workflow records. Repository-retained
sanitized evidence remains independently hashable.

## Included surface

Only regular files and intentional executable bits from the frozen Git tree are exported. The preview
includes source, tests, locked dependencies, examples, deployment/operations references, sanitized
bounded evidence, threat/claim documentation, licenses, citation, and workflows.

The preview excludes:

- the development repository's `.git` history, refs, reflogs, private Actions logs/artifacts, and remote
  administration metadata;
- untracked/ignored `.venv`, `.demo`, caches, build output, local control directories, credentials,
  runtime state, and private vault content;
- accepted Priority 6 v2 candidate bytes and readiness/final suite plaintext;
- full external evidence archives, provider credentials, private signing keys, and recovery secrets;
- any account, service, package-index, release, announcement, or live deployment side effect.

## Audit performed

The candidate tree was checked with the release preflight and direct inventory review:

1. Enumerated every tracked file, MIME class, size, and executable/symlink mode.
2. Scanned all tracked textual bytes for private machine markers and common GitHub/OpenAI/AWS/private-
   key forms; no matching secret or prohibited current path was found.
3. Enumerated binary material: one retained gzip archive, five JPEG evidence screenshots, and synthetic
   transparency tile/mirror bytes. No model-weight package or private key exists in the tree.
4. Opened all five JPEGs: they show generic MSP360 plan/restore-verifier evidence, no account ID,
   bucket name, credential, personal name, username, email, or hidden window. JPEG EXIF maps are empty.
5. Parsed all 567 members of the retained native-systemd archive: no absolute/traversal path, unsafe
   member, or exact secret pattern was found. Its `/home/runner`-class hosted paths and generic
   `human:owner` actor labels are evidence semantics, not local personal identifiers.
6. Reviewed CSV/provider reports for filenames, paths, account/bucket identifiers, errors, and
   credentials. They contain project-only `D:\Filiolae...` paths and no personal/profile path.
7. Audited every reachable development-history blob before choosing fresh-history publication. No
   common credential/private-key pattern was found; four superseded blobs contain generic local machine
   paths, which is why development history remains private rather than being waived into scope.
8. Rechecked that Priority 6 v2 tracked material contains commitments, generators/training data,
   synthetic fixtures, reports, and hashes—but not accepted candidate weights or readiness/final
   plaintext. The consumed campaign remains closed.


## Owner-label publication normalization

Before public visibility, the publication tree normalized every case-insensitive textual occurrence of
the Owner's personal name to the role label `Owner`, including narrative documentation, documentation-
like evidence metadata, and dependent test expectations. The private development archive preserves the
original historical bytes. No model output, signed receipt, provider report/image, key, score, Ledger,
or executable governance behavior was changed. Checksum inventories covering edited README/metadata
bytes were regenerated and remain mechanically verifiable.

For auditability, the affected `SHA256SUMS` file digests changed only in the public export as follows:

| Public evidence directory | Private canonical digest | Owner-normalized public digest |
|---|---|---|
| `candidate-eval-stage2-posthoc-replay-20260813` | `494034eaf0420632884eac91b5ef8d306509c1bc2bde74c73f6ab92f7482da5c` | `a38551fb45ccaf04d2a8f4d496b0ed4d8da6ba770fc7e89ea3034c45a305077f` |
| `priority-6-v2-aws-object-lock-restore-20260814` | `242d5e43e4ef941f6754293adf8ace277144c336d847b61d019c252b08fbf23d` | `6a32e10cb7e4f94ca54a9c0da3e2bde63272e776062eb69307ed9b6a64cdb76c` |
| `priority-6-v2-closeout-20260814` | `5f4fea46475b42e14dff464e1cf5204bca96efa4f005d9a8f111951f95a89748` | `12ebd47e6e0aafaecd49465b27fe79f0de97369694de005184cdf405714de0b2` |
| `r18-preservation-20260813` | `726b7265aa81f93c29ef63e9e52de1351466777fdfa39c9f3e47ba2b96630188` | `449b00c638178744a53d8d5442057f0e02dd84ca22faa16c1f2f58a0fdcf51e4` |
| `priority-6-v2-gate-d-replacement-pretraining-stop-20260813` | `58458ad78f6c9d7b006eaf96b8dc0b295f5498977bd9bb8ddd46ae940bf41e38` | `69652ec4742356b0b2fdafb55658f53a2fbf26d6faba54ca3f87325c0bf40cd0` |

## Licensing and adoption surface

The software license changed before public visibility from the superseded private Apache candidate to
`AGPL-3.0-only`. The canonical AGPL text SHA-256 is
`d8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee`; the CC BY 4.0 documentation
text SHA-256 is `9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94`.
The prime-rl patch's pinned upstream Apache-2.0 text is separately retained at SHA-256
`f5118b9c9e98b0f4076214ee13f68d5f73c13b077c44544cb9a0c4ed9155065c`.

The commercial-licensing document is policy, not a repository grant or executable agreement. The
public adoption registry is schema-bounded and empty; it contains no customer or personal information.
Commercial listing is mandatory only through a future separately executed agreement, while AGPL
registration is voluntary. The CLA is a non-assignment dual-licensing grant with a recorded acceptance
statement. Qualified review is required before the first external software Contribution is merged or
the first commercial license is executed. No v0.1.0 certification program is active.

## Final gate

At the frozen export, rerun technical/publication preflights, full tests/coverage, lint/format, lock,
deterministic build comparison, Twine, CFF validation, fresh-wheel smoke, archive safety, and exact
file inventory. Record the source commit, tree digest, file count, artifact hashes, private CI URL/run,
and private repository visibility. No visibility change is part of this audit.
