# External preservation-package checksum anchor

These checksum files describe the complete MSP360 upload/restore directory prepared after Git commit
`a6a5ea823110adbf343f922c3275e36704bf96de`. The package itself contains the approximately 12 GB
evidence archives and is intentionally not tracked by Git.

The SHA-256 of `PACKAGE-SHA256SUMS` is:

`deec38be4eb295aa6594732bfb92a9a00b5e50f19d4e8ec903655e3699aca50c`

The full package includes a complete Git bundle through `a6a5ea8`; this later Git commit anchors the
package checksum but is intentionally not added back into that bundle, avoiding a recursive package
hash. After an AWS or B2 restore, verify the restored package's own copies of these files before
checking every listed file.
