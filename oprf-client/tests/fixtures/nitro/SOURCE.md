# Nitro attestation document fixtures

Two real AWS Nitro Enclaves attestation documents (COSE_Sign1, ES384), used
by the tests in `oprf-client/src/attestation/document.rs`.

- Origin: <https://github.com/evervault/attestation-doc-validation>
- Commit: `a296a77c2b23fef8214131287423fe47c755eb3c`
- License: Apache-2.0 (`LICENSE` at that commit)
- Fetched with
  `gh api 'repos/evervault/attestation-doc-validation/contents/<path>?ref=a296a77c2b23fef8214131287423fe47c755eb3c' --jq .content | base64 -d`

| File | Upstream path | SHA-256 |
|---|---|---|
| `valid-attestation-doc-bytes` | `test-data/beta/valid-attestation-doc-bytes` | `a72552688ab6de06b9039ebda2bd5ae9285860ec886f841da94351681dfb3eb6` |
| `debug-mode-attestation-doc-bytes` | `test-data/beta/debug-mode-attestation-doc-bytes` | `46591b92f9abefaace22a6d7ea4ca9c7007dfdbe788fbe8634b230ec2043a789` |

Facts the tests rely on (read from the payloads):

- `valid-attestation-doc-bytes` (production mode): PCR0
  `f4d48b81a460c9916d1e685119074bf24660afd3e34fae9fca0a0d28d9d5599936332687e6f66fc890ac8cf150142d8b`,
  timestamp `1665651482136` (2022-10-13T08:58:02.136Z), nonce 256 bytes,
  `user_data` null.
- `debug-mode-attestation-doc-bytes` (debug mode): PCR0 all zero (48 zero
  bytes).
- Both: untagged COSE_Sign1 array, protected header `{1: -35}`,
  `cabundle[0]` is the AWS Nitro Enclaves Root G1 bundled as
  `oprf-client/src/attestation/aws-nitro-enclaves-root-g1.der` (SHA-256
  `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`).
