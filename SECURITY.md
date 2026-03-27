# Security

## Threat Model

This library implements a t-of-n threshold ECDSA protocol with honest majority.
The following assumptions apply:

- All parties communicate over authenticated point-to-point channels (e.g., TLS
  or Noise Protocol Framework). The library does **not** provide a transport
  layer — callers must ensure channel authentication and confidentiality.
- The master secret key is never reconstructed in a single location. Each party
  holds only a Shamir secret share.

### Cheating Detection

Cheating parties are detected at multiple protocol stages:

- **VOLE consistency check**: Malicious correlation values are caught via a
  SHAKE-256 proof verified with constant-time comparison
  (`subtle.ConstantTimeCompare`).
- **R-commitment decommitment**: Parties commit to nonce shares in signing
  round 1 and decommit in round 2. Inconsistencies are detected and the
  cheating party is identified.
- **Blacklisting**: Detected cheaters are permanently blacklisted via
  `SignerSetup.Blacklist` and rejected from all future signing sessions.

### Proactive Key Refresh

Key shares can be refreshed without changing the master public key (KMOS21
protocol). This limits the exposure window if a share is compromised:

- Shamir shares are re-randomized using fresh degree-(t-1) polynomials with
  zero constant term.
- VOLE correlations and FZero seeds are refreshed alongside shares.
- Refresh sessions are tracked by epoch to prevent replay.

## Constant-Time Guarantees

All operations on secret values are designed to execute in constant time,
preventing timing side-channel attacks on shared hardware:

- **Scalar arithmetic**: All secret scalar operations (addition, multiplication,
  negation) use btcec's constant-time `ModNScalar`. Modular inversion uses a
  constant-time Fermat's little theorem implementation (`scalarInverse`:
  `a^(q-2) mod q` via square-and-multiply with fixed public exponent).
  No `math/big` arithmetic is performed on secret values.
- **VOLE Beta selection**: Bob's secret binary vector β is never used as a
  branch condition. All β-dependent operations use branchless multiply-by-mask
  (`condUint32(β) * value`) or `subtle.ConstantTimeCopy` for byte selection.
- **Commitment verification**: FCom opening and VOLE proof checks use
  `subtle.ConstantTimeCompare`.
- **Zeroization**: Ephemeral secrets are zeroized via `ModNScalar.Zero()`
  (deterministic, not subject to GC interference).

The only remaining `math/big` usage is `reduce64Public`, which reduces 64-byte
public hash outputs (Fiat-Shamir challenges, FZero hashes) modulo q. These
are derived from public data and are not timing-sensitive.

## Known Limitations

- **Memory retention**: Go's garbage collector may retain copies of
  intermediate stack values after zeroization. No memory pinning or `mlock`
  is used.
- **Random oracle model**: Base OT and Fiat-Shamir proofs use SHAKE-256
  modeled as a random oracle. Commitment opening (FCom) uses SHA-256.
- **Physical attacks**: No protection is provided against physical
  side-channel attacks (power analysis, electromagnetic emanation, etc.).
- **No independent human audit**: This library has been audited by Claude
  Code (Anthropic Claude Opus 4.6), which performed source code
  review, protocol equation verification against the DKLS23 paper, compiler
  output disassembly, escape analysis, fuzz testing, and dependency
  vulnerability scanning. All 10 findings were resolved. The full report is
  in [`AUDIT.md`](AUDIT.md). This is not a substitute for an independent
  third-party audit by a firm specializing in MPC protocols, and the code
  has not been formally verified.

## Responsible Disclosure

If you discover a security vulnerability in this project, please report it
through GitHub Security Advisories (private vulnerability reporting):

<https://github.com/chrisalmeida/go-mpc/security/advisories/new>

Do not open a public issue for security vulnerabilities.

## Dependencies

| Dependency                          | Purpose                                                                               |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| `github.com/btcsuite/btcd/btcec/v2` | secp256k1 curve operations (constant-time scalar arithmetic and point multiplication) |
| `golang.org/x/crypto`               | SHAKE-256 (OT hashing, Fiat-Shamir challenges, VOLE proofs)                           |
| `github.com/stretchr/testify`       | Test assertions only (not used in production code)                                    |
