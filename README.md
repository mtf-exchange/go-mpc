# go-mpc — Threshold Signing Protocols for Go

[![CI](https://github.com/chrisalmeida/go-mpc/actions/workflows/ci.yml/badge.svg)](https://github.com/chrisalmeida/go-mpc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/chrisalmeida/go-mpc.svg)](https://pkg.go.dev/github.com/chrisalmeida/go-mpc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Go library for **multi-party computation (MPC)** threshold signing protocols. Implements **DKLS23 threshold ECDSA** over secp256k1 and **FROST threshold Schnorr** over Ed25519. Build MPC wallets, distributed custody systems, and threshold signing infrastructure for Bitcoin, Ethereum, Solana, and other blockchains.

## Protocols

| Protocol | Curve | Signature | Rounds | Status |
|---|---|---|---|---|
| **[DKLS23](dkls23/)** | secp256k1 | ECDSA | 3 | Available |
| **[FROST](frost/)** | Ed25519 | Schnorr (EdDSA) | 2 | Available |

### DKLS23 — Threshold ECDSA over secp256k1

Implementation of the [DKLS23 protocol](https://eprint.iacr.org/2023/765) (Doerner, Kondi, Lee, shelat — IEEE S&P 2024). Three signing rounds, no trusted dealer, constant-time cryptographic operations.

**Features:**
- **Distributed Key Generation (DKG)** — Feldman VSS with no trusted dealer
- **3-Round Threshold Signing** — the most round-efficient threshold ECDSA available
- **Flexible t-of-n** — 2-of-3, 3-of-5, or any threshold configuration
- **Key Share Refresh** — proactive share rotation without changing the public key (KMOS21)
- **Cheating Detection** — cryptographic verification with party blacklisting
- **Constant-Time Crypto** — branchless scalar arithmetic, branchless VOLE operations, Fermat's little theorem inversion
- **Encrypted Persistence** — pluggable encryption for key share storage

**Quick start:**

```bash
go get github.com/chrisalmeida/go-mpc
```

```go
import "github.com/chrisalmeida/go-mpc/dkls23"

// 1. Distributed Key Generation (each party runs independently)
config := dkls23.DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 2}
round1Out, coeffs, _ := dkls23.DKGRound1(config)

// 2. Exchange round 1 messages, run round 2, finalize → get share + public key
// 3. Run pairwise VOLE + FZero setup (one-time per party pair)
// 4. Sign: SignRound1 → SignRound2 → SignRound3 → SignCombine → standard ECDSA (r, s)
```

See [example/dkls23/](example/dkls23/) for a complete runnable 3-of-3 flow — DKG, pairwise setup, signing, verification, and key refresh:

```bash
cd example/dkls23 && go run .
```

### FROST — Threshold Schnorr over Ed25519

Implementation of [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) (FROST: Flexible Round-Optimized Schnorr Threshold Signatures) using the FROST(Ed25519, SHA-512) ciphersuite. Two signing rounds, no trusted dealer, signatures compatible with standard Ed25519 verification (RFC 8032).

**Features:**
- **Distributed Key Generation (DKG)** — Feldman VSS with no trusted dealer (2 rounds)
- **2-Round Threshold Signing** — Schnorr's linearity means no OT or VOLE needed
- **Flexible t-of-n** — 2-of-3, 3-of-5, or any threshold configuration
- **RFC 8032 Compatible** — FROST signatures verify with `crypto/ed25519.Verify`
- **Identifiable Abort** — individual signature shares are verified, misbehaving signers are identified
- **Key Share Refresh** — proactive share rotation without changing the public key
- **Hedged Nonce Generation** — RFC 9591 `nonce_generate` mixes CSPRNG with secret key
- **Cofactored Verification** — `[8]zB == [8](R + [c]PK)` per RFC 9591 Section 6.5
- **Encrypted Persistence** — pluggable encryption for key share storage

**Quick start:**

```go
import "github.com/chrisalmeida/go-mpc/frost"

// 1. Distributed Key Generation (each party runs independently)
config := frost.DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 2}
round1Out, coeffs, _ := frost.DKGRound1(config)

// 2. Exchange round 1 messages, run round 2, finalize → get KeyShare + public key
// 3. Sign: SignRound1 → SignRound2 → Aggregate → standard Ed25519 signature (R, z)
// 4. Verify: frost.Verify(pk, msg, sig) or crypto/ed25519.Verify(pk, msg, sig.Bytes())
```

See [example/frost/](example/frost/) for a runnable 2-of-3 flow — DKG, key refresh, signing with all subsets, and verification:

```bash
cd example/frost && go run .
```

## Use Cases

- **MPC wallets** — threshold-sign Bitcoin (ECDSA), Ethereum (ECDSA), and Solana (Ed25519) transactions without exposing private keys
- **Institutional custody** — distribute signing authority across servers, HSMs, or organizations
- **Cross-chain bridges** — secure bridge operators with threshold key management
- **Smart contract governance** — multi-party approval for on-chain operations
- **Validator key management** — protect Ed25519 validator keys for proof-of-stake networks

## Project Structure

```
dkls23/              Threshold ECDSA (secp256k1)
  dkg.go             Distributed key generation (Feldman VSS)
  sign.go            3-round threshold signing
  refresh.go         Proactive key share refresh (KMOS21)
  vole.go            Vector OLE
  ot.go              Masny-Rindal base oblivious transfer
  ot_extension.go    IKNP OT extension
  commitment.go      FCom / FZero primitives
  persistence.go     Encrypted key share serialization
  params.go          Security parameters and constants
frost/               Threshold Schnorr / Ed25519 (RFC 9591)
  keygen.go          Distributed key generation (Feldman VSS)
  sign.go            2-round threshold signing + aggregation
  refresh.go         Proactive key share refresh
  verify.go          Cofactored Ed25519 verification
  hash.go            H1-H5 domain-separated hash functions
  encoding.go        Wire format JSON marshaling
  persistence.go     Encrypted key share serialization
  errors.go          Typed error categories
  params.go          Ciphersuite constants
example/
  shared/            AES-256-GCM encryptor (shared by both demos)
  dkls23/            Complete 3-of-3 DKLS23 demo
  frost/             Complete 2-of-3 FROST demo
```

## Development

```bash
make test          # run all tests
make test-race     # run with race detector (what CI runs)
make bench         # benchmarks
make lint          # go vet + staticcheck
make ci            # full CI pipeline locally
```

## Security

All secret scalar operations are constant-time across both packages. No `math/big` arithmetic on secret data. dkls23 uses branchless VOLE Beta selection; frost uses `filippo.io/edwards25519` constant-time scalar arithmetic. Both use Fermat's little theorem for modular inversion.

Both packages have been audited by Claude Code (Anthropic Claude Opus 4.6) — covering source review, protocol equation-by-equation verification against the DKLS23 paper and RFC 9591, compiler output disassembly, escape analysis, fuzz testing, and dependency vulnerability scanning. 14 total findings across both packages were identified and resolved. See [AUDIT.md](AUDIT.md) for the full report.

See [SECURITY.md](SECURITY.md) for the threat model, constant-time guarantees, known limitations, and responsible disclosure process.

An independent third-party audit by a firm specializing in MPC protocols is recommended before production deployment with real assets.

## Authors

Co-authored by [Chris Almeida](https://github.com/chrisalmeida) and [Claude Code](https://claude.ai/code) (Anthropic Claude Opus 4.6).

## References

- Doerner, Kondi, Lee, shelat. "Threshold ECDSA in Three Rounds." IEEE S&P 2024. [ePrint 2023/765](https://eprint.iacr.org/2023/765)
- Kondi, Magri, Orlandi, Shlomovits. "Refresh When You Wake Up." IEEE S&P 2021. [ePrint 2019/1328](https://eprint.iacr.org/2019/1328)
- Connolly, Komlo, Goldberg, Wood. "Two-Round Threshold Schnorr Signatures with FROST." IETF RFC 9591, June 2024. [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
