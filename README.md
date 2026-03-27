# go-mpc — Threshold Signing Protocols for Go (DKLS23, ECDSA, secp256k1)

[![CI](https://github.com/chrisalmeida/go-mpc/actions/workflows/ci.yml/badge.svg)](https://github.com/chrisalmeida/go-mpc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/chrisalmeida/go-mpc.svg)](https://pkg.go.dev/github.com/chrisalmeida/go-mpc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Go library for **multi-party computation (MPC)** threshold signing protocols. Currently implements **DKLS23 threshold ECDSA** over secp256k1. Build MPC wallets, distributed custody systems, and threshold signing infrastructure for Bitcoin, Ethereum, Solana, and other blockchains.

## Protocols

| Protocol | Curve | Signature | Rounds | Status |
|---|---|---|---|---|
| **[DKLS23](dkls23/)** | secp256k1 | ECDSA | 3 | Available |
| FROST | ed25519 | Schnorr | 2 | Planned |

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

See [example/](example/) for a complete runnable 3-of-3 flow — DKG, pairwise setup, signing, verification, and key refresh:

```bash
cd example && go run .
```

## Use Cases

- **MPC wallets** — threshold-sign Bitcoin, Ethereum, and Solana transactions without exposing private keys
- **Institutional custody** — distribute signing authority across servers, HSMs, or organizations
- **Cross-chain bridges** — secure bridge operators with threshold key management
- **Smart contract governance** — multi-party approval for on-chain operations

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
example/             Complete 3-of-3 demo
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

All secret scalar operations are constant-time. No `math/big` arithmetic on secret data. Branchless VOLE Beta selection. Constant-time modular inversion via Fermat's little theorem. Verified at the assembly level.

This implementation has been audited by Claude Code (Anthropic Claude Opus 4.6) — covering source review, protocol equation-by-equation verification against the DKLS23 paper, compiler output disassembly, escape analysis, fuzz testing, and dependency vulnerability scanning. All 10 findings were resolved. See [AUDIT.md](AUDIT.md) for the full report.

See [SECURITY.md](SECURITY.md) for the threat model, constant-time guarantees, known limitations, and responsible disclosure process.

An independent third-party audit by a firm specializing in MPC protocols is recommended before production deployment with real assets.

## Authors

Co-authored by [Chris Almeida](https://github.com/chrisalmeida) and [Claude Code](https://claude.ai/code) (Anthropic Claude Opus 4.6).

## References

- Doerner, Kondi, Lee, shelat. "Threshold ECDSA in Three Rounds." IEEE S&P 2024. [ePrint 2023/765](https://eprint.iacr.org/2023/765)
- Kondi, Magri, Orlandi, Shlomovits. "Refresh When You Wake Up." IEEE S&P 2021. [ePrint 2019/1328](https://eprint.iacr.org/2019/1328)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
