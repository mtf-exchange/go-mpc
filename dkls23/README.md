# DKLS23 — Threshold ECDSA on secp256k1

Implementation of **"Threshold ECDSA in Three Rounds"** (Doerner, Kondi, Lee, shelat — IEEE S&P 2024).
Paper: https://eprint.iacr.org/2023/765.pdf

---

## File overview

| File | Protocol component | Paper |
|---|---|---|
| `params.go` | Security constants; gadget vector; `condUint32` branchless helper; `scalarInverse` (Fermat); domain separation tags | §8 |
| `commitment.go` | **FCom** (SHA-256 hash commitment); **FZero** (pairwise zero-sharing) | §3.1 |
| `ot.go` | **Masny-Rindal base OT** over secp256k1; `sampleScalar`; scalar/point helpers | §5.1 |
| `ot_extension.go` | **IKNP OT extension** realizing FEOTE(Zq^{l+rho}, xi=416) via SHAKE-256 PRG | §5.1 |
| `vole.go` | **RVOLE** (Protocol 5.2) — Fiat-Shamir proof, Bob verification, constant-time mu check | §5 |
| `dkg.go` | **Relaxed KeyGen** (Protocol 7.1) — Feldman VSS, Lagrange coefficients, input validation | §7 |
| `sign.go` | **Threshold ECDSA** (Protocol 3.6) — 3-round signing, VOLE multiplication, consistency checks, blacklisting | §3 |
| `refresh.go` | **Proactive refresh** (KMOS21) — re-randomizes shares, VOLE correlations, FZero seeds | |
| `persistence.go` | JSON serialization and pluggable encrypted storage for `SignerSetup` | |
| `encoding.go` | Custom JSON marshaling for all protocol message types | |
| `setup_messages.go` | Wire types for base OT, OT extension, and FZero setup messages | |
| `errors.go` | Typed errors: `CheatingPartyError`, `InvalidInputError`, `CorruptStateError`, `BlacklistedPartyError` | |

---

## Security parameters

| Parameter | Value | Meaning |
|---|---|---|
| kappa | 256 | Bit-length of secp256k1 order |
| lambda_c | 128 | Computational security parameter |
| lambda_s | 80 | Statistical security parameter |
| Xi | 416 | OT instances per VOLE (kappa + 2*lambda_s) |
| Rho | 2 | VOLE check elements (ceil(kappa/lambda_c)) |
| Ell | 2 | VOLE inputs per signing session: {r_i, sk_i} |
| SaltLen | 32 bytes | FCom commitment salt (2*lambda_c / 8) |

---

## Dependencies

- `github.com/btcsuite/btcd/btcec/v2` — secp256k1 curve arithmetic (constant-time `ModNScalar`)
- `golang.org/x/crypto/sha3` — SHAKE-256 (PRG expansion, Fiat-Shamir)
- Standard library: `crypto/rand`, `crypto/sha256`, `crypto/subtle`, `math/big` (public hash reduction only)
