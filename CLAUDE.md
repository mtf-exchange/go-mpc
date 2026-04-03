# CLAUDE.md

## Project Overview

DKLS23 threshold ECDSA library in Go. Implements the [DKLS23 paper](https://eprint.iacr.org/2023/765) (Doerner, Kondi, Lee, shelat — IEEE S&P 2024) for multi-party computation over secp256k1.

- **Module**: `github.com/chrisalmeida/go-mpc`
- **Go**: 1.25+

## Build & Test

```bash
make test          # run all tests
make test-race     # run with race detector (what CI runs)
make bench         # run benchmarks
make cover         # show coverage summary
make lint          # go vet + staticcheck
make ci            # full CI pipeline locally
```

Or directly:
```bash
go test ./...
go test -race -timeout 120s ./...
```

## Code Layout

- `dkls23/` — Core protocol package. All cryptographic code lives here.
  - `dkg.go` — Feldman VSS distributed key generation (Protocol 7.1)
  - `sign.go` — 3-round threshold signing (Protocol 3.6)
  - `refresh.go` — Proactive key share refresh (KMOS21)
  - `vole.go` — Vector OLE (Protocol 5.2)
  - `ot.go` / `ot_extension.go` — Base OT and IKNP extension
  - `commitment.go` — FCom and FZero primitives
  - `persistence.go` — AES-256-GCM encrypted serialization
  - `encoding.go` — Wire format JSON marshaling
  - `errors.go` — Typed error categories
  - `params.go` — Security constants and package-level docs
- `frost/` — FROST threshold Schnorr / Ed25519 package (RFC 9591).
  - `keygen.go` — Feldman VSS distributed key generation (2 rounds)
  - `sign.go` — 2-round threshold signing + aggregation
  - `verify.go` — Cofactored Ed25519 verification
  - `hash.go` — H1-H5 domain-separated hash functions
  - `persistence.go` — Encrypted serialization
  - `encoding.go` — Wire format JSON marshaling
  - `errors.go` — Typed error categories
  - `params.go` — Ciphersuite constants and package-level docs
- `example/` — Runnable demos
  - `shared/` — AES-256-GCM encryptor shared by both demos
  - `dkls23/` — 3-of-3 DKLS23 ECDSA demo (`cd example/dkls23 && go run .`)
  - `frost/` — 2-of-3 FROST Ed25519 demo (`cd example/frost && go run .`)
  - Separate `go.mod` with `replace github.com/chrisalmeida/go-mpc => ../`
  - Not included in `go test ./...` — run and test independently

## Conventions

- Error messages: `"dkls23 FunctionName: description"` or `"frost FunctionName: description"`
- Formatting: `gofmt`, `go vet`, `staticcheck` must all pass
- Tests: maintain 90%+ coverage, always run with `-race`
- Dependencies: keep minimal — only add if cryptographically necessary
- Exported types have GoDoc comments referencing paper sections where applicable

## Test Performance

CI runs on resource-constrained GitHub Actions runners where crypto-heavy tests can be 3–5× slower than local. The test suite uses three techniques to stay fast:

1. **Parallel VOLE setup** — `buildSetups()` in `helpers_test.go` runs pairwise VOLE/FZero setup concurrently across goroutines (one per party pair).
2. **Cached 3-of-3 fixture** — `fullSetup(t)` builds the expensive DKG+VOLE setup once via `sync.Once` and deep-copies via JSON for each caller. Use `fullSetup(t)` for any test that needs a standard 3-of-3. Only call `setupSigners(t, ids, threshold)` for non-standard configs (2-of-3, 2-of-2, etc.).
3. **`t.Parallel()`** — All tests that do crypto work (VOLE, OT, signing, refresh) must include `t.Parallel()` so they overlap. This is safe because `fullSetup` returns independent deep copies and `setupSigners`/`buildSetups` create fresh state.

When adding new tests:
- If the test needs a 3-of-3 setup, use `fullSetup(t)` (cached) — **not** `setupSigners(t, []int{1,2,3}, 3)`.
- Add `t.Parallel()` to any test that takes >100ms or calls `fullSetup`/`setupSigners`/`runVOLEPairwise`.
- Never share mutable state between parallel tests; each test should own its setup.

## Security-Sensitive Areas

All code in `dkls23/` is security-critical. Key areas requiring extra care:
- DKG (Feldman VSS commitment verification)
- Signing (nonce generation, consistency checks)
- VOLE/OT (oblivious transfer correctness)
- Key refresh (share re-randomization)
- Persistence (encryption key handling)

Ephemeral secrets (polynomial coefficients, nonce shares, Lagrange coefficients) are zeroized after use.

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on push to `main` and all PRs: `go vet` → `staticcheck` → `go test -race` → coverage summary. Reproduce locally with `make ci`.
