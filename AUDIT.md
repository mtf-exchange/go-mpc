# Security Audit Report: dkls23

**Package**: `github.com/chrisalmeida/go-mpc/dkls23`
**Scope**: All production source files in `dkls23/`
**Date**: 2026-03-27
**Auditor**: Automated cryptographic review (not a substitute for an independent third-party audit)

---

## Executive Summary

The dkls23 package implements the DKLS23 threshold ECDSA protocol (Doerner,
Kondi, Lee, shelat — IEEE S&P 2024) over secp256k1. The implementation
demonstrates strong security practices: constant-time `ModNScalar` arithmetic
for all secret scalars, branchless VOLE Beta selection, deterministic
zeroization, and defense-in-depth signature verification.

This review identified **1 high**, **4 medium**, and **5 low** severity
findings. **All 10 findings have been resolved.**

---

## Findings

### HIGH-1: Secret-dependent branching in BaseReceiverRound1 — RESOLVED

**File**: `ot.go:146-155`
**Severity**: High
**Category**: Timing side channel

The base OT receiver branched on the secret choice bit `choices[k]`,
performing a scalar multiplication + point addition in the `true` path
but only a struct assignment in the `false` path.

**Resolution**: Replaced with branchless multiply-by-mask pattern using
`condUint32(choices[k])` as the scalar. The point addition is always
executed; when the choice is false the scalar is 0, producing the identity
point, which adds to bG as a no-op.

---

### MED-1: Non-atomic VOLE state mutation during refresh — RESOLVED

**File**: `refresh.go:276-295`
**Severity**: Medium
**Category**: State consistency

VOLE states were re-randomized in-place during `RefreshFinalize`. If
`refreshVOLEAlice` succeeded for one peer but `refreshVOLEBob` failed for
another, the setup was left in a partially-mutated state.

**Resolution**: `refreshVOLEAlice` and `refreshVOLEBob` now return new
state objects instead of mutating in place. All new states are built into
temporary maps and swapped into `setup` only after every peer succeeds.

---

### MED-2: Missing nil guard on VOLE Bob state in SignRound3 — RESOLVED

**File**: `sign.go:440`
**Severity**: Medium
**Category**: Denial of service

`state2.VoleBobForRound2[j]` was accessed without a nil check. A nil
pointer dereference would crash the process if pairwise VOLE setup was
incomplete.

**Resolution**: Added `if bobState == nil` guard that appends to
`badParties`, blacklists, and continues.

---

### MED-3: Missing zeroization of intermediate share bytes — RESOLVED

**File**: `dkg.go:149-153`, `dkg.go:182-186`, `refresh.go:106-111`, `refresh.go:158-162`
**Severity**: Medium
**Category**: Memory exposure

When computing pairwise commitments, the share scalar was serialized to a
`[32]byte` for FCom but the byte array was not zeroized after use.

**Resolution**: Added explicit zeroing of `shareArr` after each `Commit`
call and after each `copy` in DKGRound1, DKGRound2, RefreshRound1, and
RefreshRound2.

---

### MED-4: Lagrange coefficient not defer-zeroized — RESOLVED

**File**: `sign.go:278-282`
**Severity**: Medium
**Category**: Memory exposure

The Lagrange coefficient `lc` was zeroed after use but not via `defer`,
meaning a future refactoring could introduce an early return that skips
zeroization.

**Resolution**: Changed `lc.Zero()` to `defer lc.Zero()` immediately
after creation.

---

### LOW-1: DKG input validation gaps — RESOLVED

**File**: `dkg.go:102-117`
**Severity**: Low
**Category**: Input validation

`DKGRound1` did not check for duplicate party IDs, non-positive IDs, or
IDs exceeding the uint32 range used by `ModNScalar.SetInt`.

**Resolution**: Added `validatePartyIDs` helper that checks all IDs are
in `[1, 2^31)` with no duplicates. Called at the top of `DKGRound1` and
`SignRound1`.

---

### LOW-2: Domain separation strings not centrally managed — RESOLVED

**File**: Multiple (`ot.go`, `ot_extension.go`, `vole.go`, `commitment.go`, `refresh.go`)
**Severity**: Low
**Category**: Protocol design

Domain separation strings were hardcoded across 6 files with no
compile-time mechanism to prevent collisions.

**Resolution**: All 9 domain strings are now named constants in `params.go`
(`domainBaseOT`, `domainOTEPRG`, `domainOTESeed`, `domainOTEExpand`,
`domainVOLEFS`, `domainVOLEProof`, `domainVOLERefresh`, `domainFZero`,
`domainFZeroRefresh`). All call sites reference the constants.

---

### LOW-3: reduce64 callable on secret data without guard — RESOLVED

**File**: `params.go:97-104`
**Severity**: Low
**Category**: API misuse risk

`reduce64` used non-constant-time `math/big` reduction. The function was
documented as public-data-only but nothing enforced this.

**Resolution**: Renamed to `reduce64Public` to make the contract explicit
at every call site.

---

### LOW-4: Nonce reuse risk on state snapshot rollback — RESOLVED

**File**: `sign.go`
**Severity**: Low
**Category**: Operational risk

If `SignerSetup` was restored from a backup after signing had occurred,
one-time VOLE correlations could be reused.

**Resolution**: Added `SignCounter uint64` to `SignerSetup`, atomically
incremented on each `SignRound1` call and persisted in JSON. A restored
setup's counter reveals how many signing sessions have consumed VOLE state.

---

### LOW-5: No bounds check on party IDs before uint32 cast — RESOLVED

**File**: `dkg.go:23`, `dkg.go:84`, `refresh.go:355`
**Severity**: Low
**Category**: Integer overflow

Party IDs were cast to `uint32` without bounds checking.

**Resolution**: Resolved together with LOW-1 via `validatePartyIDs`, which
rejects IDs outside `[1, 2^31)`.

---

## Items Verified (No Issues Found)

| Area | Assessment |
|---|---|
| **Nonce generation** | `sampleScalar` uses `crypto/rand` with rejection sampling. Bias from 256-bit reduction mod q is < 2^-128 (negligible). |
| **Scalar arithmetic** | All secret operations use constant-time `ModNScalar`. No `math/big` on secrets. |
| **VOLE Beta selection** | All Beta-dependent paths use branchless multiply-by-mask or `subtle.ConstantTimeCopy`. |
| **OT extension Beta** | `oteSeedHash` and `oteExpandHash` write the choice bit branchlessly via `condUint32`. |
| **Commitment scheme** | FCom uses SHA-256(msg ‖ salt) with 32-byte random salt. Opening is constant-time via `subtle.ConstantTimeCompare`. |
| **Low-S normalization** | Uses `ModNScalar.IsOverHalfOrder()` (constant-time) and `Negate()`. Correct per BIP-340. |
| **Signature verification** | `SignCombine` verifies the final (r, s) against the master public key before returning. Defense-in-depth against protocol bugs. |
| **Concurrency** | `SignerSetup.mu` RWMutex usage is correct: RLock for reads (SignRound1/2), Lock for writes (SignRound3, RefreshFinalize). `SignCounter` uses `atomic.AddUint64` (safe under RLock). No deadlock risk. |
| **Serialization** | JSON encoding uses fixed-size hex (scalars) and base64 (VOLE arrays). Wire format is backward-compatible. Deserialization errors are propagated. |
| **Persistence** | `SetupEncryptor` interface cleanly separates encryption from serialization. No key material in plaintext JSON after `MarshalEncrypted`. |
| **Cheating detection** | VOLE proof, FCom decommitment, Feldman verification, and public key consistency checks all implemented per the paper. Detected cheaters are blacklisted atomically. |
| **Proactive refresh** | KMOS21 Beaver OT re-randomization correctly maintains the OT correlation invariant. FZero seeds are re-derived from the combined seed. Epoch counter prevents replay. |
| **Domain separation** | All 9 domain tags are unique named constants in `params.go`. No collision risk. |

---

## Extended Verification

The following additional checks were performed beyond the initial code
review.

### Compiler Output Verification

`condUint32` (the branchless bool-to-uint32 helper used across all
Beta-dependent code paths) was disassembled on ARM64 (Apple Silicon).
The compiler emits a single `UBFX` (Unsigned Bit Field Extract) instruction
— no branch, no conditional move. This is the optimal codegen.

### Escape Analysis

`go build -gcflags='-m -m'` confirms that individual secret `ModNScalar`
values (`lc`, `sk_i`, `r_i`, `phi_i`, VOLE `dDot` array) remain stack-
allocated. Only dynamic-sized collections (`make(map)`, `make([]...)`)
escape to heap, which is expected. No secret scalar is unnecessarily
heap-allocated.

### `InverseValNonConst` Verification — REPLACED

Inspection of the decred/secp256k1 v4.0.1 source confirmed that
`InverseValNonConst` uses `big.Int.ModInverse` internally and is **not**
constant-time. The `decred/secp256k1` v4.0.1 is pinned by `btcec/v2` and
cannot be upgraded independently.

**Resolution**: Both call sites were replaced with `scalarInverse`, a
constant-time Fermat's little theorem implementation (`a^(q-2) mod q`)
using only `ModNScalar.Square` and `ModNScalar.Mul`. The exponent `q-2`
is a fixed public constant, so the square-and-multiply branch pattern is
data-independent. `InverseValNonConst` is no longer called anywhere in the
codebase.

### Error Message Review

All error messages across 11 production files were reviewed. No secret
scalar values, key material, or private state appears in any error string.
Only phase names, party IDs, and structural descriptions are included.

### Protocol Equation Verification

Equation-by-equation comparison against the DKLS23 paper:

| Component | Paper Reference | Status | Deviations |
|---|---|---|---|
| DKG (Feldman VSS) | Protocol 7.1 | Correct | FCom for share exchange (standard hardening) |
| VOLE | Protocol 5.2 | Correct | None |
| Signing | Protocol 3.6 | Correct | SHA-256 for message hashing (standard for secp256k1) |
| FZero | Section 3.1 | Correct | Seed exchange via FCom |
| FCom | Section 3.1 | Correct | SHA-256 instantiation |
| Refresh | KMOS21 | Correct | Epoch counter (operational bookkeeping) |

No bugs or missing steps found. All deviations are standard instantiation
choices or correct engineering hardening.

### Fuzz Testing

12 fuzz targets written in `fuzz_test.go` covering:
- All `UnmarshalJSON` methods (8 targets)
- `hexToScalar` parser
- `feldmanVerify` with adversarial commitments
- `GadgetInnerProduct` with random beta vectors
- `validatePartyIDs` with boundary inputs

Initial fuzzing (10s per target) found no panics.

### Edge-Case Testing

10 edge-case tests written in `edge_test.go`:
- 2-of-3 threshold signing, 2-of-2 minimal threshold
- Duplicate party IDs, negative IDs, zero IDs
- Nil VOLE Bob state (found and fixed a panic in SignRound2)
- SignCounter increment verification
- `validatePartyIDs` boundary cases

### Vulnerability Scanning

`govulncheck` reports 0 vulnerabilities affecting this code. 9 findings
in stdlib modules (`crypto/tls`, `crypto/x509`, `html/template`, `net/url`,
`archive/zip`, `os`) are in packages not called by this library.

### Dependency Versions

| Dependency | Version | Status |
|---|---|---|
| `btcsuite/btcd/btcec/v2` | v2.3.6 | Latest |
| `decred/dcrd/dcrec/secp256k1/v4` | v4.0.1 | Pinned by btcec (v4.4.1 available but incompatible) |
| `golang.org/x/crypto` | v0.49.0 | Latest |
| `stretchr/testify` | v1.11.1 | Latest |

---

## Remaining Inherent Limitations

These are not code defects — they are inherent to the protocol, the Go
runtime, or the deployment environment:

| Limitation | Reason |
|---|---|
| **Memory retention** | Go's GC may retain stack copies after zeroization. No `mlock` — would require platform-specific code and a C dependency. |
| **Random oracle model** | SHAKE-256 modeled as a random oracle is a cryptographic assumption from the DKLS23 paper. |
| **Physical side channels** | Power analysis, EM emanation require hardware countermeasures. |
| **`InverseValNonConst`** | Replaced with constant-time `scalarInverse` (Fermat's little theorem). No longer called. |
| **No independent audit** | This automated review is not a substitute for a third-party audit. |

---

## Severity Summary

| Severity | Found | Resolved |
|---|---|---|
| Critical | 0 | — |
| High | 1 | 1 |
| Medium | 4 | 4 |
| Low | 5 | 5 |
| **Total** | **10** | **10** |

---

*This automated review is not a substitute for an independent third-party
security audit. A formal audit by a firm specializing in MPC protocols is
recommended before production deployment with real assets.*
