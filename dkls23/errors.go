package dkls23

import (
	"fmt"
	"strings"
)

// Error categories for programmatic handling.
// Callers can use errors.As() to check the category:
//
//	var cheatErr *CheatingPartyError
//	if errors.As(err, &cheatErr) {
//	    // blacklist cheatErr.PartyIDs...
//	}
//
//	var inputErr *InvalidInputError
//	if errors.As(err, &inputErr) {
//	    // caller bug, don't retry
//	}

// CheatingPartyError indicates one or more parties failed verification checks.
// The protocol detected dishonest behaviour (bad Feldman, bad FCom, bad VOLE proof).
// Action: blacklist the listed parties; the protocol can continue without them
// if enough honest parties remain above the threshold.
type CheatingPartyError struct {
	PartyIDs []int
	Phase    string // e.g. "SignRound3", "DKGFinalize", "RefreshFinalize"
	Detail   string
}

func (e *CheatingPartyError) Error() string {
	return fmt.Sprintf("dkls23 %s: cheating detected from parties %v: %s", e.Phase, e.PartyIDs, e.Detail)
}

// InvalidInputError indicates the caller provided invalid arguments.
// This is a programming error — retrying with the same inputs will always fail.
type InvalidInputError struct {
	Phase  string
	Detail string
}

func (e *InvalidInputError) Error() string {
	return fmt.Sprintf("dkls23 %s: invalid input: %s", e.Phase, e.Detail)
}

// CorruptStateError indicates that internal state is inconsistent or corrupted.
// Action: halt the protocol, investigate, and potentially recover from backup.
type CorruptStateError struct {
	Phase  string
	Detail string
}

func (e *CorruptStateError) Error() string {
	return fmt.Sprintf("dkls23 %s: corrupt state: %s", e.Phase, e.Detail)
}

// BlacklistedPartyError indicates an operation was rejected because one or more
// parties in the requested set have been blacklisted for prior cheating.
type BlacklistedPartyError struct {
	PartyIDs []int
	Phase    string
}

func (e *BlacklistedPartyError) Error() string {
	ids := make([]string, len(e.PartyIDs))
	for i, id := range e.PartyIDs {
		ids[i] = fmt.Sprintf("%d", id)
	}
	return fmt.Sprintf("dkls23 %s: blacklisted parties in signer set: [%s]", e.Phase, strings.Join(ids, ", "))
}
