package frost

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorMessages(t *testing.T) {
	t.Parallel()

	cheat := &CheatingPartyError{PartyIDs: []int{2, 3}, Phase: "DKGFinalize", Detail: "bad shares"}
	assert.Contains(t, cheat.Error(), "frost DKGFinalize")
	assert.Contains(t, cheat.Error(), "[2 3]")

	inv := &InvalidInputError{Phase: "SignRound1", Detail: "bad threshold"}
	assert.Contains(t, inv.Error(), "frost SignRound1")
	assert.Contains(t, inv.Error(), "invalid input")

	corrupt := &CorruptStateError{Phase: "SignRound2", Detail: "bad state"}
	assert.Contains(t, corrupt.Error(), "frost SignRound2")
	assert.Contains(t, corrupt.Error(), "corrupt state")

	bl := &BlacklistedPartyError{PartyIDs: []int{5}, Phase: "SignRound1"}
	assert.Contains(t, bl.Error(), "frost SignRound1")
	assert.Contains(t, bl.Error(), "5")
}
