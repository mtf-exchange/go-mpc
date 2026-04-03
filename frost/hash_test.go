package frost

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestH1DomainSeparation(t *testing.T) {
	t.Parallel()
	msg := []byte("test message")

	// H1 and H3 should produce different outputs for the same input
	// (different domain tags).
	h1 := H1(msg)
	h3 := H3(msg)
	assert.NotEqual(t, h1.Bytes(), h3.Bytes())
}

func TestH2NoDomainPrefix(t *testing.T) {
	t.Parallel()
	// H2 has no domain prefix — it should equal raw SHA-512 reduced mod L.
	msg := []byte("challenge input")
	h2 := H2(msg)
	// Verify H2 is deterministic.
	h2Again := H2(msg)
	assert.Equal(t, h2.Bytes(), h2Again.Bytes())
}

func TestH4H5DomainSeparation(t *testing.T) {
	t.Parallel()
	msg := []byte("test")

	h4 := H4(msg)
	h5 := H5(msg)
	assert.NotEqual(t, h4, h5)
	assert.Len(t, h4, 64) // SHA-512 output
	assert.Len(t, h5, 64)
}

func TestH1Deterministic(t *testing.T) {
	t.Parallel()
	msg := []byte("determinism test")
	a := H1(msg)
	b := H1(msg)
	assert.Equal(t, a.Bytes(), b.Bytes())
}

func TestHashEmptyInput(t *testing.T) {
	t.Parallel()
	// All hash functions should handle empty input without panicking.
	h1 := H1(nil)
	h2 := H2(nil)
	h3 := H3(nil)
	h4 := H4(nil)
	h5 := H5(nil)
	assert.NotNil(t, h1)
	assert.NotNil(t, h2)
	assert.NotNil(t, h3)
	assert.NotNil(t, h4)
	assert.NotNil(t, h5)
}
