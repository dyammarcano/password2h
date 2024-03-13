package password2h

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewArgon2idHash(t *testing.T) {
	argon2IDHash := NewArgon2idHashDefault()

	hash := argon2IDHash.HashPassword("supersecret")
	assert.NotEmpty(t, hash)

	wrapHash := argon2IDHash.WrapPassword(hash)
	assert.NotEmpty(t, wrapHash)

	assert.True(t, argon2IDHash.CompareHashAndPassword(wrapHash, "supersecret"))
}
