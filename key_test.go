package pbkdf2

import (
	"crypto/sha256"
	"testing"

	"github.com/i9si-sistemas/assert"
)

func TestKeyGenerator(t *testing.T) {
	keyGenerator := New(sha256.New, 32, 10000)
	assert.NotNil(t, keyGenerator)
	_, ok := keyGenerator.(*PBKDF2)
	assert.True(t, ok)
}
