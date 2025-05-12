package pbkdf2

import (
	"crypto/sha256"
	"testing"

	"github.com/i9si-sistemas/assert"
)

func TestPBKDF2(t *testing.T) {
	password := "password1234"
	keyLength := 32
	generatedSaltLength := 16
	maxInteractions := 10000
	keyGenerator := &PBKDF2{
		hg: sha256.New,
		l:  keyLength,
		i:  maxInteractions,
	}
	salt, err := keyGenerator.GenerateSalt()
	assert.NoError(t, err)
	assert.Equal(t, len(salt), generatedSaltLength)
	derivedKey, err := keyGenerator.Generate(password, salt...)
	assert.NoError(t, err)
	assert.Equal(t, len(derivedKey), keyLength * 2)
	assert.True(t, keyGenerator.Compare(derivedKey, password, salt))
	salt, err = keyGenerator.GenerateSalt()
	assert.NoError(t, err)
	secondDerivedKey, err := keyGenerator.Generate(password, salt...)
	assert.NoError(t, err)
	assert.NotEqual(t, secondDerivedKey, derivedKey)
	assert.True(t, keyGenerator.Compare(secondDerivedKey, password, salt))
}