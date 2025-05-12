package pbkdf2

import "hash"

// KeyGenerator is an interface for generating a derived key from a password and a salt.
type KeyGenerator interface {
	// Generate returns a derived key from a password and a salt.
	Generate(password string, salt ...byte) (derivedKey string, err error)
	// GenerateSalt returns a random salt.
	GenerateSalt(size ...int) (salt []byte, err error)
	// Compare compares if derived key is equal to the password.
	Compare(derivedKey, password string, salt []byte) bool
}

// New returns a new KeyGenerator using pbkdf2 algorithm.
func New(
	hashFn func() hash.Hash,
	keyLength,
	interactions int,
) KeyGenerator {
	return &PBKDF2{
		hg: hashFn,
		l:  keyLength,
		i:  interactions,
	}
}
