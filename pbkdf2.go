package pbkdf2

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
)

type PBKDF2 struct {
	hg func() hash.Hash
	l  int
	i  int
}

var ErrWhileGeneratingSalt = errors.New("error while generating salt")

func (p *PBKDF2) Generate(password string, salt ...byte) (dk string, err error) {
	hash := hmac.New(p.HashGenerator(), salt)
	hashLength := hash.Size()
	blockSize := p.KeyLength() / hashLength
	if p.KeyLength()%hashLength > 0 {
		blockSize++
	}
	intermediateBlock := make([]byte, hashLength)
	iterationResult := make([]byte, hashLength)
	derivedKey := make([]byte, 0, hashLength*blockSize)
	iterationCounterBuf := make([]byte, 4)
	if len(salt) == 0 {
		salt, err = p.GenerateSalt()
		if err != nil {
			return
		}
	}
	for i := uint32(1); i <= uint32(blockSize); i++ {
		binary.BigEndian.PutUint32(iterationCounterBuf, i)
		hash.Reset()
		hash.Write(salt)
		hash.Write(iterationCounterBuf)
		iterationResult = iterationResult[:0]
		iterationResult = hash.Sum(iterationResult)

		copy(intermediateBlock, iterationResult)
		for j := uint32(2); j <= p.NumberOfIterations(); j++ {
			hash.Reset()
			hash.Write(iterationResult)
			iterationResult = iterationResult[:0]
			iterationResult = hash.Sum(iterationResult)
			for k := range iterationResult {
				intermediateBlock[k] ^= iterationResult[k]
			}
		}
		derivedKey = append(derivedKey, intermediateBlock...)
	}
	return hex.EncodeToString(derivedKey[0:p.KeyLength()]), nil
}

func (p *PBKDF2) Compare(derivedKey, password string, salt []byte) bool {
	dk, err := p.Generate(password, salt...)
	if err != nil {
		return false
	}
	return dk == derivedKey
}

func (p *PBKDF2) GenerateSalt() (salt []byte, err error) {
	saltSize := 16
	salt = make([]byte, saltSize)
	_, err = rand.Read(salt)
	return
}

func (p *PBKDF2) NumberOfIterations() uint32 {
	return uint32(p.i)
}

func (p *PBKDF2) HashGenerator() func() hash.Hash {
	return p.hg
}

func (p *PBKDF2) KeyLength() int {
	return p.l
}
