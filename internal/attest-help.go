package internal

import (
	"crypto/rand"
	"crypto/sha256"
)

func GenerateRandomCredential() ([]byte, error) {
	cred := make([]byte, 32)

	if _, err := rand.Read(cred); err != nil {
		return nil, err
	}

	return cred, nil
}

func GetAKName(tpmtPublicBytes []byte) []byte {
	nameAlg := []byte{0x00, 0x0B}
	digest := sha256.Sum256(tpmtPublicBytes)

	name := make([]byte, 0, 43)
	name = append(name, nameAlg...)
	name = append(name, digest[:]...)

	return name
}
