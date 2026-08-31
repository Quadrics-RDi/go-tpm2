package internal

import (
	"bytes"
	"crypto/sha256"
)

func CheckPCRIsExtended(oldPCR, newPCR, message []byte) bool {

	zeroSHA := sha256.Sum256(message)
	theoric := sha256.New()

	theoric.Write(oldPCR)
	theoric.Write(zeroSHA[:])
	expected := theoric.Sum(nil)

	return bytes.Equal(newPCR, expected)

}
