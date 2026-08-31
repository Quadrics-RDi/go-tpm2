package tpm

import "go-tpm2/internal"

type Session struct {
	SessionHandle uint32
	NonceSize     uint16
	Nonce         []uint8
	Attributes    uint8
	HMACSize      uint16
	HMAC          []uint8
}

func (s Session) GetStructure() []byte {
	var buffer auxilia.Wbuf

	buffer.U32(s.SessionHandle)
	buffer.U16(s.NonceSize)
	buffer.Bytes(s.Nonce)
	buffer.U8(s.Attributes)
	buffer.U16(s.HMACSize)
	buffer.Bytes(s.HMAC)

	return buffer.Get()
}

type TPMLPCRSelection struct {
	HashAlg   uint16
	PCRSelect [3]uint8
}

func (s *TPMLPCRSelection) GetStructure() []byte {
	var ret auxilia.Wbuf

	ret.U32(1) // 1 selection
	ret.U16(s.HashAlg)
	ret.U8(3) //always 3
	ret.U8(s.PCRSelect[0])
	ret.U8(s.PCRSelect[1])
	ret.U8(s.PCRSelect[2])

	return ret.Get()
}
