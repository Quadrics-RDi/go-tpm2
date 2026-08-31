package tpm

import (
	"os"
)

type TPM struct {
	File     *os.File
	FileName string
}

var (
	tpm2StNoSessions    uint16 = 0x8001
	tpm2StSessions      uint16 = 0x8002
	tpmSuClear          uint16 = 0x0000
	tpmCapTPMProperties uint32 = 0x00000006
	ptFixedStart        uint32 = 0x00000200
	tpmRSPw             uint32 = 0x40000009
	tpmPTContextSym     uint32 = 0x0000011B
	tpmPTContextSymSize uint32 = 0x0000011C
	tpmPTContextSymMode uint32 = 0x0000011D
)
