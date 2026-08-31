package tpm

type TPMIRHHierarchy uint32

func (u TPMIRHHierarchy) Get() uint32 {
	return uint32(u)
}

const (
	tpmRHOwner       TPMIRHHierarchy = 0x40000001
	tpmRHPlatform    TPMIRHHierarchy = 0x4000000C
	tpmRHEndorsement TPMIRHHierarchy = 0x4000000B
)
