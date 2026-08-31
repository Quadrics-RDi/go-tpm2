package tpm

type TPMCCCommand uint32

func (u TPMCCCommand) Get() uint32 {
	return uint32(u)
}

// commands
const (
	tpmCCStartup              TPMCCCommand = 0x00000144
	tpmCCActivateCredential   TPMCCCommand = 0x00000147
	tpmCCNVReadPublic         TPMCCCommand = 0x00000169
	tpmCCGetRandom            TPMCCCommand = 0x0000017B
	tpmCCCreatePrimary        TPMCCCommand = 0x00000131
	tpmCCCreate               TPMCCCommand = 0x00000153
	tpmCCLoad                 TPMCCCommand = 0x00000157
	tpmCCUnseal               TPMCCCommand = 0x0000015E
	tpmCCReadPublic           TPMCCCommand = 0x00000173
	tpmCCEnableOwnerHierarchy TPMCCCommand = 0x00000121
	tpmGetCapVariable         TPMCCCommand = 0x0000017A
	tpmCCPCRRead              TPMCCCommand = 0x0000017E
	tpmCCPCRExtend            TPMCCCommand = 0x00000182
	tpmCCMakeCredential       TPMCCCommand = 0x00000168
)
