package tpm

type ObjectAttribute int64

func (o ObjectAttribute) Get() uint32 {
	return uint32(o)
}

const (
	fixedTPM            ObjectAttribute = 0x00000002
	fixedParent         ObjectAttribute = 0x00000010
	sensitiveDataOrigin ObjectAttribute = 0x00000020
	userWithAuth        ObjectAttribute = 0x00000040
	adminWithPolicy     ObjectAttribute = 0x00000080
	restricted          ObjectAttribute = 0x00010000
	decrypt             ObjectAttribute = 0x00020000
	storageParent       ObjectAttribute = 0x00040000
	noDA                ObjectAttribute = 0x00000400
)
