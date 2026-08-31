package tpm

type ReturnCode uint16

func (c ReturnCode) Get() uint16 {
	return uint16(c)
}

const (
	RCSuccess ReturnCode = 0x000
	RCBadTag  ReturnCode = 0x01E

	//format-zero
	RCVer1            ReturnCode = 0x100
	RCSequence        ReturnCode = RCVer1 + 0x003
	RCPrivate         ReturnCode = RCVer1 + 0x00B
	RCHMAC            ReturnCode = RCVer1 + 0x019
	RCDisabled        ReturnCode = RCVer1 + 0x020
	RCExclusive       ReturnCode = RCVer1 + 0x021
	RCAuthType        ReturnCode = RCVer1 + 0x024
	RCAuthMissing     ReturnCode = RCVer1 + 0x025
	RCPolicy          ReturnCode = RCVer1 + 0x026
	RCPCR             ReturnCode = RCVer1 + 0x027 //failed to check PCR
	RCPCRChanged      ReturnCode = RCVer1 + 0x028 //PCR has changed since checked
	RCUpgrade         ReturnCode = RCVer1 + 0x02D
	RCTooManyContexts ReturnCode = RCVer1 + 0x02E
	RCReboot          ReturnCode = RCVer1 + 0x030
	RCUnbalanced      ReturnCode = RCVer1 + 0x031
	RCCommandSize     ReturnCode = RCVer1 + 0x042
	RCCommandCode     ReturnCode = RCVer1 + 0x043 //command code not supported
	RCAuthSize        ReturnCode = RCVer1 + 0x044
	RCAuthContext     ReturnCode = RCVer1 + 0x045
	RCNVRange         ReturnCode = RCVer1 + 0x046
	RCNVSize          ReturnCode = RCVer1 + 0x047
	RCNVLocked        ReturnCode = RCVer1 + 0x048
	RCNVAuthorizarion ReturnCode = RCVer1 + 0x049
	RCNVUninitialized ReturnCode = RCVer1 + 0x04A
	RCNVSpace         ReturnCode = RCVer1 + 0x04B
	RCNVDefined       ReturnCode = RCVer1 + 0x04C
	RCBadContext      ReturnCode = RCVer1 + 0x050
	RCCPHash          ReturnCode = RCVer1 + 0x051
	RCParent          ReturnCode = RCVer1 + 0x052
	RCNeedsTest       ReturnCode = RCVer1 + 0x053
	RCNoResult        ReturnCode = RCVer1 + 0x054
	RCSensitive       ReturnCode = RCVer1 + 0x055
	RCReadOnly        ReturnCode = RCVer1 + 0x056
	RCMaxFM0          ReturnCode = RCVer1 + 0x07F

	//format-one
	RCFMT1         ReturnCode = 0x080
	RCValue        ReturnCode = RCFMT1 + 0x004
	RCHierarchy    ReturnCode = RCFMT1 + 0x005
	RCKeySize      ReturnCode = RCFMT1 + 0x007
	RCMGF          ReturnCode = RCFMT1 + 0x008 //mask generation function not supported
	RCMode         ReturnCode = RCFMT1 + 0x009
	RCType         ReturnCode = RCFMT1 + 0x00A
	RCHandle       ReturnCode = RCFMT1 + 0x00B
	RCKDF          ReturnCode = RCFMT1 + 0x00C //unsupported jet derivation function or function not appropiate for use
	RCRange        ReturnCode = RCFMT1 + 0x00D
	RCAuthFail     ReturnCode = RCFMT1 + 0x00E
	RCNonce        ReturnCode = RCFMT1 + 0x00F
	RCPP           ReturnCode = RCFMT1 + 0x010 //authorization requires assertion of PP
	RCScheme       ReturnCode = RCFMT1 + 0x012
	RCSize         ReturnCode = RCFMT1 + 0x015
	RCSymmetric    ReturnCode = RCFMT1 + 0x016
	RCTag          ReturnCode = RCFMT1 + 0x017
	RCSelector     ReturnCode = RCFMT1 + 0x018
	ECInsufficient ReturnCode = RCFMT1 + 0x01A
	RCSignature    ReturnCode = RCFMT1 + 0x01B
	RCKey          ReturnCode = RCFMT1 + 0x01C
	RCPolicyFail   ReturnCode = RCFMT1 + 0x01D
	RCIntegrity    ReturnCode = RCFMT1 + 0x01F
	RCTicket       ReturnCode = RCFMT1 + 0x020
	RCReservedBits ReturnCode = RCFMT1 + 0x021
	RCBadAuth      ReturnCode = RCFMT1 + 0x022
	RCExpired      ReturnCode = RCFMT1 + 0x023
	RCPolicyCC     ReturnCode = RCFMT1 + 0x024
	RCBinding      ReturnCode = RCFMT1 + 0x025 //public and sensitive portions of an object are not cryptographically bound
	RCCurve        ReturnCode = RCFMT1 + 0x026
	RCECCPoint     ReturnCode = RCFMT1 + 0x027
	RCFWLimited    ReturnCode = RCFMT1 + 0x028
	RCSVNLimited   ReturnCode = RCFMT1 + 0x029
	RCChannel      ReturnCode = RCFMT1 + 0x030
	RCChannelKey   ReturnCode = RCFMT1 + 0x031

	//warnings
	RCWarn           ReturnCode = 0x900
	RCContextGap     ReturnCode = RCWarn + 0x001
	RCObjectMemory   ReturnCode = RCWarn + 0x002
	RCSessionMemory  ReturnCode = RCWarn + 0x003
	RCMemory         ReturnCode = RCWarn + 0x004
	RCSessionHandles ReturnCode = RCWarn + 0x005
	RCObjectHandles  ReturnCode = RCWarn + 0x006
	RCLocality       ReturnCode = RCWarn + 0x007
	RCYielded        ReturnCode = RCWarn + 0x008
	RCCanceled       ReturnCode = RCWarn + 0x009
	RCTesting        ReturnCode = RCWarn + 0x00A //tpm is performing self-tests
	RCReferenceH0    ReturnCode = RCWarn + 0x010 //the first handle in the handle area references a transient object or session that is not loaded
	RCReferenceH1    ReturnCode = RCWarn + 0x011
	RCReferenceH2    ReturnCode = RCWarn + 0x012
	RCReferenceH3    ReturnCode = RCWarn + 0x013
	RCReferenceH4    ReturnCode = RCWarn + 0x014
	RCReferenceH5    ReturnCode = RCWarn + 0x015
	RCReferenceH6    ReturnCode = RCWarn + 0x016
	RCReferenceS0    ReturnCode = RCWarn + 0x018 // the first authorization session handle references an object that is not loaded
	RCReferenceS1    ReturnCode = RCWarn + 0x019
	RCReferenceS2    ReturnCode = RCWarn + 0x01A
	RCReferenceS3    ReturnCode = RCWarn + 0x01B
	RCReferenceS4    ReturnCode = RCWarn + 0x01C
	RCReferenceS5    ReturnCode = RCWarn + 0x01D
	RCReferenceS6    ReturnCode = RCWarn + 0x01E
	RCNCRate         ReturnCode = RCWarn + 0x020
	RCLookout        ReturnCode = RCWarn + 0x021
	RCRetry          ReturnCode = RCWarn + 0x022
	RCNVUnavaliable  ReturnCode = RCWarn + 0x023
	RCNotUsed        ReturnCode = RCWarn + 0x7F //reserved, not used, TPM should not return this value
)

var ResponseCodeReference map[ReturnCode]string = map[ReturnCode]string{
	RCSuccess:         "TPM_RC_SUCCESS",
	RCBadTag:          "TPM_RC_BAD_TAG",
	RCSequence:        "TPM_RC_SEQUENCE",
	RCPrivate:         "TPM_RC_PRIVATE",
	RCHMAC:            "TPM_RC_HMAC",
	RCDisabled:        "TPM_RC_DISABLED",
	RCExclusive:       "TPM_RC_EXCLUSIVE",
	RCAuthType:        "TPM_RC_AUTH_TYPE",
	RCAuthMissing:     "TPM_RC_AUTH_MISSING",
	RCPolicy:          "TPM_RC_POLICY",
	RCPCR:             "TPM_RC_PCR",
	RCPCRChanged:      "TPM_RC_PCR_CHANGED",
	RCUpgrade:         "TPM_RC_UPGRADE",
	RCTooManyContexts: "TPM_RC_TOO_MANY_CONTEXTS",
	RCReboot:          "TPM_RC__REBOOT",
	RCUnbalanced:      "TPM_RC_UNBALANCED",
	RCCommandSize:     "TPM_RC_COMMAND_SIZE",
	RCCommandCode:     "TPM_RC_COMMAND_CODE",
	RCAuthSize:        "TPM_RC_AUTHSIZE",
	RCAuthContext:     "TPM_RCHIERARCHY",
	RCKeySize:         "TPM_RC_KEY_SIZE",
	RCMGF:             "TPM_RC_MGF",
	RCMode:            "TPM_RC_MODE",
	RCType:            "TPM_RC_TYPE",
	RCHandle:          "TPM_RC_HANDLE",
	RCKDF:             "TPM_RC_KDF",
	RCRange:           "TPM_RC_RANGE",
	RCAuthFail:        "TPM_RC_AUTH_FAIL",
	RCNonce:           "TPM_RC_NONCE",
	RCPP:              "TPM_RC_PP",
	RCScheme:          "TPM_RC_SCHEME",
	RCSize:            "TPM_RC_SIZE",
	RCSymmetric:       "TPM_RC_SYMMETRIC",
	RCTag:             "TPM_RC_TAG",
	RCSelector:        "TPM_RC_SELECTOR",
	ECInsufficient:    "TPM_RC_INSUFFICIENT",
	RCSignature:       "TPM_RC_SIGNATURE",
	RCKey:             "TPM_RC_KEY",
	RCPolicyFail:      "TPM_RC_POLICY_FAIL",
	RCIntegrity:       "TPM_RC_INTEGRITY",
	RCTicket:          "TPM_RC_TICKET",
	RCReservedBits:    "TPM_RC_RESERVED_BITS",
	RCBadAuth:         "TPM_RC_BAD_AUTH",
	RCExpired:         "TPM_RC_EXPIRED",
	RCPolicyCC:        "TPM_RC_POLICY_CC",
	RCBinding:         "TPM_RC_BINDING",
	RCCurve:           "TPM_RC_CURVE",
	RCECCPoint:        "TPM_RC_ECC_POINT",
	RCFWLimited:       "TPM_RC_FW_LIMITED",
	RCSVNLimited:      "TPM_RC_SVN_LIMITED",
	RCChannel:         "TPM_RC_CHANNEL",
	RCChannelKey:      "TPM_RC_CHANNEL_KEY",
	RCContextGap:      "TPM_RC_CONTEXT_GAT",
	RCObjectMemory:    "TPM_RC_OBJECT_MEMORY",
	RCSessionMemory:   "TPM_RC_SESSION_MEMORY",
	RCMemory:          "TPM_RC_MEMORY",
	RCSessionHandles:  "TPM_RC_SESSION_HANDLES",
	RCObjectHandles:   "TPM_RC_OBJECT_HANDLES",
	RCLocality:        "TPM_RC_LOCALITY",
	RCYielded:         "TPM_RC_YIELDED",
	RCCanceled:        "TPM_RC_CANCELED",
	RCTesting:         "TPM_RC_TESTING",
	RCReferenceH0:     "TPM_RC_REFERENCE_H0",
	RCReferenceH1:     "TPM_RC_REFERENCE_H1",
	RCReferenceH2:     "TPM_RC_REFERENCE_H2",
	RCReferenceH3:     "TPM_RC_REFERENCE_H3",
	RCReferenceH4:     "TPM_RC_REFERENCE_H4",
	RCReferenceH5:     "TPM_RC_REFERENCE_H5",
	RCReferenceH6:     "TPM_RC_REFERENCE_H6",
	RCReferenceS0:     "TPM_RC_REFERENCE_S0",
	RCReferenceS1:     "TPM_RC_REFERENCE_S1",
	RCReferenceS2:     "TPM_RC_REFERENCE_S2",
	RCReferenceS3:     "TPM_RC_REFERENCE_S3",
	RCReferenceS4:     "TPM_RC_REFERENCE_S4",
	RCReferenceS5:     "TPM_RC_REFERENCE_S5",
	RCReferenceS6:     "TPM_RC_REFERENCE_S6",
	RCNCRate:          "TPM_RC_RATE",
	RCLookout:         "TPM_RC_LOOKOUT",
	RCRetry:           "TPM_RC_RETRY",
	RCNVUnavaliable:   "TPM_RC_NV_UNAVALIABLE",
}
