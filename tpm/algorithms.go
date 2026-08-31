package tpm

type TPMAlg uint16

func (a TPMAlg) Get() uint16 {
	return uint16(a)
}

var (
	tpmCapAlgs         uint32 = 0x00000000
	tpmAlgRSA          TPMAlg = 0x0001
	tpmAlgSHA1         TPMAlg = 0x0004
	tpmAlgHMAC         TPMAlg = 0x0005
	tpmAlgAES          TPMAlg = 0x0006
	tpmAlgKeyedHash    TPMAlg = 0x0008
	tpmAlgXOR          TPMAlg = 0x000A
	tpmAlgSHA384       TPMAlg = 0x000C
	tpmAlgSHA512       TPMAlg = 0x000D
	tpmAlgNull         TPMAlg = 0x0010
	tpmAlgSM4          TPMAlg = 0x0016
	tpmAlgRSASSA       TPMAlg = 0x0014
	tpmAlgRSAES        TPMAlg = 0x0017
	tpmAlgRSAPSS       TPMAlg = 0x0018
	tpmAlgOAEP         TPMAlg = 0x0019
	tpmAlgECDSA        TPMAlg = 0x001A
	tpmAlgECDH         TPMAlg = 0x001B
	tpmAlgECDAA        TPMAlg = 0x001C
	tpmAlgSM2          TPMAlg = 0x001F
	tpmAlgSHA256       TPMAlg = 0x000B
	tpmAlgECSchnorr    TPMAlg = 0x0020
	tpmAlgECMQV        TPMAlg = 0x0021
	tpmAlgKDF1SP80056A TPMAlg = 0x0022
	tpmAlgKDF2         TPMAlg = 0x0023
	tpmAlgKDF1SP800108 TPMAlg = 0x0024
	tpmAlgECC          TPMAlg = 0x0025
	tpmAlgSYMCypher    TPMAlg = 0x0028
	tpmAlgCamellia     TPMAlg = 0x0029
	tpmAlgCTR          TPMAlg = 0x0040
	tpmAlgOFB          TPMAlg = 0x0041
	tpmAlgCBC          TPMAlg = 0x0042
	tpmAlgCFB          TPMAlg = 0x0043
	tpmAlgECB          TPMAlg = 0x0044
)

var AlgorithmsCodeReference map[TPMAlg]string = map[TPMAlg]string{
	tpmAlgRSA:          "TPM_ALG_RSA",
	tpmAlgSHA1:         "TPM_ALG_SHA1",
	tpmAlgHMAC:         "TPM_ALG_HMAC",
	tpmAlgKeyedHash:    "TPM_ALG_KEYEDHASH",
	tpmAlgXOR:          "TPM_ALG_XOR",
	tpmAlgSHA256:       "TPM_ALG_SHA256",
	tpmAlgSHA384:       "TPM_ALG_SHA384",
	tpmAlgSHA512:       "TPM_ALG_SHA512",
	tpmAlgNull:         "TPM_ALG_NULL",
	tpmAlgSM4:          "TPM_ALG_SM4",
	tpmAlgRSASSA:       "TPM_ALG_RSASSA",
	tpmAlgRSAES:        "TPM_ALG_RSAES",
	tpmAlgRSAPSS:       "TPM_ALG_RSAPSS",
	tpmAlgOAEP:         "TPM_ALG_OAEP",
	tpmAlgECDSA:        "TPM_ALG_ECDSA",
	tpmAlgECDH:         "TPM_ALG_ECDH",
	tpmAlgECDAA:        "TPM_ALG_ECDAA",
	tpmAlgSM2:          "TPM_ALG_SM2",
	tpmAlgECSchnorr:    "TPM_ALG_ECSCHNORR",
	tpmAlgECMQV:        "TPM_ALG_ECMQV",
	tpmAlgKDF1SP80056A: "TPM_ALG_KDF1_SP800_56A",
	tpmAlgKDF2:         "TPM_ALG_KDF2",
	tpmAlgKDF1SP800108: "TPM_ALG_KDF1_SP800_108",
	tpmAlgECC:          "TPM_ALG_ECC",
	tpmAlgSYMCypher:    "TPM_ALG_SYMCYPHER",
	tpmAlgCamellia:     "TPM_ALG_CAMELLIA",
	tpmAlgCTR:          "TPM_ALG_CTR",
	tpmAlgOFB:          "TPM_ALG_OFB",
	tpmAlgCBC:          "TPM_ALG_CBC",
	tpmAlgCFB:          "TPM_ALG_CFB",
	tpmAlgECB:          "TPM_ALG_ECB",
}
