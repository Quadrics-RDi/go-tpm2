# INFORMATION SEALING PROCEDURE


## Introduction

This document will detail the procedure to seal a set of bytes within the TPM making use of its capabilities, as well as all the requisites for doing so. The procedure will be detailed in the Go programming language following the TCG spec for the TPM2

## Procedure overview

The procedure has four phases, two for information sealing and two for retrieving:

Sealing:

1. Creating the parent container
2. Creting the sealed container within the parent

Retrieving

1. Loading the sealed container
2. Unsealing the container

For each phase, there is a dedicated command, TPM_CC_CreatePrimary and TPM_CC_Create for the sealing process and TPM_CC_Load and TPM_CC_Unseal for the data retrieval, with each having an associated Go function

## Considerations

Before we go into the functions themselves, we need to introduce a series of prerequisites, as well as the basic code structures we will need to use.

### Struct

First, we have a struct for the TPM 

```go

type TPM struct {
	File     *os.File // File buffer
	FileName string // File path, stored just in case there is a need to forcefully reload the buffer
}
```

The idea behind this struct is to have a way to attach the associated functions to it, so it can resemble the exposed commands model used in the TCG specification.

### TPM resources

The TPM is divided into two resources, which in Linux are as follows:

```bash
/dev/tpm0
/dev/tpmrm0
```

One is the instance of the TPM itself, tpm0, and the other is its resource manager, tpmrm0. By default, unless it is a command to alter the TPM itself, we will use the resource manager, which in turn means that we will operate in write-read cycles, that is, we will send a command payload and then read the response, else the response would linger until it is read which means that we would not be able to send further commands

### Sessions

Given that all these operations require to access sensitive procedures, the user that is to apply them must add a valid session to the TPM payload. This is the basic structure of a TPM2 session

```go
	type Session struct {
		SessionHandle uint32
		NonceSize uint uint16
		Nonce []uint8
		Attributes uint8
		HMACSize uint16
		HMAC []uint8
	}
```

This session is given usually by the command TPM2_CC_Start_Auth_Session. but there is a default one which by the time of this documentation is the one we will use, the password session (TPM_RS_PW)

```go
	RSPW := Session{
		SessionHandle: 0x40000009,
		NonceSize: 0,
		Attributes: 0x00, //this equals 0x01 if we are reusing a session
		HMACSize: 0x0000, //password size goes here
		HMAC: []bytes{} //empty if no password is being used
	}
```

With that said, this must head the command itself that is, the bytes must look something like

> 4000000900000008002{command}

Where 400000090000000 is our header and 8002 the indication that it uses sessions

## PCRs and the TPM

In the boot procedure, whether Secure Boot or Measured Boot, several registries are left behind of the processes undergone and their results, which in turn are stored in something called Platform Configuration Registries (PCRs). This is done in order to guarantee the integrity of the system during it and prevent any sort of tampering from going undetected.

The operations we can do with these registries are two:

### Reading a PCR

The command body structure are as follows: 

```go

type TPMLPCRSelection struct {
	HashAlg   uint16
	PCRSelect [3]uint8
}
```

Where the HashAlg represents the hashing algorithm to be used as depicted in section 2 of the specification (we use TPM_ALG_SHA256 here) and PCR represents the PCR number as a three unsigned 8-bit unsinged integers slice. All of it preceded by the prefix for no sessions (0x8001) and the command code (TPM_CC_PCR_Read, 0x0000017E) so it will be something like

> 0x80010000017E000B000000 (last six digits are these 8-bit integers)

This way we will get the PCR contents as a hash

### Extending a PCR

We can also append bytes at the end of a PCR. The command body structure is as follows:

```go
type TPMCCPCRExtend struct {
	Count uint32 //equals to 1
	TPMAlg uint16 // the hashing algorithm
	Content []byte //the data with which we want to extend the PCR with
}
```

This is preceded by the sessions header and a password session with an empty password

To check this command works as intended we have the following auxiliary function

```go
// message is what we would put in Content in the aforementioned struct
func CheckPCRIsExtended(oldPCR, newPCR, message []byte) bool {

	zeroSHA := sha256.Sum256(message)
	theoric := sha256.New()

	theoric.Write(oldPCR)
	theoric.Write(zeroSHA[:])
	expected := theoric.Sum(nil)

	return bytes.Equal(newPCR, expected)

}
```

Essentially, it hashes the PCR hash once again as the PCR would upon extended. If at any point anything has changed the PCR hash will have changed and therefore this re-hashing will not equal the new hash

## Encapsulating information

However we might want to store information in the TPM. It allows such a thing, but not straight-away. This procedure has the following steps:

### 1. Creating the primary container

Before being able to store the information we need to create a primary container with the TPM_CC_Create_Primary command, whose body is as follows

```
CC: TPM_CC_Create_Primary
Handle_ TPM_RH_ENDORSEMENT

Tag | Size | Command code | Primary Handle | AuthArea | Sensitive create | Public data | OutsideInfo | Creation PCR
8002 | 00XX | 00000131 | 4000000B | <authArea> | <sensitive> | <public> | 0000 | 00000000

<authArea> -> 0x0010 | 40000009 | 0000 | 00 | 00 (auth without password)   

<Sensitive>:

Auth | Data
00000000 | 00000000

<Public>:
TPM_ALG_RSA -> 0x0001
TPM_ALG_SHA256 -> 0x000B
ObjectAtributes -> Att1 + Att2 + ...
authpolicy -> 0x000000000000 (size 0, zero content)
TPM_ALG_AES -> 0x0006
Alg keybits -> 0x0100 (256)
TPM_ALF_CFB -> 0x0043


TPM_ALG_NULL -> 0x0000
RSA keybits -> 0x0800 (2048 keybits) 
unique -> 0x00000000 (size 0, zero content)


Object Attributes:
fixedTPM -> 0x00000002
fixedParent -> 0x00000010
sensitiveDataOrigin -> 0x00000020
userWithAuth -> 0x00000040
restricted -> 0x00020000
decrypt -> 0x00040000
noDA -> 0x00000400

Response: 
Header(14) + Body(n)

Header:
[0 - 3] -> Primary handle

```

### 2. Creating the container with the sealed data

Then we need to create a container with the sealed data

```
CC: TPM_CC_Create
Tag | Size | Command code | Primary Handle | AuthData | Sensitive create | Public data | Outside Info | PCR creation
8002 | 00XX | 00000153 | EK | authData | <sensitive> | <public> | 0000 | 0000

<Sensitive>

Auth -> 0x00000000
Data -> <string we are trying to seal as bytes>

<Public>
TPM_ALG_KEYED_HASH -> 0x0008
TPM_ALG_SHA256 -> 0x000B 

ObjectAttributes -> Att1 + Att2 + ...
Auth Policy Size -> 0x0000
TPM_ALG_NULL -> 0x0000

TPM_ALG_NULL -> 0x0000
unique -> 0x0000 (size zero, zero content)

Object Attributes:
fixedTPM -> 0x00000002
fixedParent -> 0x00000010
userWithAuth -> 0x00000040

Response:

Header(14) + Body(n)

Body:
[0 - 3] -> Private size (vs)
[4 - 4+vs] -> Private data (v)
[5+vs - 8+vs] -> Public size (bs)
[9+bs - 9+vs+bs] -> Public data (b)

```

### 3. Loading the data into the TPM

Then we will need to load the data into the TPM before we are able to unseal it

```
CC: TPM_CC_Load -> 0x00000157

Tag | Size | Command code | Primary handle | AuthData | Private size | Private data | Public Size | Public data
8002 | XXXX | 00000157 | <parent handle> | authData | AAAA | <private data> | BBBB | <public data>

the AAAA + <private data> and BBBB + <public data> are the TPMB2_PRIVATE and TPMB2_PUBLIC from before 

Response:

Header (14) + Body (n)

Header:
[0 - 3] -> handle to retrieve the data
```

### De-encapsulating information

The process before should have produced two handles, which we will use to de-encapsulate the information 

```
CC: TPM_CC_Unseal -> 0x0000015E

Tag | Size | Loaded handle | AuthData

8002 | XXXX | <handle loaded in 1.3> | authData 

Response:

Header (14) + Body (n)

Body:
[0 - 3] -> data size (ds)
[4 - 4+ds] -> data (in bytes, would need to convert to string)
```