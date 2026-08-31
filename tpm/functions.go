package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go-tpm2/auxilia"
	"go-tpm2/customCatalogs"
	"os"
)

func (t *TPM) Load(path string) error {
	var err error = nil

	file, err := os.OpenFile(path, os.O_RDWR, 0)

	t.File = file
	t.FileName = path

	return err
}

func (t *TPM) Reload() error {
	var err error
	t.File, err = os.OpenFile(t.FileName, os.O_RDWR, 0)

	return err
}

func (t *TPM) Start() error {

	buf := make([]byte, 12)

	be := binary.BigEndian

	be.PutUint16(buf[0:], tpm2StNoSessions)
	be.PutUint32(buf[2:], uint32(12))
	be.PutUint32(buf[6:], tpmCCStartup.Get())
	be.PutUint16(buf[10:], tpmSuClear)

	n, err := t.File.Write(buf)

	if err != nil {
		return err
	} else if n != len(buf) {
		return fmt.Errorf("short write on TPM2_Startup")
	}

	res := make([]byte, 4096)

	_, err = t.File.Read(res)

	return err
}

func (t *TPM) sendCommandNoSessions(cc uint32, body []byte, catalog customCatalogs.Catalog) (Response, error) {

	var res Response
	var w auxilia.Wbuf

	w.U16(tpm2StNoSessions)       //no sessions code
	w.U32(uint32(10 + len(body))) //total command length
	w.U32(cc)                     //command code
	w.Bytes(body)                 //command body

	if n, err := t.File.Write(w.Get()); err != nil {
		return res, err
	} else if n != len(w.Get()) {
		return res, fmt.Errorf(catalog.NotEnoughCommandReadBytesError(len(w.Get()), n), "") //missing error in catalog definition
	}

	fmt.Print(catalog.SendingCommandLog(cc))

	fmt.Print(catalog.FullCommandLog(w.Get()))

	res, err := t.loadResponse(catalog, cc)

	if err != nil {
		return res, err
	} else if rc := res.Header.GetReturnCode(); rc != RCSuccess {
		return res, fmt.Errorf(catalog.CommandFailedRCError(ResponseCodeReference[rc]), "")
	}

	return res, nil
}

func (t *TPM) sendCommandWithEmptyPassword(cc, handle uint32, body []byte, catalog customCatalogs.Catalog) (Response, error) {
	var res Response

	var auth auxilia.Wbuf

	auth.U32(tpmRSPw) // TPM_RS_PW
	auth.U16(0)       // nonce size
	auth.U8(0)        // session attributes
	auth.U16(0)       // hmac size

	var cmd auxilia.Wbuf

	cmd.U16(tpm2StSessions)
	cmd.U32(uint32(10 + 4 + 4 + len(auth.Get()) + len(body))) //total length
	cmd.U32(cc)
	cmd.U32(handle)
	cmd.U32(uint32(len(auth.Get())))
	cmd.Bytes(auth.Get())
	cmd.Bytes(body)

	fmt.Print(catalog.SendingCommandLog(cc))

	fmt.Print(catalog.FullCommandLog(cmd.Get()))

	if n, err := t.File.Write(cmd.Get()); err != nil {
		return res, err
	} else if n != len(cmd.Get()) {
		return res, fmt.Errorf("full command could not be written, expected %d bytes, got %d", n, len(cmd.Get()))
	}

	res, err := t.loadResponse(catalog, cc)

	return res, err
}

func (t *TPM) sendCommandTwoSessionsWOPasswords(cc, handle1, handle2 uint32, body []byte, catalog customCatalogs.Catalog) (Response, error) {

	var auth auxilia.Wbuf

	var ses1 auxilia.Wbuf

	ses1.U32(tpmRSPw)
	ses1.U16(0)
	ses1.U8(0)
	ses1.U16(0)

	var ses2 auxilia.Wbuf

	ses2.U32(tpmRSPw)
	ses2.U16(0)
	ses2.U8(0)
	ses2.U16(0)

	auth.U32(uint32(len(ses1.Get()) + len(ses2.Get())))
	auth.Bytes(ses1.Get())
	auth.Bytes(ses2.Get())

	var cmd auxilia.Wbuf

	cmd.U16(tpm2StSessions)
	cmd.U32(uint32(10 + 4 + 4 + len(auth.Get()) + len(body))) //total length
	cmd.U32(cc)
	cmd.U32(handle1)
	cmd.U32(handle2)
	cmd.Bytes(auth.Get())
	cmd.Bytes(body)

	fmt.Print(catalog.SendingCommandLog(cc))

	fmt.Print(catalog.FullCommandLog(cmd.Get()))

	if n, err := t.File.Write(cmd.Get()); err != nil {
		return Response{}, err
	} else if n != len(cmd.Get()) {
		return Response{}, fmt.Errorf("full command could not be written, expected %d bytes, got %d", n, len(cmd.Get()))
	}

	res, err := t.loadResponse(catalog, cc)

	return res, err
}

func (t *TPM) sendCommandWithPassword(cc, handle uint32, body []byte, pwd string, nonce []uint8, catalog customCatalogs.Catalog) (Response, error) {

	pwdByte := []byte(pwd)

	var res Response

	session := Session{
		SessionHandle: tpmRSPw,
		NonceSize:     uint16(len(nonce)),
		Nonce:         nonce,
		HMACSize:      uint16(len(pwdByte)),
		HMAC:          pwdByte,
	}

	auth := session.GetStructure()

	var cmd auxilia.Wbuf

	cmd.U16(tpm2StSessions)
	cmd.U32(uint32(10 + 4 + 4 + len(auth) + len(body))) //total length
	cmd.U32(cc)
	cmd.U32(handle)
	cmd.Tpmb2(auth)
	cmd.Bytes(body)

	fmt.Print(catalog.SendingCommandLog(cc))

	fmt.Print(catalog.FullCommandLog(cmd.Get()))

	if n, err := t.File.Write(cmd.Get()); err != nil {
		return res, err
	} else if n != len(cmd.Get()) {
		return res, fmt.Errorf(catalog.NotEnoughCommandReadBytesError(len(cmd.Get()), n), "")
	}

	res, err := t.loadResponse(catalog, cc)

	return res, err
}

// commands 24.1
func (t *TPM) CreatePrimary(catalog customCatalogs.Catalog) (uint32, error) {

	var sens auxilia.Wbuf

	sens.Tpmb2(nil) // user auth
	sens.Tpmb2(nil) // data

	//public
	var pub auxilia.Wbuf

	pub.U16(tpmAlgRSA.Get())    // type
	pub.U16(tpmAlgSHA256.Get()) // algorithm name
	// object attributes
	pub.U32(
		fixedTPM.Get() |
			fixedParent.Get() |
			sensitiveDataOrigin.Get() |
			userWithAuth.Get() |
			restricted.Get() |
			decrypt.Get() |
			noDA.Get(),
	)
	pub.Tpmb2(nil) // auth policy

	//RSA params

	pub.U16(tpmAlgAES.Get()) // symmetric-
	pub.U16(256)             //key bits
	pub.U16(tpmAlgCFB.Get()) //mode

	pub.U16(tpmAlgNull.Get()) //scheme
	pub.U16(2048)             //RSA keybits
	pub.U32(0)                //exponent
	pub.Tpmb2(nil)            //unique

	var body auxilia.Wbuf

	body.Tpmb2(sens.Get())
	body.Tpmb2(pub.Get())
	body.Tpmb2(nil) //outside info
	body.U32(0)     //creationPCR

	fmt.Println("Sending creating primary command")
	res, err := t.sendCommandWithEmptyPassword(tpmCCCreatePrimary.Get(), tpmRHOwner.Get(), body.Get(), catalog)

	if err != nil {
		return 0, err
	}

	handleBytes, err := res.Body.TargetData(catalog)

	return binary.BigEndian.Uint32(handleBytes), err
}

// commands 12.1
func (t *TPM) CreateSealed(parent uint32, secret []byte, catalog customCatalogs.Catalog) ([]byte, []byte, error) {
	var body auxilia.Wbuf

	fmt.Printf("Handle bytes: %x\n", parent)
	fmt.Printf("Secret bytes: %x\n", secret)

	var sens auxilia.Wbuf
	sens.Tpmb2(nil)    //auth
	sens.Tpmb2(secret) //sensitive data
	body.Tpmb2(sens.Get())

	var pub auxilia.Wbuf
	pub.U16(tpmAlgKeyedHash.Get()) // type
	pub.U16(tpmAlgSHA256.Get())    //algorithm name
	pub.U32(fixedTPM.Get() |
		fixedParent.Get() |
		userWithAuth.Get(),
	)

	pub.Tpmb2(nil) //auth policy

	// TPMT keyedhash params
	pub.U16(tpmAlgNull.Get()) // scheme
	pub.Tpmb2(nil)            // unique

	body.Tpmb2(pub.Get())

	body.Tpmb2(nil) // outside info
	body.U32(0)     // PCR

	res, err := t.sendCommandWithEmptyPassword(tpmCCCreate.Get(), parent, body.Get(), catalog)

	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("response: %x\n", res)

	responseBody := res.Body.FullBody()

	off := 4

	fmt.Println("Getting private part")
	privLen := binary.BigEndian.Uint16(responseBody[off:])
	off += 2
	privOut := responseBody[off : off+int(privLen)]
	off += int(privLen)

	fmt.Println("Getting public part")
	pubLen := binary.BigEndian.Uint16(responseBody[off:])
	off += 2
	pubOut := responseBody[off : off+int(pubLen)]

	return privOut, pubOut, nil
}

func (t *TPM) LoadSealedObject(parent uint32, priv, pub []byte, catalog customCatalogs.Catalog) (uint32, error) {
	var b auxilia.Wbuf
	b.Tpmb2(priv)
	b.Tpmb2(pub)

	res, err := t.sendCommandWithEmptyPassword(tpmCCLoad.Get(), parent, b.Get(), catalog)

	if err != nil {
		return 0, nil
	}

	data, _ := res.Body.TargetData(catalog)

	return binary.BigEndian.Uint32(data), nil
}

func (t *TPM) UnsealObject(handle uint32, catalog customCatalogs.Catalog) ([]byte, error) {
	var b auxilia.Wbuf

	res, err := t.sendCommandWithEmptyPassword(tpmCCUnseal.Get(), handle, b.Get(), catalog)

	if err != nil {
		return nil, err
	}

	return res.Body.TargetData(catalog)
}

func (t *TPM) GetHierarchyCapability(catalog customCatalogs.Catalog) ([]byte, error) {
	var body auxilia.Wbuf
	body.U32(tpmCapTPMProperties) // TPM_CAP_TPM_PROPERTIES
	body.U32(ptFixedStart)        // PT_FIXED start property
	body.U32(0x00000020)          // count

	res, err := t.sendCommandNoSessions(tpmGetCapVariable.Get(), body.Get(), catalog)

	if err != nil {
		return nil, err
	}

	return res.Body.FullBody(), nil
}

func (t *TPM) GetFixedCapability(catalog customCatalogs.Catalog) ([]byte, error) {
	var body auxilia.Wbuf
	body.U32(tpmCapTPMProperties) // TPM_CAP_TPM_PROPERTIES
	body.U32(0x00000100)          // start point
	body.U32(0x00000040)          // count

	res, err := t.sendCommandNoSessions(tpmGetCapVariable.Get(), body.Get(), catalog) // TPM_CC_GetCapability

	if err != nil {
		return nil, err
	}

	return res.Body.FullBody(), nil
}

func (t *TPM) ReadPCR(pcrIndex uint, catalog customCatalogs.Catalog) ([]byte, error) {

	pcrSelect := [3]byte{}

	pcrSelect[pcrIndex/8] = 1 << (pcrIndex % 8)

	tpmPCRSelect := TPMLPCRSelection{
		HashAlg:   tpmAlgSHA256.Get(),
		PCRSelect: pcrSelect,
	}

	res, err := t.sendCommandNoSessions(tpmCCPCRRead.Get(), tpmPCRSelect.GetStructure(), catalog)

	if err != nil {
		return nil, err
	}

	return res.Body.TargetData(catalog)
}

func (t *TPM) ExtendPCR(pcrIndex int, data []byte, catalog customCatalogs.Catalog) error {
	hash := sha256.Sum256(data)

	var body auxilia.Wbuf

	body.U32(1)                  //count
	body.U16(tpmAlgSHA256.Get()) //hash algorithm
	body.Bytes(hash[:])

	_, err := t.sendCommandWithEmptyPassword(tpmCCPCRExtend.Get(), uint32(pcrIndex), body.Get(), catalog)

	return err
}

func (t *TPM) GetSupportedAlgs(catalog customCatalogs.Catalog) ([]TPMAlg, error) {
	var body auxilia.Wbuf
	body.U32(tpmCapAlgs)
	body.U32(0x00000000) //first algorithm index
	body.U32(0x000000FF) //last index

	res, err := t.sendCommandNoSessions(tpmGetCapVariable.Get(), body.Get(), catalog)

	if err != nil {
		return nil, err
	}

	tdata, err := res.Body.TargetData(catalog)

	if err != nil {
		return nil, err
	}
	off := 0
	count := binary.BigEndian.Uint32(tdata[off:])
	off += 4

	supported := make([]TPMAlg, count)

	for range count {
		algID := binary.BigEndian.Uint32(tdata[off:])
		supported = append(supported, TPMAlg(algID))
		off += 4
	}

	return supported, nil
}

func (t *TPM) AlgorithmTemplate(catalog customCatalogs.Catalog) ([]byte, error) {
	var body auxilia.Wbuf

	body.U32(tpmCapTPMProperties)
	body.U32(tpmPTContextSym)
	body.U32(0x00000001) //count = 1

	res, err := t.sendCommandNoSessions(tpmGetCapVariable.Get(), body.Get(), catalog)

	if err != nil {
		return nil, err
	}

	return res.Body.TargetData(catalog)
}

func (t *TPM) AlgorithmSize(catalog customCatalogs.Catalog) ([]byte, error) {
	var body auxilia.Wbuf

	body.U32(tpmCapTPMProperties)
	body.U32(tpmPTContextSymSize)
	body.U32(0x00000001)

	res, err := t.sendCommandNoSessions(tpmGetCapVariable.Get(), body.Get(), catalog)

	if err != nil {
		return nil, err
	}

	return res.Body.TargetData(catalog)
}

func (t *TPM) CreateAK(parentHandle uint32, catalog customCatalogs.Catalog) (pub []byte, priv []byte, err error) {
	var body auxilia.Wbuf

	var sens auxilia.Wbuf

	sens.U16(0) //User auth size
	sens.U16(0) //data size

	body.Tpmb2(sens.Get())

	var public auxilia.Wbuf

	public.U16(tpmAlgRSA.Get())
	public.U16(tpmAlgSHA256.Get())

	public.U32(fixedTPM.Get() |
		fixedParent.Get() |
		sensitiveDataOrigin.Get() |
		userWithAuth.Get() |
		noDA.Get() |
		restricted.Get() |
		storageParent.Get())

	public.U16(0) //auth policy size

	public.U16(tpmAlgNull.Get()) //symmetric

	public.U16(tpmAlgRSASSA.Get()) //scheme
	public.U16(tpmAlgSHA256.Get()) //hash alg
	public.U16(2048)               //keybits
	public.U32(0)                  //exponent

	public.U16(0) //Unique

	body.Tpmb2(public.Get())

	body.U16(0) //outside info
	body.U32(0) //creation pcr selection, zero

	res, err := t.sendCommandWithEmptyPassword(tpmCCCreate.Get(), parentHandle, body.Get(), catalog)

	if err != nil {
		return nil, nil, err
	}

	resBody := res.Body.FullBody()

	off := 4

	privSize := int(binary.BigEndian.Uint16(resBody[off : off+2]))
	off += 2
	priv = resBody[off : off+privSize]
	off += privSize

	pubSize := int(binary.BigEndian.Uint16(resBody[off : off+2]))
	off += 2
	pub = resBody[off : off+pubSize]

	return
}

func (t *TPM) ReadPublic(catalog customCatalogs.Catalog, handle uint32) (ekPub, ekName []byte, err error) {
	var body auxilia.Wbuf

	body.U32(handle)

	res, err := t.sendCommandNoSessions(tpmCCReadPublic.Get(), body.Get(), catalog)

	bodyBytes, _ := res.Body.TargetData(catalog)

	off := 0

	pubLen := int(binary.BigEndian.Uint16(bodyBytes[off:]))
	off += 2
	ekPub = bodyBytes[off : off+pubLen]
	off += pubLen

	nameLen := int(binary.BigEndian.Uint16(bodyBytes[off:]))
	off += 2
	ekName = bodyBytes[off : off+nameLen]

	return
}

func (t *TPM) CreateTempEK(catalog customCatalogs.Catalog) (uint32, error) {

	var sens auxilia.Wbuf

	sens.Tpmb2(nil) // user auth
	sens.Tpmb2(nil) // data

	//public
	var pub auxilia.Wbuf

	pub.U16(tpmAlgRSA.Get())    // type
	pub.U16(tpmAlgSHA256.Get()) // algorithm name

	// object attributes
	pub.U32(
		fixedTPM.Get() |
			fixedParent.Get() |
			sensitiveDataOrigin.Get() |
			userWithAuth.Get() |
			restricted.Get() |
			decrypt.Get(),
	)
	pub.Tpmb2(nil) // auth policy

	//RSA params

	pub.U16(tpmAlgAES.Get()) // symmetric-
	pub.U16(128)             //key bits
	pub.U16(tpmAlgCFB.Get()) //mode

	pub.U16(tpmAlgNull.Get()) //scheme
	pub.U16(2048)             //RSA keybits
	pub.U32(0)                //exponent
	pub.Tpmb2(nil)            //unique

	var body auxilia.Wbuf

	body.Tpmb2(sens.Get())
	body.Tpmb2(pub.Get())
	body.Tpmb2(nil) //outside info
	body.U32(0)     //creationPCR

	fmt.Println("Sending creating primary command")
	res, err := t.sendCommandWithEmptyPassword(tpmCCCreatePrimary.Get(), tpmRHEndorsement.Get(), body.Get(), catalog)

	if err != nil {
		return 0, err
	}

	handleBytes, err := res.Body.TargetData(catalog)

	return binary.BigEndian.Uint32(handleBytes), err
}

func (t *TPM) MakeCredential(ekHandle uint32, secret, akName []byte, catalog customCatalogs.Catalog) (credBlob, encryptedSecret []byte, err error) {
	var body auxilia.Wbuf

	body.U32(ekHandle)
	body.Tpmb2(secret)
	body.Tpmb2(akName)

	res, err := t.sendCommandNoSessions(tpmCCMakeCredential.Get(), body.Get(), catalog)

	resBody := res.Body.FullBody()

	off := 0

	blobSize := int(binary.BigEndian.Uint16(resBody[off : off+2]))

	fmt.Println("")
	fmt.Printf("Blob size: %d\n", blobSize)
	fmt.Println("")
	off += 2

	credBlob = resBody[off : off+blobSize]
	off += blobSize

	secretSize := int(binary.BigEndian.Uint16(resBody[off : off+2]))
	off += 2

	fmt.Println("")
	fmt.Printf("Secret size: %d\n", secretSize)
	fmt.Println("")

	encryptedSecret = resBody[off : off+secretSize]

	return
}

func (t *TPM) ActivateCredential(
	akHandle, ekHandle uint32,
	blob, encryptedSecret []byte,
	catalog customCatalogs.Catalog,
) ([]byte, error) {

	var body auxilia.Wbuf

	body.Tpmb2(encryptedSecret)

	body.Tpmb2(blob)

	res, err := t.sendCommandTwoSessionsWOPasswords(tpmCCActivateCredential.Get(), akHandle, ekHandle, body.Get(), catalog)

	if err != nil {
		return nil, err
	}

	return res.Body.TargetData(catalog)
}
