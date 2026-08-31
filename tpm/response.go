package tpm

import (
	"encoding/binary"
	"fmt"
	"go-tpm2/customCatalogs"
	"io"
	"syscall"
)

type ResponseHeader interface {
	String(catalog customCatalogs.Catalog) string
	Load(bytes []byte) error
	GetSize() int
	GetReturnCode() ReturnCode
}

type HeaderNoSessions struct {
	Tag          uint16
	Size         uint32
	ResponseCode ReturnCode
}

func (h *HeaderNoSessions) String(catalog customCatalogs.Catalog) string {
	return catalog.HeaderDataLog(h.Tag, ResponseCodeReference[h.ResponseCode], h.Size)
}

func (h *HeaderNoSessions) Load(bytes []byte) error {
	if len(bytes) < 10 {
		return fmt.Errorf("wrong header size")
	}

	be := binary.BigEndian

	h.Tag = be.Uint16(bytes[0:2])
	h.Size = be.Uint32(bytes[2:6])
	h.ResponseCode = ParseReturnCode(be.Uint32(bytes[6:10]))

	return nil
}

func (h *HeaderNoSessions) GetSize() int {
	return int(h.Size)
}

func (h *HeaderNoSessions) GetReturnCode() ReturnCode {
	return h.ResponseCode
}

type HeaderSessions struct {
	HeaderNoSessions
}

func (h *HeaderSessions) Load(bytes []byte) error {
	if len(bytes) < 10 {
		return fmt.Errorf("wrong header size, expected 10, actual: %d", len(bytes))
	}

	be := binary.BigEndian

	h.Tag = be.Uint16(bytes[0:2])
	h.Size = be.Uint32(bytes[2:6])
	h.ResponseCode = ParseReturnCode(be.Uint32(bytes[6:10]))

	return nil
}

func (h *HeaderSessions) String(catalog customCatalogs.Catalog) string {

	return catalog.HeaderDataLog(h.Tag, ResponseCodeReference[h.ResponseCode], h.Size)
}

func ParseReturnCode(number uint32) ReturnCode {
	fmt.Printf("Response code: %x\n", number)
	if number == uint32(RCSuccess) {
		return RCSuccess
	}

	var rcHeader ReturnCode

	var errorNum uint32

	if number&0x80 != 0 {
		rcHeader = RCFMT1
		errorNum = number & 0x3F
	} else if number&0x900 == 0x900 {
		rcHeader = RCWarn
		errorNum = number &^ uint32(RCWarn)
	} else {
		rcHeader = RCVer1
		errorNum = number &^ uint32(RCVer1)
	}

	return rcHeader + ReturnCode(errorNum)
}

type ResponseBody interface {
	Load(bodyBytes []byte)
	FullBody() []byte
	TargetData(catalog customCatalogs.Catalog) ([]byte, error)
}

type EmptyResponse struct {
}

func (r *EmptyResponse) Load(bodyBytes []byte) {}
func (r *EmptyResponse) FullBody() []byte {
	return nil
}
func (r *EmptyResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	return nil, nil
}

type DataResponse struct {
	data []byte
}

func (r *DataResponse) Load(bodyBytes []byte) {
	r.data = bodyBytes
}

func (r *DataResponse) FullBody() []byte {
	return r.data
}

type SupportedAlgsResponse struct {
	DataResponse
}

func (r *SupportedAlgsResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	off := 1 + 4

	return r.data[off:], nil
}

type PCRHashResponse struct {
	DataResponse
}

func (r *PCRHashResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	off := 4 + 4 + 2 + 1 + 3 // header  + update counter + count of selections returned + command body

	digestCount := binary.BigEndian.Uint32(r.data[off:])
	off += 4

	if digestCount == 0 {
		return nil, fmt.Errorf(catalog.NoDigestError(), "")
	}

	digestLen := binary.BigEndian.Uint16(r.data[off:])
	off += 2
	digest := r.data[off : off+int(digestLen)]

	return digest, nil
}

type PrimaryHandleResponse struct {
	DataResponse
}

func (r *PrimaryHandleResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {

	handle := r.data[:4]

	return handle, nil
}

type GetCapVariableResponse struct {
	DataResponse
}

func (r *GetCapVariableResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	return r.FullBody(), nil
}

type CreateSealedResponse struct {
	DataResponse
}

func (r *CreateSealedResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	return r.data, nil
}

type LoadSealedResponse struct {
	DataResponse
}

func (r *LoadSealedResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	fmt.Printf("body: %x\n", r.data)
	return r.data[0:4], nil
}

type UnsealLoadedResponse struct {
	DataResponse
}

type CreateAKResponse struct {
	DataResponse
}

func (r *UnsealLoadedResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	off := 4
	dataLen := int(binary.BigEndian.Uint16(r.data[off:]))
	fmt.Printf("Data length %d\n", dataLen)
	off += 2
	return r.data[off : off+dataLen], nil
}

type ReadEKResponse struct {
	DataResponse
}

func (r ReadEKResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	return r.data, nil
}

type MakeCredentialResponse struct {
	DataResponse
}

func (r MakeCredentialResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	return r.data, nil
}

type Response struct {
	Header ResponseHeader
	Body   ResponseBody
}

type ActivateCredentialResponse struct {
	DataResponse
}

func (r ActivateCredentialResponse) TargetData(catalog customCatalogs.Catalog) ([]byte, error) {
	off := 4
	size := int(binary.BigEndian.Uint16(r.data[off : off+2]))
	fmt.Println("Response size: ", size)
	off += 2
	return r.data[off : off+size], nil
}

var ResponseBodyMatch = map[TPMCCCommand]ResponseBody{
	tpmCCPCRRead:            &PCRHashResponse{},
	tpmCCPCRExtend:          &EmptyResponse{},
	tpmGetCapVariable:       &SupportedAlgsResponse{},
	tpmCCCreatePrimary:      &PrimaryHandleResponse{},
	tpmCCCreate:             &CreateSealedResponse{},
	tpmCCUnseal:             &UnsealLoadedResponse{},
	tpmCCLoad:               &LoadSealedResponse{},
	tpmCCReadPublic:         &ReadEKResponse{},
	tpmCCMakeCredential:     &MakeCredentialResponse{},
	tpmCCActivateCredential: &ActivateCredentialResponse{},
}

func (t *TPM) loadResponse(catalog customCatalogs.Catalog, cc uint32) (Response, error) {
	syscall.Syscall(syscall.SYS_SCHED_YIELD, 0, 0, 0)
	res := Response{}

	hdr := make([]byte, 10)

	fmt.Print(catalog.ReadingHeaderLog())
	if _, err := io.ReadFull(t.File, hdr); err != nil {
		fmt.Print(catalog.FailedToReadHeader(err))
		return res, err
	}

	var header ResponseHeader
	var err error
	var headerSize int
	tag := binary.BigEndian.Uint16(hdr[0:2])
	switch tag {
	case 0x8001:
		header = &HeaderNoSessions{}
		err = header.Load(hdr[0:10]) // no sessions header is 10 bytes long
		headerSize = 10

	case 0x8002:
		header = &HeaderSessions{}
		err = header.Load(hdr)
		headerSize = 10
	default:
		return res, fmt.Errorf(catalog.UnknownTagError(tag), "")
	}

	if header.GetReturnCode() != RCSuccess {
		return res, fmt.Errorf(catalog.CommandFailedRCError(ResponseCodeReference[header.GetReturnCode()]), "")
	}

	size := header.GetSize()
	if size < headerSize {
		return res, fmt.Errorf(catalog.InvalidResponseSizeError(size), "")
	}

	body := make([]byte, size-headerSize)

	fmt.Print(catalog.ReadingBodyLog())

	if _, err = io.ReadFull(t.File, body); err != nil {
		return res, err
	}

	fmt.Print(catalog.ReadingResponseBodyLog(body))

	res.Header = header

	res.Body = ResponseBodyMatch[TPMCCCommand(cc)]

	res.Body.Load(body)

	return res, nil
}
