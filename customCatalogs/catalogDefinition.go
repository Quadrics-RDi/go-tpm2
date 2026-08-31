package customCatalogs

type Catalog interface {
	LoadTPMError(err error) string
	NotEnoughArgsError() string
	ParameterNotRecognizedError(badParam string) string
	BadPCRNumberError(err error) string
	WrongPCRNumberLocalityError(pcr int) string
	WrongPCRNumberGenericError() string
	UnableToExtendPCRError(err error) string
	UnableToReadOldPCRDigestError(err error) string
	UnableToReadNewPCRDigest(err error) string
	OperationNotRecognizedError(badOp string) string
	NotEnoughCommandReadBytesError(expectedBytes, actualBytes int) string
	WrongCommandSizeError(actualSize, expectedSize int) string
	WrongHeaderSizeError(actualSize, expectedSize int) string
	FailedToReadHeader(err error) string
	FailedToReadAdditionalHeaderData(err error) string
	FailedToReadBody(err error) string
	UnknownTagError(uTag uint16) string
	InvalidResponseSizeError(actualSize int) string
	CommandFailedRCError(rc string) string
	NoDigestError() string

	WritingToPCRLog(pcr int, message string) string
	MessageToPCRLog(message string) string
	SavingOldPCRLog() string
	CurrentPCRDigestLog(pcr int, digest []byte) string
	NewPCRDigestLog(pcr int, digest []byte) string
	PCRComparisionLog() string
	HashesMatchLog() string
	HashesDoNotMatchLog() string
	SendingCommandLog(cc uint32) string
	FullCommandLog(commandBytes []byte) string
	ReadingResponseHeaderLog() string
	TagLog(tag uint32) string
	SessionHeaderAdditionalDataLog() string
	ReadingHeaderLog() string
	ReadingBodyLog() string
	ResponseHeaderLog(header []byte) string
	ReadingResponseBodyLog(body []byte) string
	HeaderDataLog(headerTag uint16, returnCode string, size uint32) string
}
