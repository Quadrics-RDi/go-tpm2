package customCatalogs

import (
	"fmt"
)

type English struct{}

func (c English) LoadTPMError(err error) string {
	return fmt.Sprintf("Unable to load TPM %s\n", err.Error())
}
func (c English) NotEnoughArgsError() string {
	return "Not enough arguments for this operation\n"
}

func (c English) ParameterNotRecognizedError(badParam string) string {
	return fmt.Sprintf("Parameter %s not recognized\n", badParam)
}
func (c English) BadPCRNumberError(err error) string {
	return fmt.Sprintf("Unable to parse PCR number provided: %s\n", err.Error())
}
func (c English) WrongPCRNumberLocalityError(pcr int) string {
	return fmt.Sprintf("PCR number not allowed due to locality: %d\n", pcr)
}
func (c English) WrongPCRNumberGenericError() string {
	return "PCR number not valid\n"
}
func (c English) UnableToExtendPCRError(err error) string {
	return fmt.Sprintf("Unable to extend PCR: %s\n", err.Error())
}
func (c English) UnableToReadOldPCRDigestError(err error) string {
	return fmt.Sprintf("Unable to read old PCR digest, %s\n", err.Error())
}
func (c English) UnableToReadNewPCRDigest(err error) string {
	return fmt.Sprintf("Unable to read new PCR digest, %s\n", err.Error())
}
func (c English) OperationNotRecognizedError(badOp string) string {
	return fmt.Sprintf("Operation %s not a recognized type\n", badOp)
}
func (c English) WrongCommandSizeError(actualSize, expectedSize int) string {
	return fmt.Sprintf("Wrong command size, expected %d, got %d\n", expectedSize, actualSize)
}
func (c English) WrongHeaderSizeError(actualSize, expectedSize int) string {
	return fmt.Sprintf("Wrong header size, expected %d, got %d\n", expectedSize, actualSize)
}
func (c English) UnknownTagError(uTag uint16) string {
	return fmt.Sprintf("Tag not recognized: %x\n", uTag)
}
func (c English) NotEnoughCommandReadBytesError(expectedBytes, actualBytes int) string {
	return fmt.Sprintf("Not enough command read bytes, expected %d, got %d\n", expectedBytes, actualBytes)
}
func (c English) InvalidResponseSizeError(actualSize int) string {
	return fmt.Sprintf("Invalid response size: %d\n", actualSize)
}
func (c English) CommandFailedRCError(rc string) string {
	return fmt.Sprintf("TPM failed with response code %s\n", rc)
}
func (c English) NoDigestError() string {
	return "No digest was returned\n"
}
func (c English) WritingToPCRLog(pcr int, message string) string {
	return fmt.Sprintf("Writing to PCR %d message %s\n", pcr, message)
}
func (c English) MessageToPCRLog(message string) string {
	return fmt.Sprintf("Writing to PCR message %s -> %x\n", message, []byte(message))
}
func (c English) SavingOldPCRLog() string {
	return "Saving current PCR digest\n"
}
func (c English) CurrentPCRDigestLog(pcr int, digest []byte) string {
	return fmt.Sprintf("Current PCR %d digest: %x\n", pcr, digest)
}
func (c English) NewPCRDigestLog(pcr int, digest []byte) string {
	return fmt.Sprintf("New PCR %d digest: %x\n", pcr, digest)
}
func (c English) PCRComparisionLog() string {
	return "Checking if the new digest matches the old one processed manually\n"
}
func (c English) HashesMatchLog() string {
	return "Digests match\n"
}
func (c English) HashesDoNotMatchLog() string {
	return "Digests do not match, an error must have occured\n"
}
func (c English) SendingCommandLog(cc uint32) string {
	return fmt.Sprintf("Sending command with code %x\n", cc)
}
func (c English) FullCommandLog(commandBytes []byte) string {
	return fmt.Sprintf("Full command: %x\n", commandBytes)
}
func (c English) ReadingResponseHeaderLog() string {
	return "Reading response header\n"
}
func (c English) TagLog(tag uint32) string {
	return fmt.Sprintf("Header tag %x\n", tag)
}
func (c English) SessionHeaderAdditionalDataLog() string {
	return "Adding additional data for session header\n"
}
func (c English) ResponseHeaderLog(header []byte) string {
	return fmt.Sprintf("Response header: %x\n", header)
}
func (c English) ReadingResponseBodyLog(body []byte) string {
	return fmt.Sprintf("Response body: %x\n", body)
}

func (c English) FailedToReadHeader(err error) string {
	return fmt.Sprintf("Failed to read response header: %s\n", err.Error())
}
func (c English) FailedToReadBody(err error) string {
	return fmt.Sprintf("Failed to read response body: %s\n", err.Error())
}

func (c English) ReadingHeaderLog() string {
	return "Reading header:\n"
}
func (c English) ReadingBodyLog() string {
	return "Reading body:\n"
}

func (c English) FailedToReadAdditionalHeaderData(err error) string {
	return fmt.Sprintf("Failed to read additional data for sessions header: %s\n", err.Error())
}

func (c English) HeaderDataLog(headerTag uint16, returnCode string, size uint32) string {
	return fmt.Sprintf("Tag: %x | Size: %d | Response code: %s", headerTag, int(size), returnCode)
}
