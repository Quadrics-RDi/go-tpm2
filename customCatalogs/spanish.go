package customCatalogs

import (
	"fmt"
)

type Spanish struct{}

func (c Spanish) NotEnoughArgsError() string {
	return "No hay suficientes argumentos para esta operación\n"
}

func (c Spanish) LoadTPMError(err error) string {
	return fmt.Sprintf("Fallo al cargar el TPM en memoria, %s\n", err.Error())
}
func (c Spanish) ParameterNotRecognizedError(badParam string) string {
	return fmt.Sprintf("Parámetro no reconocido: %s\n", badParam)
}
func (c Spanish) BadPCRNumberError(err error) string {
	return fmt.Sprintf("Número de PCR no parseable: %s\n", err.Error())
}
func (c Spanish) WrongPCRNumberLocalityError(pcr int) string {
	return fmt.Sprintf("Número de PCR no permitido por la locality: %d\n", pcr)
}
func (c Spanish) WrongPCRNumberGenericError() string {
	return "Número de PCR no permitido\n"
}
func (c Spanish) UnableToExtendPCRError(err error) string {
	return fmt.Sprintf("No se ha podido extender la PCR: %s\n", err.Error())
}
func (c Spanish) UnableToReadOldPCRDigestError(err error) string {
	return fmt.Sprintf("No se ha podido leer la digest actual de la PCR, %s\n", err.Error())
}
func (c Spanish) UnableToReadNewPCRDigest(err error) string {
	return fmt.Sprintf("No se ha podido leer la digest de la PCR modificada, %s\n", err.Error())
}
func (c Spanish) OperationNotRecognizedError(badOp string) string {
	return fmt.Sprintf("Operación no reconocide: %s\n", badOp)
}
func (c Spanish) WrongCommandSizeError(actualSize, expectedSize int) string {
	return fmt.Sprintf("Tamaño del comando incorrecto, se esperaba %d, se ha usado %d\n", expectedSize, actualSize)
}
func (c Spanish) WrongHeaderSizeError(actualSize, expectedSize int) string {
	return fmt.Sprintf("Tamaño del header equivocado, se esperaba %d, se obtuvo %d\n", expectedSize, actualSize)
}
func (c Spanish) UnknownTagError(uTag uint16) string {
	return fmt.Sprintf("Tag del comando no reconocida, %x\n", uTag)
}
func (c Spanish) InvalidResponseSizeError(actualSize int) string {
	return fmt.Sprintf("Tamaño de la respuesta incorrecto, %d\n", actualSize)
}
func (c Spanish) NotEnoughCommandReadBytesError(expectedBytes, actualBytes int) string {
	return fmt.Sprintf("No se han leído suficientes bytes del comando, se esperaban %d, se leyeron %d\n", expectedBytes, actualBytes)
}
func (c Spanish) CommandFailedRCError(rc string) string {
	return fmt.Sprintf("El comando ha fallado con código %s\n", rc)
}
func (c Spanish) NoDigestError() string {
	return "No se ha obtenido ninguna digest de esta PCR\n"
}
func (c Spanish) WritingToPCRLog(pcr int, message string) string {
	return fmt.Sprintf("Escribiendo en la PCR %d el mensaje %s\n", pcr, message)
}
func (c Spanish) MessageToPCRLog(message string) string {
	return fmt.Sprintf("Escribiendo en la PCR el mensaje %s -> %x\n", message, []byte(message))
}
func (c Spanish) SavingOldPCRLog() string {
	return "Almacenando el valor actual de la PCR\n"
}
func (c Spanish) CurrentPCRDigestLog(pcr int, digest []byte) string {
	return fmt.Sprintf("Valor actual de  la digest de la PCR %d: %x\n", pcr, digest)
}
func (c Spanish) NewPCRDigestLog(pcr int, digest []byte) string {
	return fmt.Sprintf("Valor nuevo de la digest de la PCR %d: %x\n", pcr, digest)
}
func (c Spanish) PCRComparisionLog() string {
	return "Comparando la nueva digest con la antigua procesada\n"
}
func (c Spanish) HashesMatchLog() string {
	return "Las digests son las mismas\n"
}
func (c Spanish) HashesDoNotMatchLog() string {
	return "Las digests no son las mismas, un error ha ocurrido\n"
}
func (c Spanish) SendingCommandLog(cc uint32) string {
	return fmt.Sprintf("Lanzando comando con código %x\n", cc)
}
func (c Spanish) FullCommandLog(commandBytes []byte) string {
	return fmt.Sprintf("Bytes del comando: %x\n", commandBytes)
}
func (c Spanish) ReadingResponseHeaderLog() string {
	return "Leyendo el header de la respuesta\n"
}
func (c Spanish) TagLog(tag uint32) string {
	return fmt.Sprintf("Tag de la respuesta: %x\n", tag)
}
func (c Spanish) SessionHeaderAdditionalDataLog() string {
	return "Leyendo datos adicionales para respuesta de comando con sessiones\n"
}
func (c Spanish) ResponseHeaderLog(header []byte) string {
	return fmt.Sprintf("Datos del header: %x\n", header)
}
func (c Spanish) ReadingResponseBodyLog(body []byte) string {
	return fmt.Sprintf("Bytes del cuerpo: %x\n", body)
}

func (c Spanish) FailedToReadHeader(err error) string {
	return fmt.Sprintf("Fallo al leer el header de la respuesta: %s\n", err.Error())
}
func (c Spanish) FailedToReadBody(err error) string {
	return fmt.Sprintf("Fallo al leer el cuerpo de la respuesta: %s\n", err.Error())
}

func (c Spanish) ReadingHeaderLog() string {
	return "Leyendo el header de la respuesta:\n"
}
func (c Spanish) ReadingBodyLog() string {
	return "Leyendo el cuerpo de la respuesta:\n"
}

func (c Spanish) FailedToReadAdditionalHeaderData(err error) string {
	return fmt.Sprintf("Fallo al leer datos adicionales para respuesta de comando con sesiones, %s\n", err.Error())
}

func (c Spanish) HeaderDataLog(headerTag uint16, returnCode string, size uint32) string {
	return fmt.Sprintf("Tag: %x | Tamaño: %d | Código de respuesta: %s", headerTag, int(size), returnCode)
}
