package tpm2

import (
	"fmt"
	"go-tpm2/internal"
	"go-tpm2/customCatalogs"
	"go-tpm2/tpm"
	"regexp"
	"slices"
)

var langCatalog customCatalogs.Catalog

func init() {

	langCatalog = customCatalogs.English{}

}

func LoadTPM(path string) (tpm.TPM, error) {

	module := tpm.TPM{}

	var usePath string
	if path == "" {
		usePath = "/dev/tpm0"
	} else if match, _ := regexp.Match(".*tpm.*0", []byte(path)); !match {
		return module, fmt.Errorf("Incorrect path, %s, does not seem like a TPM path\n", path)
	} else {
		usePath = path
	}

	err := module.Load(usePath)

	return module, err

}

func ExtendPCR(mod *tpm.TPM, pcr int, msg string, catalog customCatalogs.Catalog) error {
	fmt.Print(catalog.WritingToPCRLog(pcr, msg))

	pcrDigest, err := mod.ReadPCR(uint(pcr), catalog)

	if err != nil {
		return fmt.Errorf(catalog.UnableToReadOldPCRDigestError(err), "")
	}

	fmt.Print(catalog.CurrentPCRDigestLog(pcr, pcrDigest))
	fmt.Print(catalog.SavingOldPCRLog())

	oldDigest := pcrDigest

	data := []byte(msg)

	fmt.Print(catalog.MessageToPCRLog(msg))

	err = mod.ExtendPCR(pcr, data, catalog)

	if err != nil {
		return fmt.Errorf(catalog.UnableToExtendPCRError(err), "")
	}

	pcrDigest, err = mod.ReadPCR(uint(pcr), catalog)

	if err != nil {
		return fmt.Errorf(catalog.UnableToReadNewPCRDigest(err), "")
	}

	fmt.Print(catalog.NewPCRDigestLog(pcr, pcrDigest))

	fmt.Print(catalog.PCRComparisionLog())

	isExtended := auxilia.CheckPCRIsExtended(oldDigest, pcrDigest, data)

	if isExtended {
		fmt.Print(catalog.HashesMatchLog())
	} else {
		fmt.Print(catalog.HashesDoNotMatchLog())
	}

	return nil
}

func EncapsulateInfo(mod tpm.TPM, data string, catalog customCatalogs.Catalog) (uint32, error) {

	dataBytes := []byte(data)

	primary, err := mod.CreatePrimary(catalog)

	fmt.Printf("Primary value: %x\n", primary)

	if err != nil {
		fmt.Printf("Unable to create primary bind to PCRs, %s\n", err.Error())
		return 0, err
	}

	privKey, pubKey, err := mod.CreateSealed(primary, dataBytes, catalog)
	if err != nil {

		fmt.Printf("Unable to create sealed data container, %s\n", err.Error())
		return 0, err
	}

	//here we assume that we store the keys and the primary

	sealedData, err := mod.LoadSealedObject(primary, privKey, pubKey, catalog)

	if err != nil {
		fmt.Printf("Unable to load sealed data, %s\n", err.Error())
		return 0, err
	}

	return sealedData, nil

}

func DeencapsulateInfo(mod tpm.TPM, handle uint32, catalog customCatalogs.Catalog) ([]byte, error) {
	returnData, err := mod.UnsealObject(handle, catalog)
	if err != nil {

		fmt.Printf("Unable to unseal the data, %s\n", err.Error())
	}

	return returnData, nil
}

func TestGetEK(mod *tpm.TPM, catalog customCatalogs.Catalog) {

	parent, err := mod.CreateTempEK(catalog)

	if err != nil {
		fmt.Printf("Error while getting parent, %s\n", err.Error())
		return
	}

	fmt.Printf("Parent handle: %x\n", parent)

	ek, name, err := mod.ReadPublic(catalog, parent)

	if err != nil {
		fmt.Printf("Error while fetching endorsement key: %s\n", err.Error())
		return
	}

	fmt.Printf("EK: %x, EK NAME: %x\n", ek, name)

	pub, priv, err := mod.CreateAK(parent, catalog)

	if err != nil {
		fmt.Println("Error while getting AK, ", err.Error())
		return
	}

	akHandle, err := mod.LoadSealedObject(parent, priv, pub, catalog)

	if err != nil {
		fmt.Printf("unable to load ak handle: %s\n", err.Error())
		return
	}

	fmt.Printf("Attestation key handle: %x, attestation key public: %x, attestation key private: %x\n", akHandle, pub, priv)

	// server processes start here
	akName := auxilia.GetAKName(pub)

	credential, err := auxilia.GenerateRandomCredential()

	if err != nil {
		fmt.Println("unable to generate random credential, ", err.Error())
		return
	}

	// server processes end here
	blob, encSecret, err := mod.MakeCredential(parent, credential, akName, catalog)

	if err != nil {
		fmt.Println("error while processing the blob: ", err.Error())
		return
	}

	posCred, err := mod.ActivateCredential(akHandle, parent, encSecret, blob, catalog)

	if err != nil {
		fmt.Printf("Error while activating the credential, %s\n", err.Error())
		return
	}

	//this last part should be done by the server in the final release, not the client
	if slices.Equal(credential, posCred) {
		fmt.Println("Credentials match")
	} else {
		fmt.Println("Credentials do not match")
	}

}
