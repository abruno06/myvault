package smartcard

import (
	"crypto/x509"
	"log"
	"strings"

	"github.com/go-piv/piv-go/piv"
)

// open yubikey
func OpenYubikey(smartcard string) *piv.YubiKey {
	// List all smartcards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		log.Fatal(err)
	}
	// Find a YubiKey and open the reader.
	var yubikey *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), smartcard) {
			if yubikey, err = piv.Open(card); err != nil {
				log.Fatal(err)
			}
			break
		}
	}
	if yubikey == nil {
		log.Fatal("No YubiKey found")
	}
	return yubikey
}

// read yubikey certificate
func ReadYubikeyCertificate(yubikey *piv.YubiKey, slot piv.Slot) *x509.Certificate {
	//read the personal certificate
	cert, err := yubikey.Certificate(slot)
	if err != nil {
		log.Printf("readYubikeyCertificate: %v", err)
		log.Fatal(err)
	}
	return cert
}

func CheckYubikey() bool {
	yubikey, err := piv.Cards()
	if err != nil {
		log.Fatal(err)
	}
	if len(yubikey) == 0 {
		return false
	}
	return true
}
