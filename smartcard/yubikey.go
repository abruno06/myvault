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
	//fmt.Printf("List all cards %s\n", cards)
	// Connect to the YubiKey (you can specify the reader name, or leave it empty to use the default reader).
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
	// Select the PIV slot you want to read (e.g., Authentication, Signature, etc.).
	//slot := piv.SlotAuthentication // You can change this to the slot you are interested in.

	//read the personal certificate
	cert, err := yubikey.Certificate(slot)
	if err != nil {
		log.Printf("readYubikeyCertificate: %v", err)
		log.Fatal(err)
	}
	return cert
}
