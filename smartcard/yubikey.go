package smartcard

import (
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
