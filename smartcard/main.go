package smartcard

import (
	"fmt"

	"github.com/go-piv/piv-go/piv"
)

// select yubikey slot
func SelectSlot() piv.Slot {
	var slot piv.Slot
	fmt.Println("Select Yubikey Slot (Default is Authentication)")
	fmt.Println("1. Authentication")
	fmt.Println("2. Signature")
	fmt.Println("3. Key Management")
	fmt.Println("4. Card Authentication")
	fmt.Print("Enter Slot Number: ")
	var slotNumber int
	fmt.Scanln(&slotNumber)
	switch slotNumber {
	case 1:
		slot = piv.SlotAuthentication
	case 2:
		slot = piv.SlotSignature
	case 3:
		slot = piv.SlotKeyManagement
	case 4:
		slot = piv.SlotCardAuthentication
	default:
		slot = piv.SlotAuthentication
	}
	return slot
}
