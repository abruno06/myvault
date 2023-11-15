package crypto

import (
	"math/rand"
	"strings"
)

const SpecialList = "!@#$%^&*()_+-"

// validate if the password is meeting the complexity requirements
func Checkpassword(password string, lowercase, uppercase, digit, special bool, specialList string) bool {
	//check if the password is meeting the complexity requirements
	if lowercase {
		if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
			return false
		}
	}
	if uppercase {
		if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return false
		}
	}
	if digit {
		if !strings.ContainsAny(password, "0123456789") {
			return false
		}
	}
	if special {
		if !strings.ContainsAny(password, specialList) {
			return false
		}
	}
	return true
}

// build a password generator function that will generate a password based on the given length and complexity attributes
// the password will be returned as string
func RandomPassword(lengh int, lowercase, uppercase, digit, special bool, specialList string) string {

	if lengh < 0 {
		lengh = 12
	}
	//build the list of characters
	var charList string
	if lowercase {
		charList = charList + "abcdefghijklmnopqrstuvwxyz"
	}
	if uppercase {
		charList = charList + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if digit {
		charList = charList + "0123456789"
	}
	if special {
		charList = charList + specialList
	}

	var rValue string
	// this loop will generate a password until it matches the constraints
	// the password will be returned as string
	// this is one possible implementation, there are many others
	for {
		//build the password using this constraints
		// countains at least one lowercase character
		// countains at least one uppercase character
		// countains at least one digit
		// countains at least one special character
		// countains at least one character from the given list
		for i := 0; i < lengh; i++ {
			rValue = rValue + string(charList[rand.Intn(len(charList))])
		}
		//check constraints
		if Checkpassword(rValue, lowercase, uppercase, digit, special, specialList) {
			break
		} else {
			rValue = ""
			continue
		}
	}
	return rValue

}
