package crypto

import (
	"math/rand"
	"testing"
)

//this will allow to test the function

// build a password generator function that will generate a password based on the given length and complexity attributes
// test the Checkpassword function
func TestCheckpassword(t *testing.T) {
	//test the password generator function
	if Checkpassword("Abcdefghij1!", true, true, true, true, SpecialList) == false {
		t.Errorf("Checkpassword() = %t; want true", Checkpassword("Abcdefghij1!", true, true, true, true, SpecialList))
	}
	//test the password generator function
	if Checkpassword("Abcdefghij1!", true, true, true, false, SpecialList) == false {
		t.Errorf("Checkpassword() = %t; want true", Checkpassword("Abcdefghij1!", true, true, true, true, SpecialList))
	}
	//test the special characters
	if Checkpassword("Abcdefghij1", true, true, true, true, SpecialList) == true {
		t.Errorf("Checkpassword() = %t; want false", Checkpassword("Abcdefghij1", true, true, true, true, SpecialList))
	}
	if Checkpassword("Abcdefghij1", true, true, true, false, SpecialList) == false {
		t.Errorf("Checkpassword() = %t; want true", Checkpassword("Abcdefghij1", true, true, true, false, SpecialList))
	}
	//test the lowercase
	if Checkpassword("ABCDEFGHIJ1!", true, true, true, true, SpecialList) == true {
		t.Errorf("Checkpassword() = %t; want false", Checkpassword("ABCDEFGHIJ1!", true, true, true, true, SpecialList))
	}
	if Checkpassword("ABCDEFGHIJ1!", false, true, true, true, SpecialList) == false {
		t.Errorf("Checkpassword() = %t; want true", Checkpassword("ABCDEFGHIJ1!", false, true, true, true, SpecialList))
	}
	//test the uppercase
	if Checkpassword("abcdefghij1!", true, true, true, true, SpecialList) == true {
		t.Errorf("Checkpassword() = %t; want false", Checkpassword("abcdefghij1!", true, true, true, true, SpecialList))
	}
	//test the uppercase
	if Checkpassword("abcdefghij1!", true, false, true, true, SpecialList) == false {
		t.Errorf("Checkpassword() = %t; want true", Checkpassword("abcdefghij1!", true, false, true, true, SpecialList))
	}
	//test the digit
	if Checkpassword("Abcdefghij!", true, true, true, true, SpecialList) == true {
		t.Errorf("Checkpassword() = %t; want false", Checkpassword("Abcdefghij!", true, true, true, true, SpecialList))
	}
	//test the digit
	if Checkpassword("Abcdefghij!", true, true, false, true, SpecialList) == false {
		t.Errorf("Checkpassword() = %t; want true", Checkpassword("Abcdefghij!", true, true, false, true, SpecialList))
	}

}

// Test the password generator function
func TestRandomPassword(t *testing.T) {

	//test the password generator function
	if RandomPassword(12, true, true, true, true, SpecialList) == "" {
		t.Errorf("RandomPassword() = %s; want not empty", RandomPassword(12, true, true, true, true, SpecialList))
	}
	//test the password generator function in couple with the checkpassword function 100 times
	for i := 0; i < 100; i++ {
		//randselect the length and the complexity
		//length := rand.Intn(8) + 1
		//fmt.Printf("Password Length: %d\n", length)
		lowercase := rand.Intn(2) == 0
		uppercase := rand.Intn(2) == 0
		digit := rand.Intn(2) == 0
		special := rand.Intn(2) == 0
		if pwd := RandomPassword(50, lowercase, uppercase, digit, special, SpecialList); Checkpassword(pwd, lowercase, uppercase, digit, special, SpecialList) == false {
			t.Errorf("RandomPassword() = %s; want passing the checkpassword %t for complexity %t,%t,%t,%t", pwd, Checkpassword(pwd, true, true, true, true, SpecialList), lowercase, uppercase, digit, special)
		}
	}
	// test if all contraints are false which fallback to use the space character and lenght
	if RandomPassword(12, false, false, false, false, SpecialList) != "            " {
		t.Errorf("RandomPassword() = >%s<; want 12 spaces", RandomPassword(12, false, false, false, false, SpecialList))
	}
}
