package interactif

import "fmt"

// this package will contain all the functions to interact with the user

// this function will ask the user to enter the value of the field and return the value as map[string]string
func AskUser(Previous []map[string]string) map[string]string {
	fieldValues := make(map[string]string)

	for key, field := range Previous[0] {
		var value string
		if key == "Credential" {
			rndPwd := "ee" //crypto.randomPassword(12, true, true, true, true, "!@#$%^&*()_+-")
			fmt.Printf("Enter %s: (%s) (* if you want random) ", key, field)
			fmt.Scanln(&value)
			if value == "*" {
				value = rndPwd
			} else if value == "" {
				value = field
			}
			fieldValues[key] = value
		} else {
			fmt.Printf("Enter %s: (%s) ", key, field)

			fmt.Scanln(&value)
			if value == "" {
				value = field
			}
		}
		fieldValues[key] = value
	}
	return fieldValues

}
