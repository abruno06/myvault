package interactif

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/abruno06/myvault/crypto"
	"github.com/abruno06/myvault/securestore"
	"github.com/google/uuid"
)

// return random password after asking the user for the length and complexity
func RandomPassword() {
	fmt.Println("Random Password")
	fmt.Print("Enter Password Length: ")
	var length int
	fmt.Scanln(&length)
	// if empty use default
	if length == 0 {
		length = 12
		fmt.Printf("Password Length: %d\n", length)
	}
	fmt.Print("Enter Password Complexity (l=lowercase, u=uppercase, d=digit, s=special): ")
	var complexity string
	fmt.Scanln(&complexity)
	// if empty use default
	if complexity == "" {
		complexity = "luds"
		fmt.Printf("Password Complexity: %s\n", complexity)
	}
	fmt.Print("Enter Special Characters: ")
	var special string
	fmt.Scanln(&special)
	// if empty use default
	if special == "" {
		special = "!@#$%^&*()_+-"
		fmt.Printf("Special Characters: %s\n", special)
	}
	fmt.Printf("Password: %s\n", crypto.RandomPassword(length, strings.Contains(complexity, "l"), strings.Contains(complexity, "u"), strings.Contains(complexity, "d"), strings.Contains(complexity, "s"), special))
}

// this function will create a temporary token that will return the secret once unwrapped
func GenerateBootstrapToken(ctx context.Context, secstore securestore.SecretStore) {
	fmt.Println("Generate bootstrap token")
	fmt.Print("Enter Token TTL (in minutes): ")
	var ttl int
	fmt.Scanln(&ttl)
	//if empty use default
	if ttl == 0 {
		ttl = 24
		fmt.Printf("Token TTL: %d\n", ttl)
	}
	//select the SecretId
	fmt.Print("Enter Secret ID: ")
	var secretID string
	fmt.Scanln(&secretID)
	wToken, err := securestore.WrapSecret(ctx, secstore, secretID, time.Duration(ttl)*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bootstrap Token: %s\n", wToken)
}

// this function will create a temporary token that will return the lsit of secrets once unwrapped
func GenerateBootstrapTokenList(ctx context.Context, secstore securestore.SecretStore) {
	fmt.Println("Generate bootstrap token for list of Secrets")
	fmt.Print("Enter Token TTL (in minutes): ")
	var ttl int
	fmt.Scanln(&ttl)
	//if empty use default
	if ttl == 0 {
		ttl = 24
		fmt.Printf("Token TTL: %d\n", ttl)
	}
	//select the SecretId
	fmt.Print("Enter Secret ID CSV list: ")
	var secretID string
	fmt.Scanln(&secretID)
	//generate uuid string
	uuid := uuid.New().String()
	wToken, err := securestore.WrapSecretList(ctx, secstore, strings.Split(secretID, ","), uuid, time.Duration(ttl)*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bootstrap Token: %s\n", wToken)
}

// this function will ask the user to select a list of secret, then will create a cubbyhole entry with the list of secret
// then a service token will be created with selected policies and will be used to read the token of the cubbyhole entry genereated above
// the  function will switch the client to be this new token and will store the list of secret in the token cubbyh
// the service token will be returned to the user and will be used to unwrap the cubbyhole entry
