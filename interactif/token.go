package interactif

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/abruno06/myvault/securestore"
	"github.com/google/uuid"
)

// this function will create a service token, will store it in a cubbyhole entry and will return the wrap token
func GenerateServiceToken(ctx context.Context, secstore securestore.SecretStore) string {
	fmt.Println("Generate Service Token")
	fmt.Print("Enter Token TTL (in minutes): ")
	var ttl int
	fmt.Scanln(&ttl)
	//if empty use default
	if ttl == 0 {
		ttl = 24
		fmt.Printf("Token TTL: %d\n", ttl)
	}

	serviceToken, _ := securestore.CreateToken(ctx, secstore, []string{"service"})
	//display the service token
	fmt.Printf("Service Token: %s\n", serviceToken)
	wToken, err := securestore.WrapToken(ctx, secstore, serviceToken, time.Duration(ttl)*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Service Wrap Token: %s\n", wToken)

	//ask the secret list to the user
	fmt.Print("Enter Secret ID List (comma separated): ")
	var secretIDList string
	fmt.Scanln(&secretIDList)

	uuid := uuid.New().String()
	wSecretToken, err := securestore.WrapSecretList(ctx, secstore, strings.Split(secretIDList, ","), uuid, time.Duration(ttl)*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Bootstrap Secret Token: %s\n", wSecretToken)

	//build a token securestore to store the secrets in the cubbyhole
	newSecstore, err := securestore.ConnectVaultWithToken(ctx, serviceToken)
	if err != nil {
		log.Fatalf("Error connecting to Vault using service token: %v\n", err)

	}
	//get the secret list using the wSecretToken
	//fmt.Printf("Secret: %v\n", r)
	//retreive the unWrapped token from input token
	uWrapp, err := securestore.UnWrappeSecret(ctx, newSecstore, wSecretToken)
	if err != nil {
		log.Fatalf("Error UnWrapping token: %v\n", err)
	}
	// store the secrets on the cubbyhole for the service token
	err = securestore.SetServiceSecretCubbyhole(ctx, newSecstore, uWrapp)
	if err != nil {
		log.Fatalf("Error storing the secret list in the cubbyhole: %v\n", err)
	}

	return wToken
}
