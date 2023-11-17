package main

import (
	"context"
	"fmt"
	"os"

	"github.com/abruno06/myvault/securestore"
)

// this tools will take as input a token and an action within the list of actions and execute the proper token function
// return will be json format if no error
const ActionsList = "renew,revoke"

func usage() {
	fmt.Printf("Usage: %s <token> <action>\n", os.Args[0])
	fmt.Printf("action: %s\n", ActionsList)
}
func main() {
	ctx := context.Background()
	//check if arg[1] is present
	if len(os.Args) < 3 {
		fmt.Printf("Error: Missing token and/or action\n")
		usage()
		os.Exit(1)
	}
	//retreive the token from the Arg[1]
	token := os.Args[1]
	action := os.Args[2]
	var secstore securestore.SecretStore
	var e error
	//connect to vault using given token
	secstore, err := securestore.ConnectVaultWithToken(ctx, token)
	if err != nil {
		fmt.Printf("Error connecting to vault: %v\n", e)
		os.Exit(1)
	}

	switch action {
	case "renew":
		//renew the token
		err := securestore.RenewToken(ctx, secstore, token)
		if err != nil {
			fmt.Printf("Error Renewing token: %v\n", err)
			os.Exit(1)
		}
		//fmt.Printf("Token Renewed\n")
	case "revoke":
		//revoke the token
		err := securestore.RevokeToken(ctx, secstore, token)
		if err != nil {
			fmt.Printf("Error Revoking token: %v\n", err)
			os.Exit(1)
		}
	//	fmt.Printf("Token Revoked\n")
	default:
		fmt.Printf("Error: Invalid action\n")
		usage()
		os.Exit(1)
	}
}
