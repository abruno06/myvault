package main

import (
	"context"
	"fmt"
	"os"

	"github.com/abruno06/myvault/securestore"
)

func main() {
	ctx := context.Background()
	//check if arg[1] is present
	if len(os.Args) < 2 {
		fmt.Printf("Error: Missing token\n")
		os.Exit(1)
	}
	//retreive the token from the Arg[1]
	token := os.Args[1]
	var secstore securestore.SecretStore
	var e error
	//connect to vault
	secstore, err := securestore.ConnectVault(ctx)
	//r, e := vault.Unwrap[schema.KvV2ReadResponse](ctx, client, token)
	if err != nil {
		fmt.Printf("Error connecting to vault: %v\n", e)
		os.Exit(1)
	}
	//retreive the unWrapped token from input token
	uWrapp, err := securestore.UnWrappeToken(ctx, secstore, token)
	if err != nil {
		fmt.Printf("Error UnWrapping token: %v\n", err)
		os.Exit(1)
	}
	//display the Secret
	fmt.Printf("%s\n", uWrapp)

}
