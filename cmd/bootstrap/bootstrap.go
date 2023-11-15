package main

import (
	"context"
	"fmt"
	"os"

	"github.com/abruno06/myvault/config"
	"github.com/abruno06/myvault/securestore"
)

func main() {
	ctx := context.Background()
	//retreive the token from the Arg[1]
	token := os.Args[1]
	fmt.Printf("myvault is running with APPNAME: %s and VAULTURL: %s\n", config.ReadAPPNAME(), config.ReadVaultURL())
	var secstore securestore.SecretStore
	var e error
	//connect to vault
	//secstore, e = securestore.ConnectVaultWithToken(ctx, token)
	//var client *vault.Client
	secstore, err := securestore.ConnectVault(ctx)
	//r, e := vault.Unwrap[schema.KvV2ReadResponse](ctx, client, token)
	if err != nil {
		fmt.Printf("Error connecting to vault: %v\n", e)
		os.Exit(1)
	}
	//fmt.Printf("Secret: %v\n", r)
	//retreive the unWrapped token from input token
	uWrapp, err := securestore.UnWrappeSecret(ctx, secstore, token)
	if err != nil {
		fmt.Printf("Error UnWrapping token: %v\n", err)
		os.Exit(1)
	}
	//display the Secret
	fmt.Printf("UnWrapped Token:\n%s\n", uWrapp)

}
