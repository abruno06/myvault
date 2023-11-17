package main

//this tools will take a tken as input and return the list of all cubbyhole entries as json format
import (
	"context"
	"fmt"
	"os"

	"github.com/abruno06/myvault/securestore"
)

// dispaly how to use the tool
func usage() {
	fmt.Printf("Usage: %s <token>\n", os.Args[0])
}

func main() {
	ctx := context.Background()
	//check if arg[1] is present
	if len(os.Args) < 2 {
		fmt.Printf("Error: Missing token\n")
		usage()
		os.Exit(1)
	}
	//retreive the token from the Arg[1]
	token := os.Args[1]
	var secstore securestore.SecretStore
	var e error
	//connect to vault using given token
	secstore, err := securestore.ConnectVaultWithToken(ctx, token)
	if err != nil {
		fmt.Printf("Error connecting to vault: %v\n", e)
		os.Exit(1)
	}

	json, err := securestore.ListCubbyhole(ctx, secstore)
	if err != nil {
		fmt.Printf("Error Getting Cubbyhole list: %v\n", err)
		os.Exit(1)
	}
	//display the JSON
	fmt.Printf("%s\n", json)
}
