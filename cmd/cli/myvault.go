package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/abruno06/myvault/config"
	"github.com/abruno06/myvault/interactif"
	"github.com/abruno06/myvault/secret"
	"github.com/abruno06/myvault/securestore"
	"github.com/abruno06/myvault/smartcard"
)

var VAULTURL = "https://172.0.0.1:8200"
var APPNAME = "myapp"

// display the mene
func displayMenu() {
	fmt.Println("Select Action")
	fmt.Println("1. List Secrets")
	fmt.Println("2. Add Secret")
	fmt.Println("3. Delete Secret")
	fmt.Println("4. Update Secret")
	fmt.Println("5. Get Secret")
	fmt.Println("6. Read CSV File")
	fmt.Println("7. Random Password")
	fmt.Println("8. Generate Secret bootstrap token")
	fmt.Println("9. Generate Secret bootstrap token (list)")
	fmt.Println("10. Service Token bootstrap token")
	fmt.Println("11. Exit")
	fmt.Print("Enter Action Number: ")
}

// create a menu based cli with option to select the action
func menu(ctx context.Context, secstore securestore.SecretStore) {

	//display the current token
	for {
		displayMenu()
		var actionNumber int
		fmt.Scanln(&actionNumber)
		switch actionNumber {
		case 1:
			fmt.Println("List Secrets")
			securestore.ListSecrets(ctx, secstore)
		case 2:
			fmt.Println("Add Secret")
			interactif.AddSecretInteractive(ctx, secstore)
			securestore.ListSecrets(ctx, secstore)
		case 3:
			securestore.ListSecrets(ctx, secstore)
			fmt.Println("Delete Secret")
			interactif.DeleteSecretInteractive(ctx, secstore)
			securestore.ListSecrets(ctx, secstore)
		case 4:
			fmt.Println("Update Secret")
			interactif.UpdateSecretInteractive(ctx, secstore)
			securestore.ListSecrets(ctx, secstore)
		case 5:
			fmt.Println("Get Secret")
			s, _ := securestore.GetSecret(ctx, secstore, interactif.AskSecret())
			fmt.Printf("Secret ID:\n%s", s)
		case 6:
			fmt.Println("Read CSV File")
			fmt.Print("Enter CSV Filename: ")
			var filename string
			fmt.Scanln(&filename)
			readCSV(ctx, secstore, filename)
			securestore.ListSecrets(ctx, secstore)
		case 7:
			interactif.RandomPassword()
		case 8:
			interactif.GenerateBootstrapToken(ctx, secstore)
		case 9:
			interactif.GenerateBootstrapTokenList(ctx, secstore)
		case 10:
			interactif.GenerateServiceToken(ctx, secstore)
		case 11:
			fmt.Println("Exit")
			return
		default:
			fmt.Println("Exit")
			return
		}

	}
}

//check if yubikey is plugged in and return bool

// CSV record to Secret
func csvToSecret(record []string) secret.Secret {
	rValue := secret.Secret{
		Username:     record[1],
		Credential:   record[2],
		URL:          record[3],
		Comment:      record[4],
		LastUpdate:   time.Now(),
		LastUpdateBy: config.User,
	}
	return rValue
}

// readCSV file and insert the data in vault as Secret
func readCSV(ctx context.Context, secstore securestore.SecretStore, filename string) {
	//read the csv file
	// Open the file
	csvfile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	// Parse the file
	r := csv.NewReader(csvfile)
	// Iterate through the records and insert them in vault. stop when EOF
	for {
		// Read each record from csv
		// CSV Format is
		// ID,Username,Credential,URL,Comment
		// LastUpdate,LastUpdateBy are automatically added

		record, err := r.Read()
		if err != nil {
			fmt.Println(err)
			break

		}
		fmt.Printf("Record: %v\n", record)
		//ask the Secret detail
		securestore.AddSecret(ctx, secstore, csvToSecret(record), record[0])

	}

}

// main function
func main() {
	//read the configuration file
	//fmt.Printf("config:%s")
	//prepare the context
	ctx := context.Background()
	//print the default the app is running
	fmt.Printf("%s is running with APPNAME: %s and VAULTURL: %s\n", os.Args[0], config.ReadAPPNAME(), config.ReadVaultURL())
	var secstore securestore.SecretStore
	var e error
	// check yubikey is plugged in
	if smartcard.CheckYubikey() {

		yk := smartcard.OpenYubikey(interactif.SelectSmartcard())
		defer yk.Close()
		cert := smartcard.ReadYubikeyCertificate(yk, smartcard.SelectSlot())
		//fmt.Printf("Certificate: %v\n", cert)
		//fmt.Printf("Certificate: %v\n", cert.PublicKey)
		fmt.Printf("Certificate: %v\n", cert.PublicKeyAlgorithm)
		//ask user pin
		pin := interactif.ReadPin()
		secstore, e = securestore.ConnectVaulwithYubikey(ctx, yk, pin)
		if e != nil {
			fmt.Println("Bad Pin. Falling back to username and password")
			username, password := interactif.ReadUsernamePassword()
			secstore, e = securestore.ConnectVaultWithUsernamePassword(ctx, username, password)
		}
	} else {
		fmt.Println("No Yubikey found. Falling back to username and password")
		//ask username and password
		username, password := interactif.ReadUsernamePassword()
		secstore, e = securestore.ConnectVaultWithUsernamePassword(ctx, username, password)

	}
	if e != nil {
		log.Fatal(e)
	}
	menu(ctx, secstore)

}
