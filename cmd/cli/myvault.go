package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

var VAULTURL = "https://172.0.0.1:8200"
var APPNAME = "myapp"

// reset to this
type Secret struct {
	Username     string
	Credential   string
	URL          string //optional
	Comment      string
	LastUpdate   time.Time
	LastUpdateBy string
}

var SecretFieldNames = []string{"Username", "Credential", "URL", "LastUpdate", "LastUpdateBy", "Comment"}
var SecretHumanFieldNames = []string{"Username", "Credential", "URL", "Comment"}

var User = func() string {
	if os.Getenv("USER") != "" {
		return os.Getenv("USER")
	}
	return "unknown"
}()

// select yubikey slot
func selectSlot() piv.Slot {
	var slot piv.Slot
	fmt.Println("Select Yubikey Slot (Default is Authentication)")
	fmt.Println("1. Authentication")
	fmt.Println("2. Signature")
	fmt.Println("3. Key Management")
	fmt.Println("4. Card Authentication")
	fmt.Print("Enter Slot Number: ")
	var slotNumber int
	fmt.Scanln(&slotNumber)
	switch slotNumber {
	case 1:
		slot = piv.SlotAuthentication
	case 2:
		slot = piv.SlotSignature
	case 3:
		slot = piv.SlotKeyManagement
	case 4:
		slot = piv.SlotCardAuthentication
	default:
		slot = piv.SlotAuthentication
	}
	return slot
}

// select yubikey smartcard
func selectSmartcard() string {
	var smartcard string
	fmt.Println("Select Smartcard (Default is Yubikey)")
	fmt.Println("1. Yubikey")
	fmt.Println("2. Nitrokey")
	fmt.Println("3. Other")
	fmt.Print("Enter Smartcard Number: ")
	var smartcardNumber int
	fmt.Scanln(&smartcardNumber)
	switch smartcardNumber {
	case 1:
		smartcard = "yubikey"
	case 2:
		smartcard = "nitrokey"
	case 3:
		smartcard = "other"
	default:
		smartcard = "yubikey"
	}
	return smartcard
}

// open yubikey
func openYubikey(smartcard string) *piv.YubiKey {
	// List all smartcards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("List all cards %s\n", cards)
	// Connect to the YubiKey (you can specify the reader name, or leave it empty to use the default reader).
	// Find a YubiKey and open the reader.
	var yubikey *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), smartcard) {
			if yubikey, err = piv.Open(card); err != nil {
				log.Fatal(err)
			}
			break
		}
	}
	if yubikey == nil {
		log.Fatal("No YubiKey found")
	}
	return yubikey
}

// read yubikey certificate
func readYubikeyCertificate(yubikey *piv.YubiKey, slot piv.Slot) *x509.Certificate {
	// Select the PIV slot you want to read (e.g., Authentication, Signature, etc.).
	//slot := piv.SlotAuthentication // You can change this to the slot you are interested in.

	//read the personal certificate
	cert, err := yubikey.Certificate(slot)
	if err != nil {
		log.Printf("readYubikeyCertificate: %v", err)
		log.Fatal(err)
	}
	return cert
}

// read user input for smartcard pin
func readPin() string {
	fmt.Print("Enter PIN: ")
	var pin string
	fmt.Scanln(&pin)
	//	fmt.Printf("PIN: %s\n", pin)
	return pin
}

//Vault piece

// connect to vault with specific tls config
func connectVaultWithTLSConfig(ctx context.Context, tlsConfig *tls.Config) (*vault.Client, error) {
	// prepare a client with the given base address

	client, err := vault.New(
		vault.WithAddress(readVaultURL()),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	//set the transport configuration
	httpclient := client.Configuration().HTTPClient
	transport := httpclient.Transport
	transport.(*http.Transport).TLSClientConfig = tlsConfig
	// Authenticate with the Vault server using ceritificate
	resp, err := client.Auth.CertLogin(ctx, schema.CertLoginRequest{Name: readCertificateName()})
	if err != nil {
		fmt.Printf("CertLogin error: %v\n", err)
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)

	}

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		log.Fatal(err)

	}
	return client, err
}

// connect to vault with yubikey
func connectVaulwithYubikey(ctx context.Context, yubikey *piv.YubiKey) (*vault.Client, error) {
	//set the slot to authentication
	slot := piv.SlotAuthentication // You can change this to the slot you are interested in.

	//read the personal certificate
	cert := readYubikeyCertificate(yubikey, slot)

	//read the pin from the user
	pin := readPin()
	//test the pin is correct
	if err := yubikey.VerifyPIN(pin); err != nil {
		//fallback to username and password as pin is not correct
		//read the username and password from the user
		fmt.Println("PIN is not correct, fallback to username and password")
		username, password := readUsernamePassword()
		return connectVaultWithUsernamePassword(ctx, username, password)
	}

	// set the auth
	auth := piv.KeyAuth{PIN: pin}
	//get the private key accessors
	priv, err := yubikey.PrivateKey(slot, cert.PublicKey, auth)
	if err != nil {
		log.Fatal(err)
	}
	// Load the CA certificate of the server ("./cert/server.pem")
	caCert, err := os.ReadFile("./cert/server.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Create a certificate pool with the CA certificate
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a TLS configuration with the client certificate and CA certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  priv,
		}},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}
	// the Yukibykey certificate and private retrieval is complete

	// print tls config
	//fmt.Printf("TLS Config: %v\n", tlsConfig)
	// Prepare Vault Connection

	//log client token returned
	//log.Printf("Client Token: %v", resp.Auth.ClientToken)
	return connectVaultWithTLSConfig(ctx, tlsConfig)
}

// connect to vault using username and password and return the client
func connectVaultWithUsernamePassword(ctx context.Context, username, password string) (*vault.Client, error) {
	// Prepare Vault Connection

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(readVaultURL()),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}
	// Authenticate with the Vault server using username and password
	resp, err := client.Auth.UserpassLogin(ctx, username, schema.UserpassLoginRequest{Password: password})
	if err != nil {
		log.Fatal(err)
	}

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		log.Fatal(err)

	}

	return client, err

}

// ask for username and password and return them
func readUsernamePassword() (string, string) {
	fmt.Print("Enter Username: ")
	var username string
	fmt.Scanln(&username)
	fmt.Print("Enter Password: ")
	var password string
	fmt.Scanln(&password)
	return username, password
}

// convert the map[string]interface {}  to Secret
// return the secret and true if the conversion is successful otherwise return empty secret and false
func convertToSecret(object map[string]interface{}) (Secret, bool) {
	rValue := Secret{}
	var ok bool
	rValue.Username, ok = object["Username"].(string)
	if !ok {
		return rValue, ok
	}
	rValue.Credential, ok = object["Credential"].(string)
	if !ok {
		return rValue, ok
	}
	rValue.Comment, ok = object["Comment"].(string)
	if !ok {
		return rValue, ok
	}
	rValue.URL, ok = object["URL"].(string)
	if !ok {
		return rValue, ok
	}
	if object["LastUpdate"] == nil {
		rValue.LastUpdate, _ = time.Parse("2006-01-02 15:04:05", "0001-01-01 00:00:00 ")
	} else {
		rValue.LastUpdate, _ = time.Parse("2006-01-02T15:04:05.999999-07:00", object["LastUpdate"].(string))
	}
	rValue.LastUpdateBy, _ = object["LastUpdateBy"].(string)
	return rValue, ok
}

// this function will ask the user to enter the secret id and it will search it in vault and allow update it if the secret did not expire
func updateSecretInteractive(ctx context.Context, client *vault.Client, mountpath string) error {
	//read the secret id from the user
	fmt.Print("Enter Secret ID: ")
	var secretID string
	fmt.Scanln(&secretID)
	//fmt.Printf("Secret ID: %s\n", secretID)
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//read the secret from the user
	fieldNames := SecretHumanFieldNames
	fieldValues := make(map[string]string)
	for _, fieldName := range fieldNames {
		if fieldValue, ok := s.Data.Data[secretID].(map[string]interface{})[fieldName]; ok {
			fieldValues[fieldName] = fieldValue.(string)
		} else {
			fieldValues[fieldName] = "" // Default to empty string if the field is not present
		}
	}

	s.Data.Data[secretID] = askSecretParameter(fieldValues)
	_, err = client.Secrets.KvV2Write(ctx, readAPPNAME(), schema.KvV2WriteRequest{
		Data: s.Data.Data,
	},
		vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}

// function will ask for secret parameter and return as  Secret struct
func askSecretParameter(Previous ...map[string]string) Secret {
	//read the secret from the user
	fieldValues := make(map[string]string)
	if len(Previous) > 0 {
		for key, field := range Previous[0] {
			var value string
			if key == "Credential" {
				rndPwd := randomPassword(12, true, true, true, true, "!@#$%^&*()_+-")
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
	} else {
		for _, field := range SecretHumanFieldNames {
			var value string
			if field == "Credential" {
				rndPwd := randomPassword(10, true, true, true, true, "!@#$%^&*()_+-")
				fmt.Printf("Enter %s (or hit enter to have autogenerated) ", field)
				fmt.Scanln(&value)
				if value == "" {
					value = rndPwd
				}
			} else {
				fmt.Printf("Enter %s: ", field)
				fmt.Scanln(&value)
			}
			fieldValues[field] = value
		}
	}
	rValue := Secret{
		Username:     fieldValues["Username"],
		Credential:   fieldValues["Credential"],
		URL:          fieldValues["URL"],
		Comment:      fieldValues["Comment"],
		LastUpdate:   time.Now(),
		LastUpdateBy: User,
	}
	return rValue
}

// this function take vault client will ask the user to enter a secret id and it will be searched in vault and returned it if the secret did not expire then return nil
func askSecret(ctx context.Context, client *vault.Client, mountpath string) (Secret, error) {
	//read the secret id from the user
	fmt.Print("Enter Secret ID: ")
	var secretID string
	fmt.Scanln(&secretID)
	//fmt.Printf("Secret ID: %s\n", secretID)
	rValue := Secret{}
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err == nil {
		vValue := s.Data.Data
		if vValue[secretID] != nil {
			var ok bool
			rValue, ok = convertToSecret(vValue[secretID].(map[string]interface{}))
			if !ok {
				log.Printf("Secret ID: %s not valid secret\n", vValue[secretID])
				log.Printf("Secret ID: is type %T \n", vValue[secretID])
				rValue = Secret{}
				err = fmt.Errorf("Secret ID: %s not valid secret", vValue[secretID])
			}
			//fmt.Printf("Secret: %v\n", rValue)
		} else {
			fmt.Printf("Secret ID: %s not found\n", secretID)
			rValue = Secret{}
		}
	}

	//fmt.Printf("Secret: %v\n", s.Data)
	return rValue, err
}
func getSecret(ctx context.Context, client *vault.Client, secretID, mountpath string) (Secret, error) {

	rValue := Secret{}
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err == nil {
		vValue := s.Data.Data
		if vValue[secretID] != nil {
			var ok bool
			rValue, ok = convertToSecret(vValue[secretID].(map[string]interface{}))
			if !ok {
				log.Printf("Secret ID: %s not valid secret\n", vValue[secretID])
				log.Printf("Secret ID: is type %T \n", vValue[secretID])
				rValue = Secret{}
				err = fmt.Errorf("Secret ID: %s not valid secret", vValue[secretID])
			}
			//fmt.Printf("Secret: %v\n", rValue)
		} else {
			fmt.Printf("Secret ID: %s not found\n", secretID)
			rValue = Secret{}
		}
	}

	//fmt.Printf("Secret: %v\n", s.Data)
	return rValue, err
}

// this function list all secrets in vault for the given mountpath and readAPPNAME() and display them in tabuuar format
func listSecrets(ctx context.Context, client *vault.Client, mountpath string) error {
	//read the secret for the readAPPNAME()
	list, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err != nil {
		//log.Fatal(err)
		log.Println("No secrets found")
	}
	//fmt.Printf("List: %v\n", list)
	//display all secrets found in tabular format
	// Create a tabwriter
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	columns := SecretFieldNames
	//create the format
	format := "%s\t%s\t%s\t%s\t%s\t%s\t%s\n"
	//print the header
	fmt.Fprintf(w, format, "ID", columns[0], columns[1], columns[2], columns[3], columns[4], columns[5])
	//print the data
	//make data order in alphabetical order
	Data := list.Data.Data
	var keys []string
	for key := range Data {
		keys = append(keys, key)
	}
	// Sort the keys case-insensitively
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})

	for _, k := range keys {
		var ok bool
		v := Data[k]
		secret, ok := convertToSecret(v.(map[string]interface{}))
		if ok {
			fmt.Fprintf(w, format, k, secret.Username, secret.Credential, secret.URL, secret.LastUpdate.UTC().Format("2006-01-02 15:04:05"), secret.LastUpdateBy, secret.Comment)

		}
	}
	w.Flush()
	return err

}

func addSecret(ctx context.Context, client *vault.Client, mountpath, secretID string, secret Secret) error {
	//read the secret id from the user

	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//ask the Secret detail
	s.Data.Data[secretID] = secret

	_, err = client.Secrets.KvV2Write(ctx, readAPPNAME(), schema.KvV2WriteRequest{
		Data: s.Data.Data,
	},
		vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}

// this function will ask the user an ID and a secret and it will be stored in vault
func addSecretInteractive(ctx context.Context, client *vault.Client, mountpath string) error {
	//read the secret id from the user
	var secretID string
	for {
		fmt.Print("Enter Secret ID: ")
		fmt.Scanln(&secretID)
		//check if secretID already exist
		if checkSecretID(ctx, client, mountpath, secretID) {
			fmt.Printf("Secret ID: %s already exist\n", secretID)
		} else {
			break
		}
	}
	//fmt.Printf("Secret ID: %s\n", secretID)
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//ask the Secret detail
	s.Data.Data[secretID] = askSecretParameter()

	_, err = client.Secrets.KvV2Write(ctx, readAPPNAME(), schema.KvV2WriteRequest{
		Data: s.Data.Data,
	},
		vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}

// this function will ask the user an ID and it will delete it from vault
func deleteSecretInteractive(ctx context.Context, client *vault.Client, mountpath string) error {
	//read the secret id from the user
	fmt.Print("Enter Secret ID: ")
	var secretID string
	fmt.Scanln(&secretID)
	//fmt.Printf("Secret ID: %s\n", secretID)
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Secret: %v\n", s.Data)
	//delete the secret
	delete(s.Data.Data, secretID)
	_, err = client.Secrets.KvV2Write(ctx, readAPPNAME(), schema.KvV2WriteRequest{
		Data: s.Data.Data,
	},
		vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}

// create a menu based cli with option to select the action
func menu(ctx context.Context, client *vault.Client, mountpath string) {
	for {
		fmt.Println("Select Action")
		fmt.Println("1. List Secrets")
		fmt.Println("2. Add Secret")
		fmt.Println("3. Delete Secret")
		fmt.Println("4. Update Secret")
		fmt.Println("5. Get Secret")
		fmt.Println("6. Read CSV File")
		fmt.Println("7. Exit")
		fmt.Println("8. Random Password")
		fmt.Print("Enter Action Number: ")
		var actionNumber int
		fmt.Scanln(&actionNumber)
		switch actionNumber {
		case 1:
			fmt.Println("List Secrets")
			listSecrets(ctx, client, mountpath)
		case 2:
			fmt.Println("Add Secret")
			addSecretInteractive(ctx, client, mountpath)
			listSecrets(ctx, client, mountpath)
		case 3:
			listSecrets(ctx, client, mountpath)
			fmt.Println("Delete Secret")
			deleteSecretInteractive(ctx, client, mountpath)
			listSecrets(ctx, client, mountpath)
		case 4:
			fmt.Println("Update Secret")
			updateSecretInteractive(ctx, client, mountpath)
			listSecrets(ctx, client, mountpath)
		case 5:
			fmt.Println("Get Secret")
			askSecret(ctx, client, mountpath)
		case 6:
			fmt.Println("Read CSV File")
			fmt.Print("Enter CSV Filename: ")
			var filename string
			fmt.Scanln(&filename)
			readCSV(ctx, client, mountpath, filename)
			listSecrets(ctx, client, mountpath)
		case 7:
			fmt.Println("Exit")
			return
		case 8:
			//return random password
			fmt.Println("Random Password")
			fmt.Print("Enter Password Length: ")
			var length int
			fmt.Scanln(&length)
			//if empty use default
			if length == 0 {
				length = 12
				fmt.Printf("Password Length: %d\n", length)
			}
			fmt.Print("Enter Password Complexity (l=lowercase, u=uppercase, d=digit, s=special): ")
			var complexity string
			fmt.Scanln(&complexity)
			//if empty use default
			if complexity == "" {
				complexity = "luds"
				fmt.Printf("Password Complexity: %s\n", complexity)
			}
			fmt.Print("Enter Special Characters: ")
			var special string
			fmt.Scanln(&special)
			//if empty use default
			if special == "" {
				special = "!@#$%^&*()_+-"
				fmt.Printf("Special Characters: %s\n", special)
			}
			fmt.Printf("Password: %s\n", randomPassword(length, strings.Contains(complexity, "l"), strings.Contains(complexity, "u"), strings.Contains(complexity, "d"), strings.Contains(complexity, "s"), special))

		default:
			fmt.Println("Exit")
			return
		}

	}
}

//check if yubikey is plugged in and return bool

func checkYubikey() bool {
	yubikey, err := piv.Cards()
	if err != nil {
		log.Fatal(err)
	}
	if len(yubikey) == 0 {
		return false
	}
	return true
}

// CSV record to Secret
func csvToSecret(record []string) Secret {
	rValue := Secret{
		Username:     record[1],
		Credential:   record[2],
		URL:          record[3],
		Comment:      record[4],
		LastUpdate:   time.Now(),
		LastUpdateBy: User,
	}
	return rValue
}

// check if SecretId already exist in vault
func checkSecretID(ctx context.Context, client *vault.Client, mountpath, secretID string) bool {
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, readAPPNAME(), vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//delete the secret
	if s.Data.Data[secretID] != nil {
		return true
	}
	return false
}

// readCSV file and insert the data in vault as Secret
func readCSV(ctx context.Context, client *vault.Client, mountpath, filename string) {
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
		addSecret(ctx, client, mountpath, record[0], csvToSecret(record))

	}

}

// read configuration file and return the configuration
func readConfigFile() *json.Decoder {
	//read the configuration file
	// Open the file
	configfile, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	// Parse the json file
	r := json.NewDecoder(configfile)

	return r

}

// read VAULTURL from environment variable, configuration file or use default
func readVaultURL() string {
	if os.Getenv("VAULTURL") != "" {
		return os.Getenv("VAULTURL")
	}
	configfile := readConfigFile()
	var config map[string]interface{}
	configfile.Decode(&config)
	if config["VAULTURL"] != nil {
		return config["VAULTURL"].(string)
	}
	return VAULTURL
}

// read APPNAME from environment variable, configuration file or use default
func readAPPNAME() string {
	if os.Getenv("APPNAME") != "" {
		return os.Getenv("APPNAME")
	}
	configfile := readConfigFile()
	var config map[string]interface{}
	configfile.Decode(&config)
	if config["APPNAME"] != nil {
		return config["APPNAME"].(string)
	}
	return APPNAME
}

// read certificate name from environment variable, configuration file or use default
func readCertificateName() string {
	if os.Getenv("CERTIFICATE") != "" {
		return os.Getenv("CERTIFICATE")
	}
	configfile := readConfigFile()
	var config map[string]interface{}
	configfile.Decode(&config)
	if config["CERTIFICATE"] != nil {
		return config["CERTIFICATE"].(string)
	}
	return "web"
}

// read mountpath from environment variable, configuration file or use default
func readMountPath() string {
	if os.Getenv("MOUNTPATH") != "" {
		return os.Getenv("MOUNTPATH")
	}
	configfile := readConfigFile()
	var config map[string]interface{}
	configfile.Decode(&config)
	if config["MOUNTPATH"] != nil {
		return config["MOUNTPATH"].(string)
	}
	return "kv"
}

//build a password generator function that will generate a password based on the given length and complexity attributes
// the password will be returned as string

func randomPassword(lengh int, lowercase, uppercase, digit, special bool, specialList string) string {

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
	//build the password using this constraints
	// countains at least one lowercase character
	// countains at least one uppercase character
	// countains at least one digit
	// countains at least one special character
	// countains at least one character from the given list
	var rValue string
	for {
		for i := 0; i < lengh; i++ {
			rValue = rValue + string(charList[rand.Intn(len(charList))])
		}
		//check constraints
		if lowercase {
			if !strings.ContainsAny(rValue, "abcdefghijklmnopqrstuvwxyz") {
				rValue = ""
				continue
			}
		}
		if uppercase {
			if !strings.ContainsAny(rValue, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				rValue = ""
				continue
			}
		}
		if digit {
			if !strings.ContainsAny(rValue, "0123456789") {
				rValue = ""
				continue
			}
		}
		if special {
			if !strings.ContainsAny(rValue, specialList) {
				rValue = ""
				continue
			}
		}
		break
	}
	return rValue

}

// main function
func main() {
	//read the configuration file
	//fmt.Printf("config:%s")
	//prepare the context
	ctx := context.Background()
	//print the default the app is running
	fmt.Printf("myvault is running with APPNAME: %s and VAULTURL: %s\n", readAPPNAME(), readVaultURL())

	var c *vault.Client
	var e error
	// check yubikey is plugged in
	if checkYubikey() {

		yk := openYubikey(selectSmartcard())
		defer yk.Close()
		cert := readYubikeyCertificate(yk, selectSlot())
		//fmt.Printf("Certificate: %v\n", cert)
		//fmt.Printf("Certificate: %v\n", cert.PublicKey)
		fmt.Printf("Certificate: %v\n", cert.PublicKeyAlgorithm)
		c, e = connectVaulwithYubikey(ctx, yk)

	} else {
		fmt.Println("No Yubikey found. Falling back to username and password")
		//ask username and password
		username, password := readUsernamePassword()
		c, e = connectVaultWithUsernamePassword(ctx, username, password)
	}
	if e != nil {
		log.Fatal(e)
	}
	menu(ctx, c, readMountPath())

}

//Configuration file format to be saved as config.json in the same directory as the binary
// {
// 	"VAULTURL": "https://xxx.xxx.xxx.xxx:8200"
// 	"APPNAME": "myapp",
// 	"CERTIFICATE": "web",
// 	"MOUNTPATH": "kv"
// }
