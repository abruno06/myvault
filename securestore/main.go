package securestore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/abruno06/myvault/config"
	"github.com/abruno06/myvault/interactif"
	"github.com/abruno06/myvault/secret"
	"github.com/abruno06/myvault/smartcard"
	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type Secret struct {
	Username     string
	Credential   string
	URL          string //optional
	Comment      string
	LastUpdate   time.Time
	LastUpdateBy string
}

type SecretStore struct {
	Client    *vault.Client
	Mountpath string
}

func GetSecret(ctx context.Context, client *vault.Client, secretID, mountpath string) (Secret, error) {
	rValue := Secret{}
	//read the secret for the readAPPNAME()
	_, err := client.Secrets.KvV2Read(ctx, config.ReadAPPNAME(), vault.WithMountPath(mountpath))

	if err == nil {
		/*
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
		*/
	}
	return rValue, err
}

// connect to vault with specific tls config
func ConnectVaultWithTLSConfig(ctx context.Context, tlsConfig *tls.Config) (SecretStore, error) {
	// prepare a client with the given base address

	client, err := vault.New(
		vault.WithAddress(config.ReadVaultURL()),
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
	resp, err := client.Auth.CertLogin(ctx, schema.CertLoginRequest{Name: config.ReadCertificateName()})
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
	return SecretStore{Client: client, Mountpath: config.ReadMountPath()}, err
}

// connect to vault with yubikey
func ConnectVaulwithYubikey(ctx context.Context, yubikey *piv.YubiKey) (SecretStore, error) {
	//set the slot to authentication
	slot := piv.SlotAuthentication // You can change this to the slot you are interested in.

	//read the personal certificate
	cert := smartcard.ReadYubikeyCertificate(yubikey, slot)

	//read the pin from the user
	pin := interactif.ReadPin()
	//test the pin is correct
	if err := yubikey.VerifyPIN(pin); err != nil {
		//fallback to username and password as pin is not correct
		//read the username and password from the user
		fmt.Println("PIN is not correct, fallback to username and password")
		username, password := interactif.ReadUsernamePassword()
		return ConnectVaultWithUsernamePassword(ctx, username, password)
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
	return ConnectVaultWithTLSConfig(ctx, tlsConfig)
}

// connect to vault using username and password and return the client
func ConnectVaultWithUsernamePassword(ctx context.Context, username, password string) (SecretStore, error) {
	// Prepare Vault Connection

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(config.ReadVaultURL()),
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

	return SecretStore{Client: client, Mountpath: config.ReadMountPath()}, err

}

// this function will convert a map[string]interface{} to a Secret
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

// this function list all secrets in vault for the given mountpath and readAPPNAME() and display them in tabuuar format
func ListSecrets(ctx context.Context, secstore SecretStore) error {
	//read the secret for the readAPPNAME()

	list, err := secstore.Client.Secrets.KvV2Read(ctx, config.ReadAPPNAME(), vault.WithMountPath(secstore.Mountpath))
	if err != nil {
		//log.Fatal(err)
		log.Println("No secrets found")
	}
	//fmt.Printf("List: %v\n", list)
	//display all secrets found in tabular format
	// Create a tabwriter
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	columns := secret.SecretFieldNames
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
