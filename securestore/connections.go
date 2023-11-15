package securestore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/abruno06/myvault/config"
	"github.com/abruno06/myvault/smartcard"

	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

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
	return SecretStore{Client: client, Mountpath: config.ReadMountPath(), Appname: config.ReadAPPNAME()}, err
}

// connect to vault with yubikey
func ConnectVaulwithYubikey(ctx context.Context, yubikey *piv.YubiKey, pin string) (SecretStore, error) {
	//set the slot to authentication
	slot := piv.SlotAuthentication // You can change this to the slot you are interested in.

	//read the personal certificate
	cert := smartcard.ReadYubikeyCertificate(yubikey, slot)

	//test the pin is correct
	if err := yubikey.VerifyPIN(pin); err != nil {
		return SecretStore{}, err
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

	return SecretStore{Client: client, Mountpath: config.ReadMountPath(), Appname: config.ReadAPPNAME()}, err

}
