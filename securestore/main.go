package securestore

import (
	"context"
	"fmt"
	"log"

	"github.com/abruno06/myvault/secret"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type SecretStore struct {
	Client    *vault.Client
	Mountpath string
	Appname   string
}

func GetSecret(ctx context.Context, secstore SecretStore, secretID string) (secret.Secret, error) {
	// extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath
	appname := secstore.Appname
	rValue := secret.Secret{}
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, appname, vault.WithMountPath(mountpath))

	if err == nil {

		vValue := s.Data.Data
		if vValue[secretID] != nil {
			var ok bool
			rValue, ok = secret.ConvertToSecret(vValue[secretID].(map[string]interface{}))
			if !ok {
				log.Printf("Secret ID: %s not valid secret\n", vValue[secretID])
				log.Printf("Secret ID: is type %T \n", vValue[secretID])
				rValue = secret.Secret{}
				err = fmt.Errorf("Secret ID: %s not valid secret", vValue[secretID])
			}
			//fmt.Printf("Secret: %v\n", rValue)
		} else {
			fmt.Printf("Secret ID: %s not found\n", secretID)
			rValue = secret.Secret{}
		}

	}
	return rValue, err
}

// this function will connect to vault and return all secret for a given mountpath, APPNAME
func getAllSecrets(ctx context.Context, secstore SecretStore) (map[string]interface{}, error) {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath
	//extract the appname from the SecretStore
	appname := secstore.Appname
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, appname, vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return s.Data.Data, err
}

// this function will add a secret to vault for a given mountpath, APPNAME and secretID
func setSecret(ctx context.Context, secstore SecretStore, secretID string, secret secret.Secret) error {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath
	//extract the appname from the SecretStore
	appname := secstore.Appname
	//read the secret for the readAPPNAME()
	s, err := client.Secrets.KvV2Read(ctx, appname, vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//ask the Secret detail
	s.Data.Data[secretID] = secret

	_, err = client.Secrets.KvV2Write(ctx, appname, schema.KvV2WriteRequest{
		Data: s.Data.Data,
	},
		vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}
