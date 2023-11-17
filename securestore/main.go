package securestore

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

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

// this function will add a secret to vault for a given SecretStore, secret and secretID
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

// this function will set a cubyhole for the list of secretsId
func setCubbyholeList(ctx context.Context, secstore SecretStore, storePath string, s map[string]secret.Secret) error {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath
	// Add secretId as a key
	combinedData := make(map[string]interface{})
	for k, v := range s {
		combinedData[k] = secret.ConvertFromSecret(v)
	}
	_, err := client.Secrets.CubbyholeWrite(ctx, storePath, combinedData, vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}

// this function will set a cubbyhole for the given secretID
func setCubbyhole(ctx context.Context, secstore SecretStore, secretId string, s secret.Secret) error {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath
	data := secret.ConvertFromSecret(s)
	//fmt.Printf("data: %v\n", data)
	// Add secretId as a key
	combinedData := make(map[string]interface{})
	combinedData[secretId] = data
	_, err := client.Secrets.CubbyholeWrite(ctx, secretId, combinedData, vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}

// this function will set a cubyhole for the list of secretsId
func SetServiceSecretCubbyhole(ctx context.Context, secstore SecretStore, s map[string]secret.Secret) error {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath

	var err error
	for k, v := range s {
		item := secret.ConvertFromSecret(v)
		_, err = client.Secrets.CubbyholeWrite(ctx, k, item, vault.WithMountPath(mountpath))
		if err != nil {
			log.Fatal(err)
		}
	}

	return err
}

// take a cubbyhole and wrap the secret and return the wrapped token
func WrapCubbyhole(ctx context.Context, secstore SecretStore, path string, ttl time.Duration) (string, error) {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath
	//read the cubbyhole
	resp, err := client.Secrets.CubbyholeRead(ctx, path, vault.WithMountPath(mountpath), vault.WithResponseWrapping(ttl))
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Wrapped response: %v\n", resp.WrapInfo)
	return resp.WrapInfo.Token, err
}

// create a wrap secret for a given appname and return the token
func WrapSecret(ctx context.Context, secstore SecretStore, secretID string, ttl time.Duration) (string, error) {
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
	//check if secretID exist
	if s.Data.Data[secretID] == nil {
		log.Fatalf("Secret ID: %s not found\n", secretID)
		return "", fmt.Errorf("Secret ID: %s not found\n", secretID)
	}
	//convert to secret
	sec, _ := secret.ConvertToSecret(s.Data.Data[secretID].(map[string]interface{}))
	//put the secret into the cubbyhole
	err = setCubbyhole(ctx, secstore, secretID, sec)
	if err != nil {
		log.Fatal(err)

	}
	//return the Wrappe Token
	return WrapCubbyhole(ctx, secstore, secretID, ttl)
}

// this function take a list of secretId and wrap the cubbyhole and return the token
func WrapSecretList(ctx context.Context, secstore SecretStore, secList []string, storePath string, ttl time.Duration) (string, error) {
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
	chValue := make(map[string]secret.Secret)
	for _, secretID := range secList {
		//check if secretID exist
		if s.Data.Data[secretID] == nil {
			fmt.Printf("Secret ID: %s not found\n", secretID)
			continue
		}
		//convert to secret
		sec, _ := secret.ConvertToSecret(s.Data.Data[secretID].(map[string]interface{}))
		chValue[secretID] = sec
	}
	err = setCubbyholeList(ctx, secstore, storePath, chValue)
	if err != nil {
		log.Fatal(err)
	}
	return WrapCubbyhole(ctx, secstore, storePath, ttl)
}

// this function will unwrap a cubbyhole and return the secret
func UnWrappeSecret(ctx context.Context, secstore SecretStore, token string) (map[string]secret.Secret, error) {
	//extract the client from the SecretStore
	client := secstore.Client

	//read the cubbyhole
	resp, err := vault.Unwrap[map[string]interface{}](ctx, client, token)
	if err != nil {
		log.Fatal(err)
	}
	rValue := make(map[string]secret.Secret)
	//fmt.Printf("Unwrapped response: %v\n", resp)
	// loop to the resp.Data key
	for key, v := range resp.Data {
		rValue[key], _ = secret.ConvertToSecret(v.(map[string]interface{}))
	}
	//convert to secret

	return rValue, err
}

// this function will unwrap a secret and return a json string
func UnWrappeSecretJSON(ctx context.Context, secstore SecretStore, token string) (string, error) {
	//extract the client from the SecretStore
	data, _ := UnWrappeSecret(ctx, secstore, token)
	jsonData, err := json.Marshal(data)
	return string(jsonData), err
}
