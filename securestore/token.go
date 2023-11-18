package securestore

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/abruno06/myvault/secret"
	"github.com/google/uuid"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// create a new token with a given policy
func CreateToken(ctx context.Context, secstore SecretStore, policies []string) (string, error) {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath

	//create a new token with the given policies
	// Token will have no parent and will not expire
	// Type is service
	resp, err := client.Auth.TokenCreate(ctx, schema.TokenCreateRequest{
		Policies: policies,
		NoParent: true,
		Ttl:      "1440h",
		Type:     "service",
	}, vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return resp.Auth.ClientToken, err
}

// this function will wrap a token and return the wrapped token
func WrapToken(ctx context.Context, secstore SecretStore, token string, ttl time.Duration) (string, error) {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath
	//generate a UUID for the wrapping token
	uuid := uuid.New().String()
	//set the token into a cubbyhole entry
	_, err := client.Secrets.CubbyholeWrite(ctx, uuid, map[string]interface{}{"token": token}, vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//wrap the cubbyhole
	resp, err := client.Secrets.CubbyholeRead(ctx, uuid, vault.WithMountPath(mountpath), vault.WithResponseWrapping(ttl))
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Wrapped response: %v\n", resp.WrapInfo)
	return resp.WrapInfo.Token, err
}

// this function will unwrap a token and return the Access token from it
func UnWrappeToken(ctx context.Context, secstore SecretStore, token string) (string, error) {
	//extract the client from the SecretStore
	client := secstore.Client

	//read the cubbyhole
	resp, err := vault.Unwrap[map[string]interface{}](ctx, client, token)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Unwrapped response: %v\n", resp)
	// loop to the resp.Data key
	return resp.Data["token"].(string), err
}

// this function will retur all Cubbyhole entries
func ListCubbyhole(ctx context.Context, secstore SecretStore) (string, error) {
	//extract the client from the SecretStore
	client := secstore.Client
	//extract the mountpath from the SecretStore
	mountpath := secstore.Mountpath

	//read the cubbyhole
	resp, err := client.Secrets.CubbyholeList(ctx, "", vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Cubbyhole response: %v\n", resp.Data.Keys)
	rValue := make(map[string]secret.Secret)
	for _, v := range resp.Data.Keys {
		//get the cubbyhole entry value
		value, err := client.Secrets.CubbyholeRead(ctx, v, vault.WithMountPath(mountpath))
		if err != nil {
			log.Fatal(err)
		}
		//convert the value to secret
		rValue[v], _ = secret.ConvertToSecret(value.Data)

	}
	//fmt.Printf("Cubbyhole response: %v\n", rValue)
	jsonData, err := json.Marshal(rValue)
	return string(jsonData), err

}

// function renew the token
func RenewToken(ctx context.Context, secstore SecretStore, token string) error {
	//extract the client from the SecretStore
	client := secstore.Client
	//renew the token
	resp, err := client.Auth.TokenRenewSelf(ctx, schema.TokenRenewSelfRequest{Token: token})
	if err != nil {
		log.Fatal(err)
	}
	rJson, _ := json.Marshal(resp)
	fmt.Printf("%v\n", string(rJson))
	return err
}

// function to revoke the token
func RevokeToken(ctx context.Context, secstore SecretStore, token string) error {
	//extract the client from the SecretStore
	client := secstore.Client
	//revoke the token
	resp, err := client.Auth.TokenRevokeSelf(ctx)
	if err != nil {
		log.Fatal(err)
	}
	rJson, _ := json.Marshal(resp)
	fmt.Printf("%v\n", string(rJson))
	return err
}
