package securestore

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/abruno06/myvault/secret"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// this function list all secrets in vault for the given mountpath and readAPPNAME() and display them in tabuuar format
func ListSecrets(ctx context.Context, secstore SecretStore) error {
	//read the secret for the readAPPNAME()

	Data, err := getAllSecrets(ctx, secstore)

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
		s, ok := secret.ConvertToSecret(v.(map[string]interface{}))
		if ok {
			fmt.Fprintf(w, format, k, s.Username, s.Credential, s.URL, s.LastUpdate.UTC().Format("2006-01-02 15:04:05"), s.LastUpdateBy, s.Comment)

		}
	}
	w.Flush()
	return err

}

// this function add a Secret to vault for the given secstore and secretID
func AddSecret(ctx context.Context, secstore SecretStore, secret secret.Secret, secretID string) error {
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
	//set the secret
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

// this function will update a secret in vault for a given secstore, secret and secretID
func DeleteSecret(ctx context.Context, secstore SecretStore, secretId string) error {
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
	//delete the secret
	delete(s.Data.Data, secretId)

	_, err = client.Secrets.KvV2Write(ctx, appname, schema.KvV2WriteRequest{
		Data: s.Data.Data,
	},
		vault.WithMountPath(mountpath))
	if err != nil {
		log.Fatal(err)
	}
	return err
}

// check if SecretId already exist in vault
func CheckSecretID(ctx context.Context, secstore SecretStore, secretID string) bool {
	//read the secret for the readAPPNAME()
	s, err := secstore.Client.Secrets.KvV2Read(ctx, secstore.Appname, vault.WithMountPath(secstore.Mountpath))
	if err != nil {
		log.Fatal(err)
	}
	//delete the secret
	if s.Data.Data[secretID] != nil {
		return true
	}
	return false
}
