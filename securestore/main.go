package securestore

import (
	"context"

	"github.com/abruno06/myvault/config"
	"github.com/hashicorp/vault-client-go"
)

type Secret struct {
	Username string
}

func getSecret(ctx context.Context, client *vault.Client, secretID, mountpath string) (Secret, error) {
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
