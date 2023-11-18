# myvault

## Description
This little application is a prototype to interconnect Yukikey with Vault using piv mode of Yubikey.
This allow to build a quick and dirty password manager where information get saved in secure way into Vault and accessible from all location where the Vault server is accessible.

## Prereq 

Have a yubikey (or equivalent) key supporting piv mode to store private key and authentication certificate in it.
Have certificate loaed to the key
Have Hashicorp Vault knowledge

## Environment need

You need a working Hashicorp Vault server supporting Certificates as authentication mechanism
you can found all documentation needed
https://developer.hashicorp.com/vault/docs/what-is-vault


## Setup the Vault and Yukibey configuration

- Configure Vault with Auth with TLS certificate : https://developer.hashicorp.com/vault/docs/auth/cert
- Install your Yubikey Authentication Certificate into the Auth cert uisng either the UI, the CLI or the API
- Make sure your certificate is associated with the proper Policy that allow certificates manipulation
    example if your kv secret is mount to kv/*
    ``` yaml
    # Allow a token to set kv 
    path "kv/*" {
    capabilities = ["create", "read", "update", "delete", "list"
    }
    ```
- Set the token TTL for the certificate to be small as possible.
- (todo renew token if expired)

If you do not have piv or equivalent this application fallback to username/password to get Vault access.
Same if your pin is Invalid

## Run the application

```term
go run cmd/cli/myvault.go
```

or compile it 

```term
go build cmd/cli/myvault.go
```

## Batch Load

you can use a CSV File to load your data:
the format is the following if your are using the built in secret format

```SecretID, Username, Credential, URL, Comment```

no header are expected on the CSV file
remark: do not put ',' in the comment piece if you do not want unexpected result
## Packages

The application has been splited to allow flexibility for future

## Bootstrap

This feature allow you to export a secret and share a one time token to retreive it.
This is done using the wrap / unwrap feature and cubbyhole to store the expose secret

## TODO

Improve the Secret 

## Known issue with piv

in case of build or run error in linux, follow this link

https://github.com/go-piv/piv-go/issues/114

## Known errors

```
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

This mean that your vault server certificate is not recognized by your OS.
This is most probably because your Vault certificate is using a non public CA unknow by your computeur.
Follow process related to your OS to make it part of trusted CA.