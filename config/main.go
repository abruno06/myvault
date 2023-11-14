package config

import (
	"encoding/json"
	"log"
	"os"
)

var VAULTURL = "https://172.0.0.1:8200"
var APPNAME = "myapp"

var SecretFieldNames = []string{"Username", "Credential", "URL", "LastUpdate", "LastUpdateBy", "Comment"}
var SecretHumanFieldNames = []string{"Username", "Credential", "URL", "Comment"}

var User = func() string {
	if os.Getenv("USER") != "" {
		return os.Getenv("USER")
	}
	return "unknown"
}()

// read configuration file and return the configuration
func readConfigFile() *json.Decoder {
	//read the configuration file
	// Open the file
	configfile, err := os.Open("../config.json")
	if err != nil {
		log.Fatal(err)
	}
	// Parse the json file
	r := json.NewDecoder(configfile)

	return r

}

// read VAULTURL from environment variable, configuration file or use default
func ReadVaultURL() string {
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
func ReadAPPNAME() string {
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
func ReadCertificateName() string {
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
func ReadMountPath() string {
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
