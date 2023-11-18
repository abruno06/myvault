package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

//Configuration file format to be saved as config.json in the same directory as the binary
// {
// 	"VAULTURL": "https://xxx.xxx.xxx.xxx:8200"
// 	"APPNAME": "myapp",
// 	"CERTIFICATE": "web",
// 	"MOUNTPATH": "kv"
// }

var VAULTURL = "https://127.0.0.1:8200"
var APPNAME = "myapp"

var SecretFieldNames = []string{"Username", "Credential", "URL", "LastUpdate", "LastUpdateBy", "Comment"}
var SecretHumanFieldNames = []string{"Username", "Credential", "URL", "Comment"}

// User is the user running the application
var User = func() string {
	if os.Getenv("USER") != "" {
		return os.Getenv("USER")
	}
	return "unknown"
}()

// this function will return how build a configuration file
func Usage() {
	//Configuration file format to be saved as config.json in the same directory as the binary
	// {
	// 	"VAULTURL": "https://xxx.xxx.xxx.xxx:8200"
	// 	"APPNAME": "myapp",
	// 	"CERTIFICATE": "web",
	// 	"MOUNTPATH": "kv"
	// }
	fmt.Printf("Configuration file format to be saved as config.json in the same directory where the binary is run from\n")
	fmt.Printf("{\n")
	fmt.Printf("\t\"VAULTURL\": \"https://xxx.xxx.xxx.xxx:8200\"\n")
	fmt.Printf("\t\"APPNAME\": \"myapp\",\n")
	fmt.Printf("\t\"CERTIFICATE\": \"web\",\n")
	fmt.Printf("\t\"MOUNTPATH\": \"kv\"\n")
	fmt.Printf("}\n")

}

// read configuration file and return the configuration
func readConfigFile() *json.Decoder {
	//read the configuration file
	// Open the file
	configfile, err := os.Open("config.json")
	if err != nil {
		Usage()
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
