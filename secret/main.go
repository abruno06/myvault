package secret

import (
	"fmt"
	"time"
)

// reset to this
type Secret struct {
	Username     string    `json:"username"`
	Credential   string    `json:"credential"`
	URL          string    `json:"url"` //optional
	Comment      string    `json:"comment"`
	LastUpdate   time.Time `json:"lastupdate"`
	LastUpdateBy string    `json:"lastupdateby"`
}

var SecretFieldNames = []string{"Username", "Credential", "URL", "LastUpdate", "LastUpdateBy", "Comment"}
var SecretHumanFieldNames = []string{"Username", "Credential", "URL", "Comment"}

// String method for the Secret struct
func (s Secret) String() string {
	return fmt.Sprintf("Username: %s\nCredential: %s\nURL: %s\nComment: %s\nLastUpdate: %s\nLastUpdateBy: %s\n", s.Username, s.Credential, s.URL, s.Comment, s.LastUpdate, s.LastUpdateBy)
}

// convert the map[string]interface {}  to Secret
// return the secret and true if the conversion is successful otherwise return empty secret and false
func ConvertToSecret(object map[string]interface{}) (Secret, bool) {
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
		rValue.LastUpdate, _ = time.Parse("2006-01-02 15:04:05", "0001-01-01 00:00:00")
	} else {
		//fmt.Printf("LastUpdate: %s\n", object["LastUpdate"].(string))
		var ep error
		rValue.LastUpdate, ep = time.Parse("2006-01-02T15:04:05.999999-07:00", object["LastUpdate"].(string))
		if ep != nil {
			//fmt.Printf("Error parsing date: %s\n", ep)
			rValue.LastUpdate, _ = time.Parse("2006-01-02 15:04:05", object["LastUpdate"].(string))
		}
	}
	rValue.LastUpdateBy, _ = object["LastUpdateBy"].(string)
	return rValue, ok
}

// this function will convert the secret to map[string]interface {}
func ConvertFromSecret(secret Secret) map[string]interface{} {
	rValue := make(map[string]interface{})
	rValue["Username"] = secret.Username
	rValue["Credential"] = secret.Credential
	rValue["Comment"] = secret.Comment
	rValue["URL"] = secret.URL
	rValue["LastUpdate"] = secret.LastUpdate.UTC().Format("2006-01-02 15:04:05")
	rValue["LastUpdateBy"] = secret.LastUpdateBy
	return rValue
}
