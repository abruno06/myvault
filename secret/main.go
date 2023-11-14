package secret

import "time"

// reset to this
type Secret struct {
	Username     string
	Credential   string
	URL          string //optional
	Comment      string
	LastUpdate   time.Time
	LastUpdateBy string
}

var SecretFieldNames = []string{"Username", "Credential", "URL", "LastUpdate", "LastUpdateBy", "Comment"}
var SecretHumanFieldNames = []string{"Username", "Credential", "URL", "Comment"}

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
		rValue.LastUpdate, _ = time.Parse("2006-01-02 15:04:05", "0001-01-01 00:00:00 ")
	} else {
		rValue.LastUpdate, _ = time.Parse("2006-01-02T15:04:05.999999-07:00", object["LastUpdate"].(string))
	}
	rValue.LastUpdateBy, _ = object["LastUpdateBy"].(string)
	return rValue, ok
}
