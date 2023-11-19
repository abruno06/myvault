package secret

import (
	"testing"
	"time"
)

//this will allow to test the function of secret package

// test the convertToSecret function
func TestConvertToSecret(t *testing.T) {
	//test if the conversion is successful
	if obj, _ := ConvertToSecret(map[string]interface{}{"Username": "user", "Credential": "password", "URL": "url", "Comment": "comment", "LastUpdate": "2020-01-01T00:00:00.000000-07:00", "LastUpdateBy": "user"}); obj == (Secret{Username: "user", Credential: "password", URL: "url", Comment: "comment", LastUpdate: time.Date(2020, 01, 01, 00, 00, 00, 00, time.UTC), LastUpdateBy: "user"}) {
		t.Errorf("ConvertToSecret() = %t; want true", obj == (Secret{Username: "user", Credential: "password", URL: "url", Comment: "comment", LastUpdate: time.Date(2020, 01, 01, 00, 00, 00, 00, time.UTC), LastUpdateBy: "user"}))
	}
	//test if the conversion is not successful
	if obj, _ := ConvertToSecret(map[string]interface{}{"Username": "user", "Credential": "password", "URL": "url", "Comment": "comment", "LastUpdate": "2020-01-01T00:00:00.000000-07:00", "LastUpdateBy": "user1"}); obj == (Secret{Username: "user", Credential: "password", URL: "url", Comment: "comment", LastUpdate: time.Date(2020, 01, 01, 00, 00, 00, 00, time.UTC), LastUpdateBy: "user"}) {
		t.Errorf("ConvertToSecret() = %t; want false", obj == (Secret{Username: "user", Credential: "password", URL: "url", Comment: "comment", LastUpdate: time.Date(2020, 01, 01, 00, 00, 00, 00, time.UTC), LastUpdateBy: "user"}))
	}
}

// test the convertFromSecret function
func TestConvertFromSecret(t *testing.T) {
	// create a Secret
	mysecret := Secret{Username: "user", Credential: "password", URL: "url", Comment: "comment", LastUpdate: time.Date(2020, 01, 01, 00, 00, 00, 00, time.UTC), LastUpdateBy: "user"}
	// create the map[string]interface{} for the secret
	mysecretmap := make(map[string]interface{})
	mysecretmap["Username"] = "user"
	mysecretmap["Credential"] = "password"
	mysecretmap["URL"] = "url"
	mysecretmap["Comment"] = "comment"
	mysecretmap["LastUpdate"] = "2020-01-01 00:00:00"
	mysecretmap["LastUpdateBy"] = "user"
	// create the map[string]interface{} for not matching secret
	mysecretmapfalse := make(map[string]interface{})
	mysecretmapfalse["Username"] = "user"
	mysecretmapfalse["Credential"] = "password"
	mysecretmapfalse["URL"] = "url"
	mysecretmapfalse["Comment"] = "comment"
	mysecretmapfalse["LastUpdate"] = "2020-01-01 00:00:00"
	mysecretmapfalse["LastUpdateBy"] = "user1"
	//another type of false

	mysecretmapfalse2 := make(map[string]interface{})
	mysecretmapfalse2["Username"] = "user"
	mysecretmapfalse2["Credential"] = "password"
	mysecretmapfalse2["URL"] = "url"
	mysecretmapfalse2["Comment"] = "comment"
	mysecretmapfalse2["LastUpdate"] = "2020-01-01 00:00:00"
	mysecretmapfalse2["LastUpdateBy"] = "user"
	mysecretmapfalse2["extra"] = "extra"

	if rsecretmap := ConvertFromSecret(mysecret); compareMaps(rsecretmap, mysecretmap) != true {
		t.Errorf("ConvertFromSecret() = %t; want true", compareMaps(rsecretmap, mysecretmap))

	}

	if rsecretmapf := ConvertFromSecret(mysecret); compareMaps(rsecretmapf, mysecretmapfalse) != false {
		t.Errorf("ConvertFromSecret() = %t; want false", compareMaps(rsecretmapf, mysecretmapfalse))
	}

	if rsecretmapf := ConvertFromSecret(mysecret); compareMaps(rsecretmapf, mysecretmapfalse2) != false {
		t.Errorf("ConvertFromSecret() = %t; want false", compareMaps(rsecretmapf, mysecretmapfalse2))
	}
}

// test the compareMaps function
func TestCompareMaps(t *testing.T) {
	// create the map[string]interface{} for the secret
	mysecretmap := make(map[string]interface{})
	mysecretmap["Username"] = "user"
	mysecretmap["Credential"] = "password"
	mysecretmap["URL"] = "url"
	mysecretmap["Comment"] = "comment"
	mysecretmap["LastUpdate"] = "2020-01-01 00:00:00"
	mysecretmap["LastUpdateBy"] = "user"
	// create the map[string]interface{} for not matching secret
	mysecretmapfalse := make(map[string]interface{})
	mysecretmapfalse["Username"] = "user"
	mysecretmapfalse["Credential"] = "password"
	mysecretmapfalse["URL"] = "url"
	mysecretmapfalse["Comment"] = "comment"
	mysecretmapfalse["LastUpdate"] = "2020-01-01 00:00:00"
	mysecretmapfalse["LastUpdateBy"] = "user1"
	//another type of false

	mysecretmapfalse2 := make(map[string]interface{})
	mysecretmapfalse2["Username"] = "user"
	mysecretmapfalse2["Credential"] = "password"
	mysecretmapfalse2["URL"] = "url"
	mysecretmapfalse2["Comment"] = "comment"
	mysecretmapfalse2["LastUpdate"] = "2020-01-01 00:00:00"
	mysecretmapfalse2["LastUpdateBy"] = "user"
	mysecretmapfalse2["extra"] = "extra"

	if compareMaps(mysecretmap, mysecretmap) != true {
		t.Errorf("compareMaps() = %t; want true", compareMaps(mysecretmap, mysecretmap))

	}

	if compareMaps(mysecretmap, mysecretmapfalse) != false {
		t.Errorf("compareMaps() = %t; want false", compareMaps(mysecretmap, mysecretmapfalse))
	}

	if compareMaps(mysecretmap, mysecretmapfalse2) != false {
		t.Errorf("compareMaps() = %t; want false", compareMaps(mysecretmap, mysecretmapfalse2))
	}
}
