package config

// Path: config/config_test.go
// test the config package
import (
	"testing"
)

var CERTIFICATE = "web"
var MOUNTPATH = "kv"

// test redConfigFile function
func TestReadConfigFile(t *testing.T) {
	//test if config file is not empty
	if readConfigFile() == nil {
		t.Errorf("readConfigFile() = %T; want not nil", readConfigFile())
	}
}

// test ReadVaultURL function
func TestReadVaultURL(t *testing.T) {
	//test if VAULTURL is set
	if ReadVaultURL() != VAULTURL {
		t.Errorf("ReadVaultURL() = %s; want %s", ReadVaultURL(), VAULTURL)
	}
	//test if VAULTURL is not set
	VAULTURL = ""
	if ReadVaultURL() == VAULTURL {
		t.Errorf("ReadVaultURL() != %s; want %s", VAULTURL, ReadVaultURL())
	}
}

// test ReadAPPNAME function
func TestReadAPPNAME(t *testing.T) {
	//test if APPNAME is set
	if ReadAPPNAME() != APPNAME {
		t.Errorf("ReadAPPNAME() = %s; want %s", ReadAPPNAME(), APPNAME)
	}
	//test if APPNAME is not set
	APPNAME = ""
	if ReadAPPNAME() == APPNAME {
		t.Errorf("ReadAPPNAME() != %s; want %s", APPNAME, ReadAPPNAME())
	}
}

// test ReadCertificateName function
func TestReadCertificateName(t *testing.T) {
	//test if CERTIFICATE is set
	if ReadCertificateName() != CERTIFICATE {
		t.Errorf("ReadCertificateName() = %s; want %s", ReadCertificateName(), CERTIFICATE)
	}
	//test if CERTIFICATE is not set
	CERTIFICATE = ""
	if ReadCertificateName() == CERTIFICATE {
		t.Errorf("ReadCertificateName() != %s; want %s", CERTIFICATE, ReadCertificateName())
	}
}

// test ReadMountPath function
func TestReadMountPath(t *testing.T) {
	//test if MOUNTPATH is set
	if ReadMountPath() != MOUNTPATH {
		t.Errorf("ReadMountPath() = %s; want %s", ReadMountPath(), MOUNTPATH)
	}
	//test if MOUNTPATH is not set
	MOUNTPATH = ""
	if ReadMountPath() == MOUNTPATH {
		t.Errorf("ReadMountPath() != %s; want %s", MOUNTPATH, ReadMountPath())
	}
}
