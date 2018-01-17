package crypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"testing"
)

func Test_keypair(t *testing.T) {
	baseinfo := CertInformation{
		Country:            []string{"CN"},
		Organization:       []string{"WS"},
		OrganizationalUnit: []string{"work-stacks"},
		IsCA:               true,
		EmailAddress:       []string{"12345@qq.com"},
		Locality:           []string{"SuZhou"},
		Province:           []string{"JiangSu"},
		CommonName:         "192.168.205.114",
		CrtName:            "test_root.crt",
		KeyName:            "test_root.key",
	}

	err := CreateCrt(nil, nil, baseinfo)
	if err != nil {
		t.Log("Create crt error, error info:", err)
		return
	}
	crtinfo := baseinfo
	crtinfo.IsCA = false
	crtinfo.CrtName = "test_server.crt"
	crtinfo.KeyName = "test_server.key"
	crtinfo.Names = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 1, 3}, Value: "MAC_ADDR"}}

	crt, pri, err := Parse(baseinfo.CrtName, baseinfo.KeyName)
	if err != nil {
		t.Log("Parse crt error, error info:", err)
		return
	}
	err = CreateCrt(crt, pri, crtinfo)
	if err != nil {
		t.Log("Create crt error, error info:", err)
	}
	os.Remove(baseinfo.CrtName)
	os.Remove(baseinfo.KeyName)
	os.Remove(crtinfo.CrtName)
	os.Remove(crtinfo.KeyName)
}
