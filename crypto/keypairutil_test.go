package crypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
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
		CrtPath:            "test_root.crt",
		KeyPath:            "test_root.key",
	}

	err := CreateCrt(nil, nil, baseinfo)
	if err != nil {
		t.Log("Create crt error, error info:", err)
		return
	}
	crtinfo := baseinfo
	crtinfo.IsCA = false
	crtinfo.CrtPath = "test_server.crt"
	crtinfo.KeyPath = "test_server.key"
	crtinfo.Names = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 1, 3}, Value: "MAC_ADDR"}}

	crt, pri, err := Parse(baseinfo.CrtPath, baseinfo.KeyPath)
	if err != nil {
		t.Log("Parse crt error, error info:", err)
		return
	}
	err = CreateCrt(crt, pri, crtinfo)
	if err != nil {
		t.Log("Create crt error, error info:", err)
	}
	// os.Remove(baseinfo.CrtPath)
	// os.Remove(baseinfo.KeyPath)
	// os.Remove(crtinfo.CrtPath)
	// os.Remove(crtinfo.KeyPath)
}
