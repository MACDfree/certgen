package crypto

import (
	"crypto/x509"
	"io/ioutil"

	"github.com/lotus-wu/go-pkcs12"
)

// CreatePfx 创建pfx
func CreatePfx(crtPath, keyPath, pfxPath, password string) error {
	crt, pri, err := Parse(crtPath, keyPath)
	if err != nil {
		return err
	}

	pfxdata, err := pkcs12.Encode(pri, crt, nil, password)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(pfxPath, pfxdata, 0666)
}

// ParsePfx 解析pfx
func ParsePfx(pfxPath, password string) (privatekey interface{}, cert []*x509.Certificate, err error) {
	pfxData, err := ioutil.ReadFile(pfxPath)
	if err != nil {
		return nil, nil, err
	}

	privatekey, cert, err = pkcs12.DecodeAll(pfxData, password)
	return
}
