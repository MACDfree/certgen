package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	rd "math/rand"
	"os"
	"time"
)

func init() {
	rd.Seed(time.Now().UnixNano())
}

// CertInformation 为证书生成基本信息
type CertInformation struct {
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	EmailAddress       []string
	Province           []string
	Locality           []string
	CommonName         string
	CrtPath, KeyPath   string
	IsCA               bool
	Names              []pkix.AttributeTypeAndValue
}

func newCertificate(info CertInformation) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(rd.Int63()),
		Subject: pkix.Name{
			Country:            info.Country,
			Organization:       info.Organization,
			OrganizationalUnit: info.OrganizationalUnit,
			Province:           info.Province,
			CommonName:         info.CommonName,
			Locality:           info.Locality,
			ExtraNames:         info.Names,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		BasicConstraintsValid: true,
		IsCA:           info.IsCA,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		EmailAddresses: info.EmailAddress,
	}
}

func write(filename, Type string, p []byte) error {
	file, err := os.Create(filename)
	defer file.Close()
	if err != nil {
		return err
	}
	b := &pem.Block{Bytes: p, Type: Type}
	return pem.Encode(file, b)
}

// CreateCrt 创建证书对
func CreateCrt(rootCa *x509.Certificate, rootKey *rsa.PrivateKey, info CertInformation) error {
	crt := newCertificate(info)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	var buf []byte
	if rootCa == nil || rootKey == nil {
		// 创建自签名证书
		buf, err = x509.CreateCertificate(rand.Reader, crt, crt, &key.PublicKey, key)
	} else {
		// 使用根证书签名
		buf, err = x509.CreateCertificate(rand.Reader, crt, rootCa, &key.PublicKey, rootKey)
	}
	if err != nil {
		return err
	}

	err = write(info.CrtPath, "CERTIFICATE", buf)
	if err != nil {
		return err
	}
	buf = x509.MarshalPKCS1PrivateKey(key)
	return write(info.KeyPath, "PRIVATE KEY", buf)
}

// ParseCrt 解析Crt
func ParseCrt(path string) (*x509.Certificate, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &pem.Block{}
	p, buf = pem.Decode(buf)
	return x509.ParseCertificate(p.Bytes)
}

// Parse 解析证书和密钥
func Parse(crtPath, keyPath string) (rootCertificate *x509.Certificate, rootPrivateKey *rsa.PrivateKey, err error) {
	rootCertificate, err = ParseCrt(crtPath)
	if err != nil {
		return
	}
	rootPrivateKey, err = ParseKey(keyPath)
	return
}

// ParseKey 解析密钥
func ParseKey(path string) (*rsa.PrivateKey, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, buf := pem.Decode(buf)
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}
