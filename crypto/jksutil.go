package crypto

import (
	"crypto/x509"
	"log"
	"os"
	"time"

	"github.com/macdfree/keystore-go"
)

// CreateJks 创建jks
func CreateJks(alias string, crtPath []string, keyPath string, jksPath, password string) error {
	var crts []keystore.Certificate

	for _, v := range crtPath {
		crt, err := ParseCrt(v)
		if err != nil {
			return err
		}
		c := keystore.Certificate{Type: "X.509", Content: crt.Raw}
		crts = append(crts, c)
	}

	key, err := ParseKey(keyPath)
	if err != nil {
		return err
	}

	entry := &keystore.PrivateKeyEntry{
		Entry:     keystore.Entry{CreationDate: time.Now()},
		PrivKey:   x509.MarshalPKCS1PrivateKey(key),
		CertChain: crts,
	}
	ks := keystore.KeyStore{
		alias: entry,
	}
	writeKeyStore(ks, jksPath, []byte(password))
	return nil
}

func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		log.Fatal(err)
	}
	return keyStore
}

func writeKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	o, err := os.Create(filename)
	defer o.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = keystore.Encode(o, keyStore, password)
	if err != nil {
		log.Fatal(err)
	}
}
