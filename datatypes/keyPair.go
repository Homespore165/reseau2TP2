package datatypes

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	_ "strings"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

func GenerateKeyPair() (KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyPair{}, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPem := string(pem.EncodeToMemory(privatePemBlock))

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return KeyPair{}, err
	}
	publicPemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPem := string(pem.EncodeToMemory(publicPemBlock))

	return KeyPair{
		PublicKey:  publicKeyPem,
		PrivateKey: privateKeyPem,
	}, nil
}

//
// func IsolateKey(key string) string {
// 	lines := strings.Split(key, "\n")
// 	isolatedKey := strings.Join(lines[1:len(lines)-2], "\n")
// 	return "-----BEGIN RSA PUBLIC KEY-----\n" + isolatedKey + "\n-----END RSA PUBLIC KEY-----\n"
// }
