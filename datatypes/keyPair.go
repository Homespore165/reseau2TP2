package datatypes

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

func VerifySignature(signature []byte, key string) bool {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return false
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	hashed := sha256.Sum256(signature[:len(signature)-256-1])
	err = rsa.VerifyPKCS1v15(parsedKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signature[len(signature)-256:])
	if err != nil {
		return false
	}
	return true
}
