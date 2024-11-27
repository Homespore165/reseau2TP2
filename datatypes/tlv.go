package datatypes

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"strings"
)

type TLV struct {
	Tag    uint8
	Length int
	Value  []byte
}

func NewTLV(t uint8, v []byte) TLV {
	return TLV{Tag: t, Length: len(v), Value: v}
}

func (t *TLV) Encode() []byte {
	newLineReplacedValue := strings.ReplaceAll(string(t.Value[:]), "\n", "\\n")
	t.Value = []byte(newLineReplacedValue)
	t.Length = len(t.Value)
	var b []byte
	b = append(b, t.Tag)
	b = append(b, byte(t.Length>>8), byte(t.Length))
	b = append(b, t.Value...)
	b = append(b, '\n')
	return b
}

func Decode(b []byte) (TLV, error) {
	// Check if the slice is long enough to contain Tag, Length, and at least some Value
	if len(b) < 3 {
		return TLV{}, errors.New("byte slice too short to decode TLV")
	}

	// Extract Tag
	tag := b[0]

	// Extract Length (2 bytes, big-endian)
	length := int(b[1])<<8 | int(b[2])

	// Ensure the slice is long enough to contain the specified length
	if len(b) < 3+length {
		return TLV{}, errors.New("insufficient bytes for specified length")
	}

	// Extract Value
	value := b[3 : 3+length]
	valueString := string(value[:])
	valueString = strings.ReplaceAll(valueString, "\\n", "\n")
	value = []byte(valueString)

	return TLV{
		Tag:    tag,
		Length: length,
		Value:  value,
	}, nil
}

func (t *TLV) Sign(privateKey string) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		log.Fatal("Failed to decode private key")
	}
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	hashed := sha256.Sum256(t.Value)
	signature, err := rsa.SignPKCS1v15(rand.Reader, parsedKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatal(err)
	}
	t.Value = append(t.Value, ";"...)
	t.Value = append(t.Value, signature...)
	t.Length = len(t.Value)
}

func (t *TLV) Verify(publicKey string) (bool, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return false, errors.New("Failed to decode public key")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	hashed := sha256.Sum256(t.Value[:len(t.Value)-256-1])
	err = rsa.VerifyPKCS1v15(parsedKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], t.Value[len(t.Value)-256:])
	if err != nil {
		return false, err
	}
	return true, nil
}
