package datatypes

import (
	"strconv"
)

type User struct {
	FirstName string
	LastName  string
	IsActive  bool
	Elo       int
	PublicKey string
}

func NewUser(firstName string, lastName string, isActive bool, elo int, publicKey string) *User {
	return &User{
		FirstName: firstName,
		LastName:  lastName,
		IsActive:  isActive,
		Elo:       elo,
		PublicKey: publicKey,
	}
}

func (u *User) CreateTLV() TLV {
	isActive := 0
	if u.IsActive {
		isActive = 1
	}
	v := []byte(u.FirstName + ";" + u.LastName + ";" + strconv.Itoa(isActive) + ";" + strconv.Itoa(u.Elo) + ";" + u.PublicKey)
	tlv := NewTLV(0x00, v)
	return tlv
}
