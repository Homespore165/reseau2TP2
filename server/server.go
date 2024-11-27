package server

import (
	"bufio"
	"fmt"
	"github.com/google/uuid"
	"github.com/notnil/chess"
	"log"
	"net"
	"reseau2TP2/datatypes"
	"strconv"
	"strings"
	"time"
)

var err error
var games map[uuid.UUID]*chess.Game
var keyPair datatypes.KeyPair

func Init() error {
	defer fmt.Println("Server started")
	db, err = initDB()
	if err != nil {
		return err
	}
	go func() {
		err := tcpManager()
		if err != nil {
			log.Fatal(err)
		}
	}()
	keyPair, err = datatypes.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func tcpManager() error {
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn)
	}
}

func gameManager() {
	for {
		for uuid := range games {
			storedTime, err := getLastMoveTime(uuid.String())
			if err != nil {
				log.Fatal(err)
			}
			lastMoveTime, err := time.Parse("2006-01-02 15:04:05", storedTime)
			if err != nil {
				log.Fatal(err)
			}

			if time.Since(lastMoveTime) > 10*time.Minute {
				delete(games, uuid)
			}
		}
	}
}
func validateSignature(tlv datatypes.TLV) bool {
	keys, _ := getPublicKeys()
	for _, key := range keys {
		if _, err := tlv.Verify(key); err == nil {
			return true
		}
	}
	return false
}

func handleConnection(c net.Conn) {
	defer func(c net.Conn) {
		err := c.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(c)

	reader := bufio.NewReader(c)
	for {
		// Read the raw bytes
		rawBytes, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Println(err)
			break
		}

		// Remove the newline character
		rawBytes = rawBytes[:len(rawBytes)-1]

		// Decode the TLV
		tlv, err := datatypes.Decode(rawBytes)
		if err != nil {
			fmt.Println(err)
		}

		switch tlv.Tag {
		case 0x00: // HelloRequest
			val := strings.Split(string(tlv.Value[:]), ";")
			fn := val[0]
			ln := val[1]
			active := val[2]
			elo := val[3]
			key := val[4]
			eloInt, _ := strconv.Atoi(elo)
			user := datatypes.User{
				FirstName: fn,
				LastName:  ln,
				IsActive:  active == "1",
				Elo:       eloInt,
				PublicKey: key,
			}
			err := createNewUser(&user)
			if err != nil {
				log.Fatal(err)
			}
			tlv := datatypes.NewTLV(0x03, []byte(keyPair.PublicKey))
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}
		case 0x1E: // GetAvailableGames
			verified := validateSignature(tlv)
			if !verified {
				break
			}
			// TODO: Implement

		}
	}
}
