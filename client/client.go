package client

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"reseau2TP2/datatypes"
	"strings"

	"github.com/google/uuid"
	_ "github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	_ "github.com/tidwall/sjson"
)

type Client struct {
	conn            net.Conn
	KeyPair         datatypes.KeyPair
	serverPublicKey string
	isLoggedIn      bool
}

func Init() (Client, error) {
	err := createConfig()
	if err != nil {
		return Client{}, err
	}

	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return Client{}, err
	}

	keyPair, err := datatypes.GenerateKeyPair()
	if err != nil {
		return Client{}, err
	}

	setConfig("key.public", keyPair.PublicKey)
	setConfig("key.private", keyPair.PrivateKey)

	return Client{
		conn:    conn,
		KeyPair: keyPair,
	}, nil
}

func createConfig() error {
	if _, err := os.Stat("./client/config.json"); err == nil {
		return nil
	}

	file, err := os.Create("./client/config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	json := `{
	"ip": "127.0.0.1",
	"port": {
	"tcp": 8080,
	"udp": 8081
	},
	"protocol": "tcp"
	}`
	_, err = file.WriteString(json)
	if err != nil {
		return err
	}
	return nil
}

func setConfig(path string, value interface{}) {
	file, err := os.OpenFile("./client/config.json", os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	json, err := os.ReadFile("./client/config.json")
	if err != nil {
		log.Fatal(err)
	}
	jsonString := string(json[:])
	jsonString, _ = sjson.Set(jsonString, path, value)
	err = os.WriteFile("./client/config.json", []byte(jsonString), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func (c *Client) Send(message datatypes.TLV) error {
	_, err := c.conn.Write(message.Encode())
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Receive() (datatypes.TLV, error) {
	reader := bufio.NewReader(c.conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return datatypes.TLV{}, err
	}
	r, err := datatypes.Decode(line)
	if err != nil {
		log.Fatal(err)
	}
	return r, nil
}

func (c *Client) Login(user datatypes.User) error {
	tlv := user.CreateTLV()
	tlv.Encode()
	err := c.Send(tlv)
	if err != nil {
		return err
	}
	tlv, err = c.Receive()
	if err != nil {
		return err
	}
	if tlv.Tag != 0x03 {
		return errors.New("Invalid response")
	}
	c.serverPublicKey = string(tlv.Value[:])
	setConfig("serverPublicKey", c.serverPublicKey)
	c.isLoggedIn = true
	return nil
}

func (c *Client) GetAvailableGames() []uuid.UUID {
	if !c.isLoggedIn {
		log.Fatal("Not logged in")
	}

	tlv := datatypes.NewTLV(0x1E, []byte{})
	tlv.Sign(c.KeyPair.PrivateKey)
	err := c.Send(tlv)
	if err != nil {
		log.Fatal(err)
	}

	tlv, err = c.Receive()
	if err != nil {
		log.Fatal(err)
	}
	if tlv.Tag != 0x82 {
		log.Fatal("Invalid response")
	}
	verified, err := tlv.Verify(c.serverPublicKey)
	if err != nil || !verified {
		log.Fatal("Invalid signature")
	}

	val := strings.Split(string(tlv.Value[:]), ";")
	var games []uuid.UUID
	for _, v := range val {
		uuid, err := uuid.Parse(v)
		if err != nil {
			continue
		}
		games = append(games, uuid)
	}
	return games
}
