package client

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"reseau2TP2/datatypes"
	"strconv"
	"strings"

	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	_ "github.com/tidwall/sjson"
)

type Client struct {
	configFile      string
	conn            net.Conn
	KeyPair         datatypes.KeyPair
	ServerPublicKey string
	isLoggedIn      bool
	inGame          bool
}

func Init(configFile string) (Client, error) {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return Client{}, err
	}

	client := Client{
		configFile: configFile,
		conn:       conn,
	}

	err = createConfig(configFile)
	if err != nil {
		return Client{}, err
	}

	keyPair := datatypes.KeyPair{
		PublicKey:  client.getConfig("key.public"),
		PrivateKey: client.getConfig("key.private"),
	}
	client.KeyPair = keyPair

	client.ServerPublicKey = client.getConfig("ServerPublicKey")

	return client, nil
}

func createConfig(configFile string) error {
	if _, err := os.Stat(configFile); err == nil {
		return nil
	}

	file, err := os.Create(configFile)
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

	keyPair, err := datatypes.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	json, _ = sjson.Set(json, "key.public", keyPair.PublicKey)
	json, _ = sjson.Set(json, "key.private", keyPair.PrivateKey)

	_, err = file.WriteString(json)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) loadConfig(configFile string) {
	c.KeyPair.PublicKey = c.getConfig("key.public")
	c.KeyPair.PrivateKey = c.getConfig("key.private")
	c.ServerPublicKey = c.getConfig("ServerPublicKey")
	c.isLoggedIn = c.getConfig("isLoggedIn") == "true"
	c.inGame = c.getConfig("inGame") == "true"
}

func (c *Client) setConfig(path string, value interface{}) {
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	json, err := os.ReadFile(c.configFile)
	if err != nil {
		log.Fatal(err)
	}
	jsonString := string(json[:])
	jsonString, _ = sjson.Set(jsonString, path, value)
	err = os.WriteFile(c.configFile, []byte(jsonString), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func (c *Client) getConfig(path string) string {
	json, err := os.ReadFile(c.configFile)
	if err != nil {
		log.Fatal(err)
	}
	value := gjson.Get(string(json[:]), path)
	return value.String()
}

func (c *Client) awaitMove() {
	tlv, err := c.Receive()
	if err != nil {
		log.Fatal(err)
	}
	err = tlv.Decrypt(c.KeyPair.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		log.Fatal("Invalid signature")
	}

	if tlv.Tag != 0x81 {
		c.Send(tlv)
		c.awaitMove()
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
	if c.isLoggedIn {
		fmt.Println("Already logged in")
		return nil
	}

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
	c.ServerPublicKey = string(tlv.Value[:])
	c.setConfig("ServerPublicKey", c.ServerPublicKey)
	c.isLoggedIn = true
	return nil
}

func (c *Client) GetAvailableGames() []uuid.UUID {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return nil
	}

	tlv := datatypes.NewTLV(0x1F, []byte{})
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
	verified, err := tlv.Verify(c.ServerPublicKey)
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

func (c *Client) HostGame() {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	if c.inGame {
		fmt.Println("Already in a game")
		return
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
	if tlv.Tag != 0x82 && tlv.Tag != 0x83 {
		log.Fatal("Invalid response")
	}
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		log.Fatal("Invalid signature")
	}
	if tlv.Tag == 0x82 {
		c.inGame = true
		c.setConfig("inGame", "true")
	} else {
		fmt.Println("Player already in game")
	}
}

func (c *Client) JoinGame(gameID uuid.UUID) {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	if c.inGame {
		fmt.Println("Already in a game")
		return
	}

	tlv := datatypes.NewTLV(0x20, []byte(gameID.String()+";"))
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
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		log.Fatal("Invalid signature")
	}
	c.inGame = true
	c.setConfig("inGame", "true")

	if tlv.Tag == 0x82 {
		c.awaitMove()
	}
}

func (c *Client) PlayMove(move string) {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	if !c.inGame {
		fmt.Println("Not in a game")
		return
	}

	tlv := datatypes.NewTLV(0x21, []byte(move))
	tlv.Sign(c.KeyPair.PrivateKey)
	tlv.Encrypt(c.ServerPublicKey)
	err := c.Send(tlv)
	if err != nil {
		log.Fatal(err)
	}

	tlv, err = c.Receive()
	tlv.Decrypt(c.KeyPair.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		log.Fatal("Invalid signature")
	}

	log.SetPrefix("Client: ")
	log.Println("Tag Received: " + string(tlv.Tag))
	switch tlv.Tag {
	case 0x82:
		log.Println("Move accepted")
	case 0x83:
		log.Println("Move rejected")
	}
	log.SetPrefix("Server: ")

	if tlv.Tag == 0x82 {
		c.awaitMove()
	}
}

func (c *Client) GetAvailableMoves() []string {
	var moves []string
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return nil
	}

	if !c.inGame {
		fmt.Println("Not in a game")
		return nil
	}

	tlv := datatypes.NewTLV(0x22, []byte{})
	tlv.Sign(c.KeyPair.PrivateKey)
	tlv.Encrypt(c.ServerPublicKey)
	err := c.Send(tlv)
	if err != nil {
		log.Fatal(err)
	}

	tlv, err = c.Receive()
	if err != nil {
		log.Fatal(err)
	}
	tlv.Decrypt(c.KeyPair.PrivateKey)
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		log.Fatal("Invalid signature")
	}

	val := strings.Split(string(tlv.Value[:]), ";")
	nbMoves, err := strconv.Atoi(string(val[0]))
	if err != nil {
		log.Fatal(err)
	}
	for i := 1; i <= nbMoves; i++ {
		moves = append(moves, val[i])
	}

	return moves
}
