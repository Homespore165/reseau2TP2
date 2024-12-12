package client

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"log"
	"net"
	"os"
	"reseau2TP2/datatypes"
	"strconv"
	"strings"
	"sync"
)

type Client struct {
	configFile      string
	conn            net.Conn
	connUDP         net.UDPConn
	KeyPair         datatypes.KeyPair
	ServerPublicKey string
	isLoggedIn      bool
	inGame          bool
	moveMutex       *sync.Mutex
	moveWaitCancel  chan struct{}
	awaitingMove    bool
	logger          *log.Logger
	mode            string
}

func Init(configFile string, i int) (Client, error) {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return Client{}, err
	}

	udpServer, err := net.ResolveUDPAddr("udp", "localhost:8081")
	if err != nil {
		return Client{}, err
	}
	connUDP, err := net.DialUDP("udp", nil, udpServer)
	if err != nil {
		return Client{}, err
	}

	logger := log.New(os.Stdout, fmt.Sprintf("Client %d: ", i), log.LstdFlags)
	client := Client{
		configFile:     configFile,
		conn:           conn,
		connUDP:        *connUDP,
		moveMutex:      &sync.Mutex{},
		moveWaitCancel: make(chan struct{}),
		logger:         logger,
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
	client.mode = client.getConfig("protocol")

	return client, nil
}

func createConfig(configFile string) error {
	log.SetPrefix("Client: ")
	defer log.SetPrefix("Server: ")
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

func (c *Client) setConfig(path string, value interface{}) {
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0644)
	if err != nil {
		c.logger.Fatal(err)
	}
	defer file.Close()

	json, err := os.ReadFile(c.configFile)
	if err != nil {
		c.logger.Fatal(err)
	}
	jsonString := string(json[:])
	jsonString, _ = sjson.Set(jsonString, path, value)
	err = os.WriteFile(c.configFile, []byte(jsonString), 0644)
	if err != nil {
		c.logger.Fatal(err)
	}
}

func (c *Client) RejoinWhite() {
	c.inGame = true
}

func (c *Client) RejoinBlack() {
	c.inGame = true
	go c.awaitMove()
}

func (c *Client) getConfig(path string) string {
	json, err := os.ReadFile(c.configFile)
	if err != nil {
		c.logger.Fatal(err)
	}
	value := gjson.Get(string(json[:]), path)
	return value.String()
}

func (c *Client) awaitMove() {
	c.awaitingMove = true
	defer func() {
		c.awaitingMove = false
	}()
	c.moveMutex.Lock()
	defer c.moveMutex.Unlock()
	c.logger.Println("Waiting for move")

	select {
	case <-c.moveWaitCancel:
		return
	default:
		tlv, err := c.Receive()
		if err != nil {
			c.logger.Fatal(err)
		}
		err = tlv.Decrypt(c.KeyPair.PrivateKey)
		if err != nil {
			c.logger.Fatal(err)
		}
		verified, err := tlv.Verify(c.ServerPublicKey)
		if err != nil || !verified {
			c.logger.Fatal("Invalid signature")
		}

		switch tlv.Tag {
		case 0x80:
			c.setConfig("inGame", "false")
			c.inGame = false
			val := strings.Split(string(tlv.Value[:]), ";")
			c.setConfig("history.-1", val[0])
			c.logger.Println("Game over")
		case 0x81:
			c.logger.Println("Move received")
			val := strings.Split(string(tlv.Value[:]), ";")
			c.logger.Println(val[0])
			return
		default:
			c.awaitMove()
		}

		if tlv.Tag != 0x81 {
			c.awaitMove()
		}
	}
}

func (c *Client) Send(message datatypes.TLV) error {
	if c.mode == "tcp" {
		return c.SendTCP(message)
	} else {
		return c.SendUDP(message)
	}
}

func (c *Client) SendTCP(message datatypes.TLV) error {
	_, err := c.conn.Write(message.Encode())
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) SendUDP(message datatypes.TLV) error {
	_, err := c.connUDP.Write(message.Encode())
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Receive() (datatypes.TLV, error) {
	if c.mode == "tcp" {
		return c.ReceiveTCP()
	} else {
		return c.ReceiveUDP()
	}
}

func (c *Client) ReceiveTCP() (datatypes.TLV, error) {
	reader := bufio.NewReader(c.conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return datatypes.TLV{}, err
	}
	r, err := datatypes.Decode(line)
	if err != nil {
		c.logger.Fatal(err)
	}
	return r, nil
}

func (c *Client) ReceiveUDP() (datatypes.TLV, error) {
	b := make([]byte, 1024)
	_, err := c.connUDP.Read(b)
	if err != nil {
		return datatypes.TLV{}, err
	}
	return datatypes.Decode(b)
}

func (c *Client) Close() {
	c.conn.Close()
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
		c.logger.Fatal(err)
	}

	tlv, err = c.Receive()
	if err != nil {
		c.logger.Fatal(err)
	}
	if tlv.Tag != 0x82 {
		c.logger.Fatal("Invalid response")
	}

	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		c.logger.Println("Invalid signature")
		return nil
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
		c.logger.Fatal(err)
	}

	tlv, err = c.Receive()
	if err != nil {
		c.logger.Fatal(err)
	}
	if tlv.Tag != 0x82 && tlv.Tag != 0x83 {
		c.logger.Fatal(tlv.Tag)
	}
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		c.logger.Fatal("Invalid signature")
	}
	if tlv.Tag == 0x82 {
		c.inGame = true
		c.setConfig("inGame", "true")
	} else {
		fmt.Println("Player already in game")
	}
}

func (c *Client) JoinSolo() {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	if c.inGame {
		fmt.Println("Already in a game")
		return
	}

	tlv := datatypes.NewTLV(0x1D, []byte{})
	tlv.Sign(c.KeyPair.PrivateKey)
	err := c.Send(tlv)
	if err != nil {
		c.logger.Fatal(err)
	}

	tlv, err = c.Receive()
	if err != nil {
		c.logger.Fatal(err)
	}
	if tlv.Tag != 0x82 && tlv.Tag != 0x83 {
		c.logger.Fatal(tlv.Tag)
	}
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		c.logger.Fatal("Invalid signature")
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
		c.logger.Fatal(err)
	}

	tlv, err = c.Receive()
	if err != nil {
		c.logger.Fatal(err)
	}
	if tlv.Tag != 0x82 {
		c.logger.Fatal("Invalid response")
	}
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		c.logger.Fatal("Invalid signature")
	}
	c.inGame = true
	c.setConfig("inGame", "true")
	go c.awaitMove()
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

	if c.awaitingMove {
		fmt.Println("Awaiting move")
		return
	}

	c.moveMutex.Lock()
	defer c.moveMutex.Unlock()

	tlv := datatypes.NewTLV(0x21, []byte(move))
	tlv.Sign(c.KeyPair.PrivateKey)
	tlv.Encrypt(c.ServerPublicKey)
	err := c.Send(tlv)
	if err != nil {
		c.logger.Fatal(err)
	}

	tlv, err = c.Receive()
	tlv.Decrypt(c.KeyPair.PrivateKey)
	if err != nil {
		c.logger.Fatal(err)
	}

	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		c.logger.Fatal("Invalid signature")
	}

	switch tlv.Tag {
	case 0x80:
		c.setConfig("inGame", "false")
		c.inGame = false
		val := strings.Split(string(tlv.Value[:]), ";")
		c.setConfig("history.-1", val[0])
		c.logger.Println("Game over")
		close(c.moveWaitCancel)
		return
	case 0x82:
		c.logger.Println("Move accepted")
	case 0x83:
		c.logger.Println("Move rejected")
		c.awaitingMove = false
	}

	go c.awaitMove()
}

func (c *Client) GetAvailableMoves() []string {
	close(c.moveWaitCancel)
	c.moveWaitCancel = make(chan struct{})
	c.moveMutex.Lock()
	defer c.moveMutex.Unlock()

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
		c.logger.Fatal(err)
	}

	tlv, err = c.Receive()
	if err != nil {
		c.logger.Fatal(err)
	}
	tlv.Decrypt(c.KeyPair.PrivateKey)
	verified, err := tlv.Verify(c.ServerPublicKey)
	if err != nil || !verified {
		c.logger.Fatal("Invalid signature")
	}

	val := strings.Split(string(tlv.Value[:]), ";")
	nbMoves, err := strconv.Atoi(val[0])
	if err != nil {
		c.logger.Fatal(err)
	}
	for i := 1; i < nbMoves; i++ {
		moves = append(moves, val[i])
	}

	go c.awaitMove()

	return moves
}

func (c *Client) CLI() {
	var items []string
	if !c.isLoggedIn {
		items = append(items, "Login")
	} else {
		if !c.inGame {
			items = append(items, "Host game")
			items = append(items, "Join solo")
			items = append(items, "Join game")
			items = append(items, "Get available games")
		} else {
			items = append(items, "Play move")
			items = append(items, "Get available moves")
		}
		items = append(items, "Quit")
	}
	prompt := promptui.Select{
		Label: "What do you want to do?",
		Items: items,
	}

	_, result, err := prompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}

	switch result {
	case "Login":
		c.loginCLI()
	case "Host game":
		c.HostGame()
		c.CLI()
	case "Join solo":
		c.JoinSolo()
		c.CLI()
	case "Join game":
		c.joinGameCLI()
	case "Get available games":
		c.getAvailableGamesCLI()
	case "Play move":
		c.playMoveCLI()
	case "Get available moves":
		c.getAvailableMovesCLI()
	case "Quit":
		c.Close()
	}
}

func (c *Client) loginCLI() {
	if c.isLoggedIn {
		fmt.Println("Already logged in")
		return
	}

	firstNamePrompt := promptui.Prompt{
		Label: "First name",
	}
	firstName, err := firstNamePrompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}

	lastNamePrompt := promptui.Prompt{
		Label: "Last name",
	}
	lastName, err := lastNamePrompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}

	eloPrompt := promptui.Prompt{
		Label: "Elo",
		Validate: func(s string) error {
			_, err := strconv.Atoi(s)
			if err != nil {
				return errors.New("Invalid number")
			}
			return nil
		},
	}
	elo, err := eloPrompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}
	eloInt, err := strconv.Atoi(elo)
	if err != nil {
		c.logger.Fatal(err)
	}

	user := datatypes.NewUser(firstName, lastName, true, eloInt, c.KeyPair.PublicKey)
	err = c.Login(*user)
	if err != nil {
		c.logger.Fatal(err)
	}
	c.CLI()
}

func (c *Client) joinGameCLI() {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	gameIDPrompt := promptui.Prompt{
		Label: "Game ID",
	}
	gameID, err := gameIDPrompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}
	gameIDUUID, err := uuid.Parse(gameID)
	if err != nil {
		c.logger.Fatal(err)
	}

	c.JoinGame(gameIDUUID)
}

func (c *Client) getAvailableGamesCLI() {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	games := c.GetAvailableGames()
	gamesID := make([]string, len(games))
	for _, game := range games {
		gamesID = append(gamesID, game.String())
	}
	gamesID = gamesID[1:]
	prompt := promptui.Select{
		Label: "Select a game",
		Items: gamesID,
	}

	_, result, err := prompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}

	gameID, err := uuid.Parse(result)
	if err != nil {
		c.logger.Fatal(err)
	}

	c.JoinGame(gameID)
	c.CLI()
}

func (c *Client) playMoveCLI() {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	if !c.inGame {
		fmt.Println("Not in a game")
		return
	}

	if c.awaitingMove {
		fmt.Println("Awaiting move")
		c.CLI()
	}

	movePrompt := promptui.Prompt{
		Label: "Move",
	}
	move, err := movePrompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}

	c.PlayMove(move)
	c.CLI()
}

func (c *Client) getAvailableMovesCLI() {
	if !c.isLoggedIn {
		fmt.Println("Not logged in")
		return
	}

	if !c.inGame {
		fmt.Println("Not in a game")
		return
	}

	if c.awaitingMove {
		fmt.Println("Awaiting move")
		c.CLI()
	}

	moves := c.GetAvailableMoves()
	fmt.Println("Available moves:")
	for _, move := range moves {
		fmt.Println(move)
	}
	if len(moves) == 0 {
		fmt.Println("No available moves")
		c.CLI()
		return
	}

	prompt := promptui.Select{
		Label: "Select a move",
		Items: moves,
	}

	_, result, err := prompt.Run()
	if err != nil {
		c.logger.Fatal(err)
	}

	c.PlayMove(result)
	c.CLI()
}
