package server

import (
	"bufio"
	"fmt"
	"github.com/google/uuid"
	"github.com/notnil/chess"
	"github.com/notnil/chess/uci"
	"log"
	"net"
	"reseau2TP2/datatypes"
	"strconv"
	"strings"
	"sync"
	"time"
)

var err error
var games map[uuid.UUID]*chess.Game
var keyPair datatypes.KeyPair
var activeConnections = make(map[string]net.Conn)
var connectionsMutex sync.Mutex

func Init() error {
	defer log.Println("Server started")
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
	go gameManager()
	games = make(map[uuid.UUID]*chess.Game)
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
		var gameUUIDs []uuid.UUID

		connectionsMutex.Lock()
		for uuid := range games {
			gameUUIDs = append(gameUUIDs, uuid)
		}
		connectionsMutex.Unlock()

		for _, uuid := range gameUUIDs {
			storedTime, err := getLastMoveTime(uuid.String())
			if err != nil {
				log.Println("Error getting last move time:", err)
				continue
			}

			lastMoveTime, err := time.Parse("2006-01-02 15:04:05", storedTime)
			if err != nil {
				log.Println("Error parsing time:", err)
				continue
			}

			if time.Since(lastMoveTime) > 10*time.Minute {
				connectionsMutex.Lock()
				delete(games, uuid)
				connectionsMutex.Unlock()
			}
		}

		time.Sleep(1 * time.Minute)
	}
}

func getConnectionForPlayer(publicKey string) (net.Conn, error) {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	conn, exists := activeConnections[publicKey]
	if !exists {
		return nil, fmt.Errorf("no active connection for player with public key %s", publicKey)
	}
	return conn, nil
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

func getPlayerIDFromSignature(signature []byte) int {
	keys, _ := getPublicKeys()
	for _, key := range keys {
		if verified := datatypes.VerifySignature(signature, key); verified {
			return getPlayerIDFromPublicKey(key)
		}
	}
	return -1
}

func playerInGame(playerID int) bool {
	gameList, err := getGamesByPlayerID(playerID)
	if err != nil {
		log.Fatal(err)
	}
	for _, game := range gameList {
		if loadGame(game).Outcome() == chess.NoOutcome {
			return true
		}
	}
	return false
}

func loadGame(gameID string) *chess.Game {
	pgn, err := getPGN(gameID)
	if err != nil {
		return chess.NewGame()
	}
	game, err := chess.PGN(strings.NewReader(pgn))
	if err != nil {
		log.Fatal(err)
	}
	return chess.NewGame(game)
}

func handleConnection(c net.Conn) {
	log.SetPrefix("Server: ")
	var playerPublicKey string

	defer func(c net.Conn) {
		err := c.Close()
		if err != nil {
			log.Fatal(err)
		}

		if playerPublicKey != "" {
			connectionsMutex.Lock()
			delete(activeConnections, playerPublicKey)
			connectionsMutex.Unlock()
		}
		c.Close()
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
		case 0x00: // Login
			log.Println("Login")
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
			if !publicKeyExists(key) {
				err := createNewUser(&user)
				if err != nil {
					log.Fatal(err)
				}
			}
			tlv := datatypes.NewTLV(0x03, []byte(keyPair.PublicKey))
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}

			playerPublicKey = key

			connectionsMutex.Lock()
			activeConnections[playerPublicKey] = c
			connectionsMutex.Unlock()
		case 0x1D: // JoinSolo
			log.Println("HostGame")
			verified := validateSignature(tlv)
			if !verified {
				break
			}

			gameID := uuid.New()
			//TODO: add collision detection
			whiteID := getPlayerIDFromSignature(tlv.Value[:])
			blackID := 0
			if playerInGame(whiteID) {
				tlv := datatypes.NewTLV(0x82, []byte("Player already in game"))
				tlv.Sign(keyPair.PrivateKey)
				_, err = c.Write(tlv.Encode())
				if err != nil {
					log.Fatal(err)
				}
				break
			}
			createNewGame(gameID.String(), whiteID, blackID)

			tlv = datatypes.NewTLV(0x82, []byte(gameID.String()))
			tlv.Sign(keyPair.PrivateKey)
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}
		case 0x1E: // HostGame
			log.Println("HostGame")
			verified := validateSignature(tlv)
			if !verified {
				break
			}

			gameID := uuid.New()
			//TODO: add collision detection
			whiteID := getPlayerIDFromSignature(tlv.Value[:])
			blackID := -1
			if playerInGame(whiteID) {
				tlv := datatypes.NewTLV(0x82, []byte("Player already in game"))
				tlv.Sign(keyPair.PrivateKey)
				_, err = c.Write(tlv.Encode())
				if err != nil {
					log.Fatal(err)
				}
				break
			}
			createNewGame(gameID.String(), whiteID, blackID)

			tlv = datatypes.NewTLV(0x82, []byte(gameID.String()))
			tlv.Sign(keyPair.PrivateKey)
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}
		case 0x1F: // GetAvailableGames
			log.Println("GetAvailableGames")
			verified := validateSignature(tlv)
			if !verified {
				break
			}

			gameList := getUnstartedGames()
			var gameIDs string
			for _, game := range gameList {
				gameIDs += game + ";"
			}
			tlv = datatypes.NewTLV(0x82, []byte(gameIDs))
			tlv.Sign(keyPair.PrivateKey)
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}
		case 0x20: // JoinGame
			log.Println("JoinGame")
			verified := validateSignature(tlv)
			if !verified {
				break
			}
			val := strings.Split(string(tlv.Value[:]), ";")
			gameID := val[0]
			playerID := getPlayerIDFromSignature(tlv.Value[:])
			if games[uuid.MustParse(gameID)] == nil {
				if gameExists(gameID) {
					joinGame(gameID, playerID)
				}
			} else {
				joinGame(gameID, playerID)
			}

			tlv = datatypes.NewTLV(0x82, []byte(gameID))
			tlv.Sign(keyPair.PrivateKey)
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}
		case 0x21: // PlayMove
			log.Println("PlayMove")
			err := tlv.Decrypt(keyPair.PrivateKey)
			if err != nil {
				log.Println(err)
			}
			verified := validateSignature(tlv)
			if !verified {
				break
			}

			playerID := getPlayerIDFromSignature(tlv.Value[:])
			gameID, err := findActiveGame(playerID)
			if err != nil {
				log.Println(err)
				break
			}
			if games[uuid.MustParse(gameID)] == nil {
				games[uuid.MustParse(gameID)] = loadGame(gameID)
			}

			game := games[uuid.MustParse(gameID)]
			pgn := game.String()

			var currentID int
			if game.Position().Turn() == chess.Black {
				currentID, err = getBlackPlayerID(gameID)
				if err != nil {
					log.Println(err)
					break
				}

			} else {
				currentID, err = getWhitePlayerID(gameID)
				if err != nil {
					log.Println(err)
					break
				}
			}

			if currentID != playerID {
				tlv = datatypes.NewTLV(0x83, []byte("Not your turn"))
				tlv.Sign(keyPair.PrivateKey)
				pbKey, err := getPlayerPublicKey(playerID)
				if err != nil {
					log.Println(err)
					break
				}
				tlv.Encrypt(pbKey)
				_, err = c.Write(tlv.Encode())
				if err != nil {
					log.Fatal(err)
				}
				break
			}

			success := "Move successful"
			val := strings.Split(string(tlv.Value[:]), ";")
			move := val[0]
			err = game.MoveStr(move)
			if err != nil {
				log.Println(err)
				success = "Invalid move"
				tlv = datatypes.NewTLV(0x83, []byte(success))
				tlv.Sign(keyPair.PrivateKey)
				pbKey, err := getPlayerPublicKey(playerID)
				if err != nil {
					log.Println(err)
					break
				}
				tlv.Encrypt(pbKey)
				_, err = c.Write(tlv.Encode())
				if err != nil {
					log.Fatal(err)
				}
				break
			}

			pgn = game.String()
			err = saveGame(gameID, pgn)
			if err != nil {
				log.Println(err)
				break
			}

			var tag uint8 = 0x82
			if game.Outcome() != chess.NoOutcome {
				tag = 0x80
				success = game.FEN()
			}
			pbKey, err := getPlayerPublicKey(playerID)
			if err != nil {
				log.Println(err)
				break
			}

			// Send response to player
			tlv = datatypes.NewTLV(tag, []byte(success))
			tlv.Sign(keyPair.PrivateKey)
			tlv.Encrypt(pbKey)
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}

			// TODO: handle playing against AI
			if blackID, _ := getBlackPlayerID(gameID); blackID == 0 {
				// AI move
				eng, err := uci.New("stockfish")
				if err != nil {
					panic(err)
				}
				defer eng.Close()
				if game.Outcome() == chess.NoOutcome {
					if err := eng.Run(uci.CmdUCI, uci.CmdIsReady, uci.CmdUCINewGame); err != nil {
						panic(err)
					}

					cmdPos := uci.CmdPosition{Position: game.Position()}
					cmdGo := uci.CmdGo{MoveTime: 2 * time.Second}
					if err := eng.Run(cmdPos, cmdGo); err != nil {
						panic(err)
					}
					move := eng.SearchResults().BestMove
					if err := game.Move(move); err != nil {
						panic(err)
					}

					tag = 0x81
					if game.Outcome() != chess.NoOutcome {
						tag = 0x80
						tlv = datatypes.NewTLV(tag, []byte(game.FEN()))
						tlv.Sign(keyPair.PrivateKey)
						tlv.Encrypt(pbKey)
						_, err = c.Write(tlv.Encode())
						if err != nil {
							log.Fatal(err)
						}
						break
					}

					tlv = datatypes.NewTLV(tag, []byte(game.FEN()))
					tlv.Sign(keyPair.PrivateKey)
					tlv.Encrypt(pbKey)
					_, err = c.Write(tlv.Encode())
					if err != nil {
						log.Fatal(err)
					}

					break
				}
			}

			otherID, _ := getWhitePlayerID(gameID)
			if currentID == otherID {
				otherID, _ = getBlackPlayerID(gameID)
			}
			pbKey, _ = getPlayerPublicKey(otherID)
			conn, err := getConnectionForPlayer(pbKey)
			if err != nil {
				log.Println(err)
				break
			}

			tag = 0x81
			if game.Outcome() != chess.NoOutcome {
				tag = 0x80
				tlv = datatypes.NewTLV(tag, []byte(game.FEN()))
				tlv.Sign(keyPair.PrivateKey)
				tlv.Encrypt(pbKey)
				_, err = conn.Write(tlv.Encode())
				if err != nil {
					log.Fatal(err)
				}
				break
			}

			tlv = datatypes.NewTLV(tag, []byte(game.FEN()))
			tlv.Sign(keyPair.PrivateKey)
			tlv.Encrypt(pbKey)
			_, err = conn.Write(tlv.Encode())
			if err != nil {
				log.Fatal(err)
			}
		case 0x22: // GetAvailableMoves
			log.Println("GetAvailableMoves")
			err := tlv.Decrypt(keyPair.PrivateKey)
			if err != nil {
				log.Println(err)
				break
			}
			verified := validateSignature(tlv)
			if !verified {
				break
			}

			playerID := getPlayerIDFromSignature(tlv.Value[:])
			gameID, err := findActiveGame(playerID)
			if err != nil {
				log.Println(err)
				break
			}
			if games[uuid.MustParse(gameID)] == nil {
				games[uuid.MustParse(gameID)] = loadGame(gameID)
			}

			var moves []string
			game := games[uuid.MustParse(gameID)]
			for _, move := range game.ValidMoves() {
				algebraic, err := parseAlgebraicNotation(move, game.Position().Board())
				if err != nil {
					log.Println(err)
					break
				}

				moves = append(moves, algebraic)
			}

			movesString := strings.Join(moves, ";")
			movesString = strconv.Itoa(len(moves)) + ";" + movesString
			tlv = datatypes.NewTLV(0x82, []byte(movesString))
			tlv.Sign(keyPair.PrivateKey)
			pbKey, err := getPlayerPublicKey(playerID)
			if err != nil {
				log.Println(err)
				break
			}
			tlv.Encrypt(pbKey)
			_, err = c.Write(tlv.Encode())
			if err != nil {
				log.Println(err)
			}
		}
	}
}
