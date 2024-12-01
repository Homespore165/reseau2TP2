package server

import (
	"database/sql"
	"fmt"
	"log"
	"reseau2TP2/datatypes"
	"time"
)

var db *chessDB

type chessDB struct {
	db *sql.DB
}

var dbRequestChannel = make(chan DBRequest)

func initDB() (*chessDB, error) {
	creationQuery := `CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	firstName TEXT,
	lastName TEXT,
	active INTEGER,
	elo INTEGER,
	publicKey TEXT
	);
	CREATE TABLE IF NOT EXISTS games (
	id TEXT PRIMARY KEY,
	whiteID INTEGER,
	blackID INTEGER,
	pgn TEXT,
	lastMoveTime TEXT,
	FOREIGN KEY(whiteID) REFERENCES users(id),
	FOREIGN KEY(blackID) REFERENCES users(id)
	);`

	db, err := sql.Open("sqlite3", "./chess.db")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(creationQuery)
	if err != nil {
		return nil, err
	}

	go dbManager()

	return &chessDB{db}, nil
}

func dbManager() {
	for req := range dbRequestChannel {
		var response DBResponse
		switch req.QueryType {
		case "createNewUser":
			err := _createNewUser(req.Parameters[0].(*datatypes.User))
			response = DBResponse{Result: nil, Err: err}
		case "getLastMoveTime":
			lastMoveTime, err := _getLastMoveTime(req.Parameters[0].(string))
			response = DBResponse{Result: lastMoveTime, Err: err}
		case "getPublicKeys":
			publicKeys, err := _getPublicKeys()
			response = DBResponse{Result: publicKeys, Err: err}
		case "getPlayerIDFromPublicKey":
			playerID, err := _getPlayerIDFromPublicKey(req.Parameters[0].(string))
			response = DBResponse{Result: playerID, Err: err}
		case "createNewGame":
			gameID := req.Parameters[0].(string)
			whiteID := req.Parameters[1].(int)
			blackID := req.Parameters[2].(int)
			err := _createNewGame(gameID, whiteID, blackID)
			response = DBResponse{Result: nil, Err: err}
		case "gameExists":
			exists := _gameExists(req.Parameters[0].(string))
			response = DBResponse{Result: exists, Err: nil}
		case "getUnstartedGames":
			games, err := _getUnstartedGames()
			response = DBResponse{Result: games, Err: err}
		case "publicKeyExists":
			exists := _publicKeyExists(req.Parameters[0].(string))
			response = DBResponse{Result: exists, Err: nil}
		case "joinGame":
			err := _joinGame(req.Parameters[0].(string), req.Parameters[1].(int))
			response = DBResponse{Result: nil, Err: err}
		case "getGames":
			games, err := _getGames()
			response = DBResponse{Result: games, Err: err}
		case "getGamesByPlayerID":
			games, err := _getGamesByPlayerID(req.Parameters[0].(int))
			response = DBResponse{Result: games, Err: err}
		case "getPGN":
			pgn, err := _getPGN(req.Parameters[0].(string))
			response = DBResponse{Result: pgn, Err: err}
		case "findActiveGame":
			gameID, err := _findActiveGame(req.Parameters[0].(int))
			response = DBResponse{Result: gameID, Err: err}
		case "saveGame":
			err := _saveGame(req.Parameters[0].(string), req.Parameters[1].(string))
			response = DBResponse{Result: nil, Err: err}
		case "getPlayerPublicKey":
			publicKey, err := _getPlayerPublicKey(req.Parameters[0].(int))
			response = DBResponse{Result: publicKey, Err: err}
		case "getWhitePlayerID":
			whiteID, err := _getWhitePlayerID(req.Parameters[0].(string))
			response = DBResponse{Result: whiteID, Err: err}
		case "getBlackPlayerID":
			blackID, err := _getBlackPlayerID(req.Parameters[0].(string))
			response = DBResponse{Result: blackID, Err: err}
		default:
			response = DBResponse{Err: fmt.Errorf("unknown query type")}
		}
		req.Response <- response
	}
}

func _createNewUser(u *datatypes.User) error {
	_, err := db.db.Exec(`INSERT INTO users
		(
		firstName,
		lastName,
		active,
		elo,
		publicKey
		)
		VALUES (?, ?, ?, ?, ?);`,
		u.FirstName, u.LastName, u.IsActive, u.Elo, u.PublicKey)
	return err
}

func createNewUser(u *datatypes.User) error {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "createNewUser",
		Parameters: []interface{}{u},
		Response:   responseChannel,
	}
	response := <-responseChannel
	if response.Err != nil {
		return response.Err
	}
	return nil
}

func _getLastMoveTime(gameID string) (string, error) {
	var lastMoveTime string
	err := db.db.QueryRow(`SELECT lastMoveTime FROM games WHERE id = ?;`, gameID).Scan(&lastMoveTime)
	if err != nil {
		return "", err
	}
	return lastMoveTime, nil
}

func getLastMoveTime(gameID string) (string, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getLastMoveTime",
		Parameters: []interface{}{gameID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	if response.Err != nil {
		return response.Result.(string), response.Err
	}
	return response.Result.(string), nil
}

func _getPublicKeys() ([]string, error) {
	rows, err := db.db.Query(`SELECT publicKey FROM users;`)
	if err != nil {
		return nil, err
	}
	var publicKeys []string
	for rows.Next() {
		var publicKey string
		err = rows.Scan(&publicKey)
		if err != nil {
			return nil, err
		}
		publicKeys = append(publicKeys, publicKey)
	}
	return publicKeys, nil
}

func getPublicKeys() ([]string, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getPublicKeys",
		Parameters: []interface{}{},
		Response:   responseChannel,
	}
	response := <-responseChannel
	if response.Err != nil {
		return response.Result.([]string), response.Err
	}
	return response.Result.([]string), nil
}

func _getPlayerIDFromPublicKey(publicKey string) (int, error) {
	var playerID int
	err := db.db.QueryRow(`SELECT id FROM users WHERE publicKey = ?;`, publicKey).Scan(&playerID)
	if err != nil {
		return -1, err
	}
	return playerID, nil
}

func getPlayerIDFromPublicKey(publicKey string) int {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getPlayerIDFromPublicKey",
		Parameters: []interface{}{publicKey},
		Response:   responseChannel,
	}
	response := <-responseChannel
	if response.Err != nil {
		return response.Result.(int)
	}
	return response.Result.(int)
}

func _createNewGame(gameID string, whiteID int, blackID int) error {
	_, err := db.db.Exec(`INSERT INTO games
		(
		id,
		whiteID,
		blackID,
		pgn,
		lastMoveTime
		)
		VALUES (?, ?, ?, ?, ?);`,
		gameID, whiteID, blackID, nil, time.Now().Format("2006-01-02 15:04:05"))
	return err
}

func createNewGame(gameID string, whiteID int, blackID int) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "createNewGame",
		Parameters: []interface{}{gameID, whiteID, blackID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	if response.Err != nil {
		return
	}
	return
}

func _gameExists(gameID string) bool {
	var exists bool
	err := db.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM games WHERE id = ?);`, gameID).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func gameExists(gameID string) bool {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "gameExists",
		Parameters: []interface{}{gameID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.(bool)
}

func _joinGame(gameID string, playerID int) error {
	_, err := db.db.Exec(`UPDATE games
		SET blackID = ?
		WHERE id = ?;`,
		playerID, gameID)
	return err
}

func joinGame(gameID string, playerID int) error {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "joinGame",
		Parameters: []interface{}{gameID, playerID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Err
}

func _getUnstartedGames() ([]string, error) {
	rows, err := db.db.Query(`SELECT id FROM games WHERE blackID = -1;`)
	if err != nil {
		return nil, err
	}
	var games []string
	for rows.Next() {
		var gameID string
		err = rows.Scan(&gameID)
		if err != nil {
			log.Fatal(err)
		}
		games = append(games, gameID)
	}
	return games, nil
}

func getUnstartedGames() []string {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getUnstartedGames",
		Parameters: []interface{}{},
		Response:   responseChannel,
	}
	response := <-responseChannel
	if response.Err != nil {
		return response.Result.([]string)
	}
	return response.Result.([]string)
}

func _publicKeyExists(publicKey string) bool {
	var exists bool
	err := db.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE publicKey = ?);`, publicKey).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func publicKeyExists(publicKey string) bool {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "publicKeyExists",
		Parameters: []interface{}{publicKey},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.(bool)
}

func _getGames() ([]string, error) {
	rows, err := db.db.Query(`SELECT id FROM games;`)
	if err != nil {
		return nil, err
	}
	var games []string
	for rows.Next() {
		var gameID string
		err = rows.Scan(&gameID)
		if err != nil {
			log.Fatal(err)
		}
		games = append(games, gameID)
	}
	return games, nil
}

func getGames() []string {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getGames",
		Parameters: []interface{}{},
		Response:   responseChannel,
	}
	response := <-responseChannel
	if response.Err != nil {
		return response.Result.([]string)
	}
	return response.Result.([]string)
}

func _getGamesByPlayerID(playerID int) ([]string, error) {
	rows, err := db.db.Query(`SELECT id FROM games WHERE whiteID = ? OR blackID = ?;`, playerID, playerID)
	if err != nil {
		return nil, err
	}
	var games []string
	for rows.Next() {
		var gameID string
		err = rows.Scan(&gameID)
		if err != nil {
			log.Fatal(err)
		}
		games = append(games, gameID)
	}
	return games, nil
}

func getGamesByPlayerID(playerID int) ([]string, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getGamesByPlayerID",
		Parameters: []interface{}{playerID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.([]string), response.Err
}

func _getPGN(gameID string) (string, error) {
	var pgn string
	err := db.db.QueryRow(`SELECT pgn FROM games WHERE id = ?;`, gameID).Scan(&pgn)
	if err != nil {
		return "", err
	}
	return pgn, nil
}

func getPGN(gameID string) (string, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getPGN",
		Parameters: []interface{}{gameID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.(string), response.Err
}

func _findActiveGame(playerID int) (string, error) {
	rows, err := db.db.Query(`SELECT id FROM games WHERE whiteID = ? OR blackID = ? ORDER BY lastMoveTime DESC LIMIT 1;`, playerID, playerID)
	if err != nil {
		return "", err
	}
	var gameID string
	for rows.Next() {
		err = rows.Scan(&gameID)
		if err != nil {
			return "", err
		}
	}
	return gameID, nil
}

func findActiveGame(playerID int) (string, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "findActiveGame",
		Parameters: []interface{}{playerID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.(string), response.Err
}

func _saveGame(gameID string, pgn string) error {
	_, err := db.db.Exec(`UPDATE games
		SET pgn = ?,
		lastMoveTime = ?
		WHERE id = ?;`,
		pgn, time.Now().Format("2006-01-02 15:04:05"), gameID)
	return err
}

func saveGame(gameID string, pgn string) error {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "saveGame",
		Parameters: []interface{}{gameID, pgn},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Err
}

func _getPlayerPublicKey(playerID int) (string, error) {
	var publicKey string
	err := db.db.QueryRow(`SELECT publicKey FROM users WHERE id = ?;`, playerID).Scan(&publicKey)
	if err != nil {
		return "", err
	}
	return publicKey, nil
}

func getPlayerPublicKey(playerID int) (string, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getPlayerPublicKey",
		Parameters: []interface{}{playerID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.(string), response.Err
}

func _getWhitePlayerID(gameID string) (int, error) {
	var whiteID int
	err := db.db.QueryRow(`SELECT whiteID FROM games WHERE id = ?;`, gameID).Scan(&whiteID)
	if err != nil {
		return -1, err
	}
	return whiteID, nil
}

func getWhitePlayerID(gameID string) (int, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getWhitePlayerID",
		Parameters: []interface{}{gameID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.(int), response.Err
}

func _getBlackPlayerID(gameID string) (int, error) {
	var blackID int
	err := db.db.QueryRow(`SELECT blackID FROM games WHERE id = ?;`, gameID).Scan(&blackID)
	if err != nil {
		return -1, err
	}
	return blackID, nil
}

func getBlackPlayerID(gameID string) (int, error) {
	responseChannel := make(chan DBResponse)
	dbRequestChannel <- DBRequest{
		QueryType:  "getBlackPlayerID",
		Parameters: []interface{}{gameID},
		Response:   responseChannel,
	}
	response := <-responseChannel
	return response.Result.(int), response.Err
}
