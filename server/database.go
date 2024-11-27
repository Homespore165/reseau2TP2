package server

import (
	"database/sql"
	"fmt"
	"reseau2TP2/datatypes"
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
	signature TEXT
	);
	CREATE TABLE IF NOT EXISTS games (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	whiteID INTEGER,
	blackID INTEGER,
	fen TEXT,
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
			u := req.Parameters[0].(*datatypes.User)
			_, err := db.db.Exec(`INSERT INTO users 
				(
				firstName,
				lastName,
				active,
				elo,
				signature
				)
				VALUES (?, ?, ?, ?, ?);`,
				u.FirstName, u.LastName, u.IsActive, u.Elo, u.PublicKey)
			response = DBResponse{Result: nil, Err: err}
		case "getLastMoveTime":

		case "getPublicKeys":
			var publicKeys []string
			err := db.db.QueryRow(`SELECT GROUP_CONCAT(signature, ';') FROM users;`).Scan(&publicKeys)
			if err != nil {
				response = DBResponse{Result: nil, Err: err}
			}
			response = DBResponse{Result: publicKeys, Err: nil}
		default:
			response = DBResponse{Err: fmt.Errorf("unknown query type")}
		}
		req.Response <- response
	}
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
