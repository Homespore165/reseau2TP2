package main

import (
	"log"
	"reseau2TP2/client"
	"reseau2TP2/datatypes"
	_ "reseau2TP2/datatypes"
	"reseau2TP2/server"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	err := server.Init()
	if err != nil {
		log.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	c1, err := client.Init("./client/config1.json")
	if err != nil {
		log.Fatal(err)
	}
	user := datatypes.NewUser("John", "Doe", true, 1500, c1.KeyPair.PublicKey)
	err = c1.Login(*user)
	if err != nil {
		log.Fatal(err)
	}
	c1.HostGame()

	c2, err := client.Init("./client/config2.json")
	if err != nil {
		log.Fatal(err)
	}
	user2 := datatypes.NewUser("Jane", "Doe", true, 1500, c2.KeyPair.PublicKey)
	err = c2.Login(*user2)
	if err != nil {
		log.Fatal(err)
	}
	games := c2.GetAvailableGames()
	if len(games) != 0 {
		c2.JoinGame(games[0])
	} else {
		log.Println("Already joined game")
	}
	go c1.PlayMove("g4")
	go c2.PlayMove("e5")
	// c1.PlayMove("e4")
	// c2.PlayMove("e5")
	// c1.PlayMove("Nf3")
	// c2.PlayMove("Nc6")
	// c1.PlayMove("Bb5")
	// c2.PlayMove("a6")
	// c1.PlayMove("Ba4")

	select {}
}
