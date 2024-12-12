package main

import (
	_ "github.com/mattn/go-sqlite3"
	"log"
	"reseau2TP2/client"
	"reseau2TP2/datatypes"
	_ "reseau2TP2/datatypes"
	"reseau2TP2/server"
	"time"
)

func main() {
	err := server.Init()
	if err != nil {
		log.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	c1, err := client.Init("./client/config1.json", 1)
	if err != nil {
		log.Fatal(err)
	}
	user := datatypes.NewUser("John", "Doe", true, 1500, c1.KeyPair.PublicKey)
	err = c1.Login(*user)
	if err != nil {
		log.Fatal(err)
	}

	c2, err := client.Init("./client/config2.json", 2)
	user2 := datatypes.NewUser("Jane", "Doe", true, 1500, c2.KeyPair.PublicKey)
	err = c2.Login(*user2)
	if err != nil {
		log.Fatal(err)
	}

	c3, err := client.Init("./client/config3.json", 3)
	user3 := datatypes.NewUser("Jack", "Doe", true, 1500, c3.KeyPair.PublicKey)
	err = c3.Login(*user3)
	if err != nil {
		log.Fatal(err)
	}

	//Demo 1
	//c1.CLI()

	//Demo 2
	// c2.HostGame()
	// games := c2.GetAvailableGames()
	// c3.JoinGame(games[0])
	// c2.PlayMove("e4")
	// time.Sleep(100 * time.Millisecond)
	// c3.PlayMove("e5")
	// time.Sleep(100 * time.Millisecond)
	// c2.PlayMove("Nf3")
	// time.Sleep(100 * time.Millisecond)
	// c3.PlayMove("Nc6")
	// time.Sleep(100 * time.Millisecond)
	// c2.PlayMove("Bb5")
	// time.Sleep(100 * time.Millisecond)
	// c3.PlayMove("a6")

	//Demo 3
	//c1.CLI()

	//Demo 4
	// c2.RejoinWhite()
	// c3.RejoinBlack()
	// time.Sleep(100 * time.Millisecond)
	// c2.PlayMove("Ba4")
	// time.Sleep(100 * time.Millisecond)
	// c3.PlayMove("b5")
	// time.Sleep(100 * time.Millisecond)
	// c2.PlayMove("Bb3")
	// time.Sleep(100 * time.Millisecond)
	// c3.PlayMove("Nf6")
	// time.Sleep(100 * time.Millisecond)
	// c2.PlayMove("O-O")

	select {}
}
