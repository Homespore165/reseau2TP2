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

	c1.HostGame()
	c2.CLI()

	select {}
}
