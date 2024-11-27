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

	client, err := client.Init()
	if err != nil {
		log.Fatal(err)
	}
	user := datatypes.NewUser("John", "Doe", true, 1500, client.KeyPair.PublicKey)
	client.Login(*user)

	for {
	}
}
