package main

import (
	"fmt"
	"log"
	"net"

	"github.com/Alextopher/pcloud-go/shared"
)

func main() {
	// Create TCP listener
	listener, err := net.Listen("tcp", ":1337")

	if err != nil {
		log.Fatal(err)
	}

	// Load ed25519 key pair
	pub, priv, err := shared.GetKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Listen for connections
	for {
		// Wait for connection
		conn, err := listener.Accept()

		if err != nil {
			log.Println(err)
			continue
		}

		// Create TCPWrapper
		tcpWrapper := shared.NewTCPWrapper(conn, true, pub, priv)

		// Handle connection in new goroutine
		go handleConnection(tcpWrapper)
	}
}

func handleConnection(tcpWrapper *shared.TCPWrapper) {
	defer tcpWrapper.Close()

	// Elliptic curve Diffie-Hellman
	err := tcpWrapper.Handshake()
	if err != nil {
		fmt.Println(err)
		return
	}
	log.Println("Handshake complete")

	// Echo messages
	for {
		msg := <-tcpWrapper.Recv

		tcpWrapper.Send <- msg
	}
}
