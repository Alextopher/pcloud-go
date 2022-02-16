package main

import (
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

	for {
		// Wait for connection
		conn, err := listener.Accept()

		if err != nil {
			log.Println(err)
			continue
		}

		// Create TCPWrapper
		tcpWrapper := shared.NewTCPWrapper(conn, true)

		// Handle connection in new goroutine
		go handleConnection(tcpWrapper)
	}
}

func handleConnection(tcpWrapper *shared.TCPWrapper) {
	// Elliptic curve Diffie-Hellman
	tcpWrapper.ECDH()

	log.Println("Handshake complete")

	// Echo messages
	for {
		msg := <-tcpWrapper.Recv

		tcpWrapper.Send <- msg
	}
}
