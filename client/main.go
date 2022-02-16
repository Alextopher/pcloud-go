package main

import (
	"fmt"
	"net"
	"os"

	"github.com/Alextopher/pcloud-go/shared"
)

func main() {
	// Connect to TCP port 1337 on localhost
	conn, err := net.Dial("tcp", "localhost:1337")
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	// Create TCP wrapper
	tcpWrapper := shared.NewTCPWrapper(conn, false)

	// Elliptic curve Diffie-Hellman
	tcpWrapper.ECDH()
	fmt.Println("Handshake complete")

	// Read from stdin and send to TCP connection then expect an echo
	for {
		// Read message
		message := make([]byte, 1024)
		n, err := os.Stdin.Read(message)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Send message
		tcpWrapper.Send <- message[:n]

		// Read echo
		echo := <-tcpWrapper.Recv

		// Print echo
		fmt.Println(string(echo))
	}
}
