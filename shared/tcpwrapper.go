package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"net"
)

// TCPWrapper is a wrapper for a TCP connection which allows us to send
// and receive messages encytped using channels
type TCPWrapper struct {
	conn net.Conn
	Send chan []byte
	Recv chan []byte

	// Indicates if this is the server
	isServer bool

	// Shared AES streams
	localStream, remoteStream cipher.Stream

	// Flag to indicate if the handshake is complete
	handshakeComplete bool
}

// NewTCPWrapper creates a new TCPWrapper and starts the read and write goroutines
func NewTCPWrapper(conn net.Conn, isServer bool) *TCPWrapper {
	// Create read and write channels
	send := make(chan []byte)
	recv := make(chan []byte)

	// Create TCP wrapper
	tcpWrapper := &TCPWrapper{
		conn:     conn,
		Send:     send,
		Recv:     recv,
		isServer: isServer,
	}

	// Start goroutines
	go tcpWrapper.send()
	go tcpWrapper.recv()

	return tcpWrapper
}

// Close closes the connection
func (tcpWrapper *TCPWrapper) Close() {
	tcpWrapper.conn.Close()

	close(tcpWrapper.Send)
	close(tcpWrapper.Recv)
}

func (tcpWrapper *TCPWrapper) ECDH() error {
	// Create ecdsa keypair
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public := private.PublicKey

	// Extract the x and y coordinates from the public key
	if err != nil {
		return err
	}

	// Send public key
	tcpWrapper.Send <- public.X.Bytes()
	tcpWrapper.Send <- public.Y.Bytes()

	// Receive public key
	x, ok := <-tcpWrapper.Recv
	if !ok {
		return fmt.Errorf("failed to receive public key")
	}
	X := big.NewInt(0).SetBytes(x)

	y, ok := <-tcpWrapper.Recv
	if !ok {
		return fmt.Errorf("failed to receive public key")
	}
	Y := big.NewInt(0).SetBytes(y)

	// Remote public key times local private key
	if !public.Curve.IsOnCurve(X, Y) {
		return fmt.Errorf("invalid public key from remote")
	}

	shared, _ := public.Curve.ScalarMult(X, Y, private.D.Bytes())

	// SHA256 hash of shared key as a slice
	hash := sha256.New().Sum(shared.Bytes())

	// Split hash into two halves
	hash1 := hash[:len(hash)/2]
	hash2 := hash[len(hash)/2:]

	// Initialize AES Ciphers
	aes1, err := aes.NewCipher(hash1)
	if err != nil {
		return err
	}

	aes2, err := aes.NewCipher(hash2)
	if err != nil {
		return err
	}

	bs := aes1.BlockSize()

	// IV is the first n bytes of the hash
	iv := hash1[:bs]

	// Streams are client and server specific
	if tcpWrapper.isServer {
		tcpWrapper.localStream = cipher.NewCTR(aes1, iv)
		tcpWrapper.remoteStream = cipher.NewCTR(aes2, iv)
	} else {
		tcpWrapper.remoteStream = cipher.NewCTR(aes1, iv)
		tcpWrapper.localStream = cipher.NewCTR(aes2, iv)
	}

	tcpWrapper.handshakeComplete = true

	return nil
}

func (tcpWrapper *TCPWrapper) recv() {
	// Read from connection
	for {
		// First 4 bytes are the length of the message
		length := make([]byte, 4)
		n, err := tcpWrapper.conn.Read(length)

		if n != 4 || err != nil {
			log.Println("Error reading length of message", err)
			return
		}

		// Convert length to int
		lengthInt := int(length[0]) | int(length[1])<<8 | int(length[2])<<16 | int(length[3])<<24

		// Read message
		message := make([]byte, lengthInt)
		n, err = tcpWrapper.conn.Read(message)

		// Decrypt message with remote stream
		if tcpWrapper.handshakeComplete {
			tcpWrapper.remoteStream.XORKeyStream(message, message)
		}

		if n != lengthInt || err != nil {
			log.Println("Error reading message", err)
			return
		}

		// Send message to recv channel
		tcpWrapper.Recv <- message
	}
}

func (tcpWrapper *TCPWrapper) send() {
	// Write to connection
	for message := range tcpWrapper.Send {
		// First 4 bytes are the length of the message
		length := make([]byte, 4)
		length[0] = byte(len(message))
		length[1] = byte(len(message) >> 8)
		length[2] = byte(len(message) >> 16)
		length[3] = byte(len(message) >> 24)

		// Write length and message
		_, err := tcpWrapper.conn.Write(length)

		if err != nil {
			log.Println("Error writing length of message", err)
			return
		}

		// Encrypt message with local stream
		if tcpWrapper.handshakeComplete {
			tcpWrapper.localStream.XORKeyStream(message, message)
		}

		_, err = tcpWrapper.conn.Write(message)

		if err != nil {
			log.Println("Error writing message", err)
			return
		}
	}
}
