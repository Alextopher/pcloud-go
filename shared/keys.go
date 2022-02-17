package shared

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

// Load ed25519 key pair from file or generate new key pair
func GetKeyPair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	pub, priv, err = LoadKeyPair()
	if err != nil {
		// Generate new key pair
		pub, priv, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, nil, err
		}

		// Save the keypair to files
		err = SaveKeyPair(pub, priv)
		if err != nil {
			return nil, nil, err
		}
	}

	return pub, priv, nil
}

// Load ed25519 key pair from file
// errors if file does not exist
func LoadKeyPair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	keyfile, err := os.Open("key")
	if err != nil {
		return nil, nil, err
	}
	defer keyfile.Close()

	// Read hex bytes from file
	var pubHex, privHex string
	fmt.Fscanf(keyfile, "%s %s", &pubHex, &privHex)
	if err != nil {
		return nil, nil, err
	}

	// Decode hex bytes
	pub, err = hex.DecodeString(pubHex)
	if err != nil {
		return nil, nil, err
	}

	priv, err = hex.DecodeString(privHex)
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

// Saves key pair to file
func SaveKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) (err error) {
	keyfile, err := os.OpenFile("key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	// Encode hex bytes to file
	fmt.Fprintf(keyfile, "%s %s", hex.EncodeToString(pub), hex.EncodeToString(priv))
	keyfile.Close()

	return nil
}
