/*
Copyright © 2023 David Araújo <david2araujo5@gmail.com>
*/
package cmd

import (
	"crypto/sha256"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/spf13/cobra"
)

// Global variables
var (
	Password string
	Key      [32]byte
)

func keygen() {
	Key = sha256.Sum256([]byte(Password))
	sboxgen()
}

func sboxgen() {
	aead, _ := chacha20poly1305.NewX(Key[:])

	// Generate pre-mixing clean box
	cleanbox := []byte{}
	for i := 0; i < 256; i++ {
		for j := 0; j < 16; j++ {
			cleanbox = append(cleanbox, byte(i))
		}
	}

	// Generate list of exchange indexes
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	ciphertext := aead.Seal(nil, nonce, make([]byte, 128*2), nil)
	ciphertext = ciphertext[:256]

	for i := 0; i < len(ciphertext); i += 1 {
		num := (uint16(ciphertext[i]))
		fmt.Printf("%d ", num%64)
	}

	// Rubik Cube manipulation
	//	- Rotate columns
	//	- Rotate rows

}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "e-des",
	Short: "E-DES encryption tool based in a 256 bit key",
	Long: `E-DEs uses a SHA 256 bit hash of a password and ChaCha20
to generate substitution boxes for encrypting data`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&Password, "password", "p", "", "Encryption/ decryption password")
}
