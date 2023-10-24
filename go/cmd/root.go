/*
Copyright © 2023 David Araújo <david2araujo5@gmail.com>
*/
package cmd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/spf13/cobra"
)

// Global variables
var (
	Password string
	Key      [32]byte
)

/* Rubik's Shuffle
 * This shuffle technique is based on the way a Rubik cube is shuffled.
 * Given a byte array with a perfect square length, and a shuffle key
 * of the same length as the root, the algorithm rotates each column
 * the same number of places has indicated in the shuffle key at
 * at the index indicated by the number of the column. This, obviously,
 * will used half of the shuffle key.
 * The row rotation follows exactly the same logic, but with
 * the rows and uses the second half of the shuffle key.
 */
func RubikShuffle(matrix []byte, shuffleKey []int) ([]byte, error) {
	// Size of matrix
	sideSize := int(math.Sqrt(float64(len(matrix))))
	if sideSize*sideSize != len(matrix) {
		return []byte{}, errors.New("it is now a square matrix")
	}

	fmt.Printf("%02x\n", matrix)
	fmt.Printf("Original length: %d\n\n", len(matrix))

	// Rotate columns
	for i := 0; i < sideSize; i += 1 {
		temp := []byte{}
		for j := 0; j < len(matrix); j += sideSize {
			temp = append(temp, matrix[i+j])
		}
		lastK := temp[(sideSize - shuffleKey[i]):sideSize]
		firstSMK := temp[:(sideSize - shuffleKey[i])]
		temp = append(lastK, firstSMK...)
		for j, k := 0, 0; j < len(matrix); j, k = j+sideSize, k+1 {
			matrix[i+j] = temp[k]
		}
	}

	shuffleKey = shuffleKey[sideSize:]

	// Rotate rows
	for i, k := 0, 0; i < len(matrix); i, k = i+sideSize, k+1 {
		temp := matrix[i : i+sideSize]
		lastK := temp[(sideSize - shuffleKey[k]):sideSize]
		firstSMK := temp[:(sideSize - shuffleKey[k])]
		temp = append(lastK, firstSMK...)
		temp = append(matrix[:i], temp...)
		matrix = append(temp, matrix[i+sideSize:]...)
	}

	fmt.Printf("%02x\n", matrix)
	fmt.Printf("Final length: %d\n", len(matrix))
	os.Exit(0)

	return matrix, nil
}

func SboxGen() {
	// Key generation
	Key = sha256.Sum256([]byte(Password))

	aead, _ := chacha20poly1305.NewX(Key[:])

	// Generate pre-shuffle clean box
	cleanbox := []byte{}
	for i := 0; i < 256; i++ {
		for j := 0; j < 16; j++ {
			cleanbox = append(cleanbox, byte(i))
		}
	}

	// Generate list of exchange indexes
	ciphertext := aead.Seal(nil, make([]byte, chacha20poly1305.NonceSizeX), make([]byte, 128*2), nil)
	ciphertext = ciphertext[:256]

	// Convert to shuffle key list
	shuffleKey := []int{}
	for i := 0; i < len(ciphertext); i += 1 {
		shuffleKey = append(shuffleKey, int(ciphertext[i])%64)
	}

	RubikShuffle(cleanbox, shuffleKey)
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
