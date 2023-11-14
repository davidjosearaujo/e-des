// Copyright 2023 davidjosearaujo
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	Message  string
	Key      [32]byte
	SBboxes  [][]byte
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
func RubikShuffle(matrix []byte, ciphertext []byte) ([]byte, error) {
	sideSize := int(math.Sqrt(float64(len(matrix))))

	// Size of matrix
	if sideSize*sideSize != len(matrix) {
		return []byte{}, errors.New("it is now a square matrix")
	}

	// Size of ciphertext
	if sideSize*2 != len(ciphertext) {
		return []byte{}, errors.New("shuffling key is not the correct size")
	}

	// Convert to shuffle key list with modulus of 64
	shuffleKey := []int{}
	for i := 0; i < len(ciphertext); i += 1 {
		shuffleKey = append(shuffleKey, int(ciphertext[i])%64)
	}

	// Rotate columns
	for i := 0; i < sideSize; i += 1 {
		temp := []byte{}
		for j := 0; j < len(matrix); j += sideSize {
			temp = append(temp, matrix[i+j])
		}
		lastK := temp[(sideSize - shuffleKey[i]):sideSize]
		firstK := temp[:(sideSize - shuffleKey[i])]
		temp = append(lastK, firstK...)
		for j, k := 0, 0; j < len(matrix); j, k = j+sideSize, k+1 {
			matrix[i+j] = temp[k]
		}
	}

	shuffleKey = shuffleKey[sideSize:]

	var out []byte
	// Rotate rows
	for i, k := 0, 0; i < len(matrix); i, k = i+sideSize, k+1 {
		temp := matrix[i : i+sideSize]
		lastK := temp[(sideSize - shuffleKey[k]):sideSize]
		firstSMK := temp[:(sideSize - shuffleKey[k])]
		out = append(out, lastK...)
		out = append(out, firstSMK...)
	}

	return out, nil
}

func SboxGen(password []byte) {
	// Key generation
	Key = sha256.Sum256(password)

	aead, _ := chacha20poly1305.NewX(Key[:])

	// Generate pre-shuffle clean box
	cleanbox := []byte{}
	for i := 0; i < 256; i++ {
		for j := 0; j < 16; j++ {
			cleanbox = append(cleanbox, byte(i))
		}
	}

	// Generate list of exchange indexes
	ciphertext := aead.Seal(nil, make([]byte, chacha20poly1305.NonceSizeX), make([]byte, 128), nil)
	ciphertext = ciphertext[:128]

	shuffledBoxes, err := RubikShuffle(cleanbox, ciphertext)
	if err != nil {
		panic(fmt.Errorf("error during rubik shuffling of clean S-boxes: %s", err))
	}

	for i := 0; i < 16; i++ {
		SBboxes = append(SBboxes, []byte(shuffledBoxes[i*256 : i*256+256]))
	}
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
	rootCmd.PersistentFlags().StringVarP(&Password, "password", "p", "", "Encryption/decryption password")
	rootCmd.PersistentFlags().StringVarP(&Message, "message", "m", "", "Message to encrypt/decrypt")
}
