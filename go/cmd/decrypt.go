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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func PKCS7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

// Decryption Feistel Network
func DecFeistelNetwork(block []byte, sbox []byte) []byte {
	var out = make([]byte, len(block))
	var temp = make([]byte, len(block)/2)
	index := block[len(block)/2-1]

	for i := 0; i < len(block)/2; i++ {
		// Li -> Ri-1
		out[len(block)/2+i] = block[i]
		// Li -> fi
		temp[i] = sbox[index]
		if i <= 2 {
			index += block[len(block)/2-2-i]
		}
	}

	for i := 0; i < len(block)/2; i++ {
		// Ri XOR f(Ki)
		out[i] = temp[i] ^ block[i+len(block)/2]
	}

	return out
}

// Decrypt
func Decrypt(blocks []byte) []byte {
	var out []byte

	// Iterate through all blocks
	for i := 0; i < len(blocks); i += 8 {
		block := blocks[i : i+8]

		// Each block goes through a Feistel network with each S-Box
		// but now in reverse order
		for j := len(SBboxes) - 1; j >= 0; j-- {
			block = DecFeistelNetwork(block, SBboxes[j])
		}

		out = append(out, block...)
	}

	// Remove PKCS#7 padding from the message
	message, _ := PKCS7strip(out, 8)

	return message
}

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt the content of the message",
	PreRun: func(cmd *cobra.Command, args []string) {
		SboxGen([]byte(Password))
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Cast message to byte array
		blocks, _ := hex.DecodeString(Message)
		fmt.Printf("%s\n", Decrypt(blocks))
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
}
