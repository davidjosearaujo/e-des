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

// Feistel Network
// will only process 8 byte blocks with a given S-Box
func DecFeistelNetwork(block []byte, sbox []byte) ([]byte){
	var out = make([]byte, len(block))
	var temp = make([]byte, len(block)/2)
	index := block[len(block)/2-1]

	for i:=0; i < len(block)/2; i++ {
		// Li -> Ri-1
		out[len(block)/2+i] = block[i]
		// Li -> fi
		temp[i] = sbox[index]
		if i <= 2{
			index += block[len(block)/2-2-i]
		}
	}

	for i:=0; i < len(block)/2; i++{
		// Ri XOR f(Ki)
		out[i] = temp[i] ^ block[i+len(block)/2]
	}

	return out
}

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt the content of the message",
	PreRun: func(cmd *cobra.Command, args []string) {
		SboxGen()
	},
	Run: func(cmd *cobra.Command, args []string) {
		var out []byte
		fmt.Printf("Ciphered block\t\tOriginal block\n")

		// Cast message to byte array
		blocks, _ := hex.DecodeString(Message)

		// Iterate through all blocks
		for i:=0; i < len(blocks); i+=8 {
			block := blocks[i:i+8]
			fmt.Printf("%x\t",block)

			// Each block goes through a Feistel network with each S-Box
			// but now in reverse order
			for j := len(SBboxes)-1; j >= 0; j-- {
				block = DecFeistelNetwork(block, SBboxes[j])
			}

			fmt.Printf("%x\n",block)
			out = append(out, block...)
		}

		// Remove PKCS#7 padding from the message
		message, _ := PKCS7strip(out, 8)

		fmt.Printf("\nMessage: %s\n\n", message)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
}
