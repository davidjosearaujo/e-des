/*
Copyright © 2023 David Araújo <david2araujo5@gmail.com>
*/
package cmd

import (
	"bytes"
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

	for i, j:=len(block)-1, 0; i >= 0; i, j = i-1, j+1 {
		if i >= len(block)/2 && j < len(block)/2{
			out[j+(len(block)/2)] = block[j]			
			temp[j] = sbox[index]
			if i > len(block)/2 {
				index += block[i-len(block)/2-1]
			}
		}else{
			out[j-(len(block)/2)] = temp[j-(len(block)/2)] ^ block[j]
		}
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

		// Cast message to byte array
		blocks := []byte(Message)

		// Iterate through all blocks
		for i:=0; i < len(blocks); i+=8 {
			var block []byte
			if i == 120 {
				block = blocks[i:]		
			}else{
				block = blocks[i:i+8]
			}
			fmt.Printf("%02x\n",block)

			// Each block goes through a Feistel network with each S-Box
			// but now in reverse order
			for j := len(SBboxes)-1; j >= 0; j-- {
				block = DecFeistelNetwork(block, SBboxes[j])
			}

			out = append(out, block...)
		}

		// Remove PKCS#7 padding from the message
		message, _ := PKCS7strip(out, 64)

		fmt.Printf("Message: %s\n", message)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
}
