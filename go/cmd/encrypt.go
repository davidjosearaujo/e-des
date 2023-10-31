/*
Copyright © 2023 David Araújo <david2araujo5@gmail.com>
*/
package cmd

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"
)

func PKCS7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 1 || blockSize >= 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data) % blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

// Feistel Network
func EncFeistelNetwork(block []byte, sbox []byte) ([]byte){
	var out = make([]byte, len(block))
	var temp = make([]byte, len(block)/2)
	
	index := block[len(block)-1]
	for i,j:=len(block)-1, 0; i >= len(block)/2 ; i, j = i-1, j+1 {
		// Ri-1 -> Li
		out[i-len(block)/2] = block[i]
		// Ri-1 -> fi
		temp[j] = sbox[index]
		index += block[i-1]
	}

	for i:=0; i < len(block)/2; i++{
		// Li-1 XOR f(Ki)
		out[i+len(block)/2] = temp[i] ^ block[i]
	}

	return out
}

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt the content of the message",
	PreRun: func(cmd *cobra.Command, args []string) {
		SboxGen()
	},
	Run: func(cmd *cobra.Command, args []string) {	
		var out []byte

		// Add PKCS#7 padding to the message
		blocks, _ := PKCS7pad([]byte(Message), 8)

		// Iterate through all blocks
		for i:=0; i < len(blocks); i += 8{
			block := blocks[i:i+8]

			// Each block goes through a Feistel network with each S-Box
			for _, box := range SBboxes {
				block = EncFeistelNetwork(block, box)
			}
			
			out = append(out, block...)
		}
		fmt.Printf("%x\n", out)
	},
}



func init() {
	rootCmd.AddCommand(encryptCmd)
}
