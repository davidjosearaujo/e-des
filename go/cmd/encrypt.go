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
// Will only process 8 byte blocks with a given S-Box
func EncFeistelNetwork(block []byte, sbox []byte) ([]byte){
	var out = make([]byte, len(block))
	var temp = make([]byte, len(block)/2)
	index := block[len(block)-1]

	for i, j:=len(block)-1, 0; i >= 0; i, j = i-1, j+1 {
		if i >= len(block)/2 && j < len(block)/2{
			out[j] = block[j+(len(block)/2)]
			temp[j] = sbox[index]	
			index += block[i-1]
		}else{
			out[j] = temp[j-(len(block)/2)] ^ block[j-(len(block)/2)]
		}
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
		blocks, _ := PKCS7pad([]byte(Message), 64)

		// Iterate through all blocks
		for i:=0; i < len(blocks); i += 8{
			block := blocks[i:i+8]

			// Each block goes through a Feistel network with each S-Box
			for j:=0; j < len(SBboxes); j++ {
				block = EncFeistelNetwork(block, SBboxes[j])
			}
			out = append(out, block...)
		}

		fmt.Printf("%02x\n", out)
		fmt.Printf("Initial length: %d\tFinal length: %d\n", len(Message), len(out))
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
}
