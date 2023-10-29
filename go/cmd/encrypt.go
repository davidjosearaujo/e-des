/*
Copyright © 2023 David Araújo <david2araujo5@gmail.com>
*/
package cmd

import (

	"github.com/spf13/cobra"
)

// Feistel Network
// Will only process 8 byte blocks with a given S-Box
func FeistelNetwork(block []byte, sbox [256]byte) ([]byte){
	out := []byte{}
	temp := []byte{}
	index := block[7]

	for i, j:=7, 0; i >= 0; i, j = i-1, j+1 {
		if i >= 4 && j < 4{
			out[j] = block[j+4]
			temp[j] = sbox[index]	
			index += block[i-1]
		}else{
			out[j] = temp[j-4] ^ block[j-4]
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
		// TODO: Implement encryption process
		// 			- F networks

		// TESTING
		message := "Sit laborum reprehenderit aute voluptate quis officia duis voluptate dolor id elit et."
		var out []byte

		blocks := []byte(message)
		for i:=0; i < len(blocks); i += 8{
			block := blocks[i:i+8]
			for i:=0; i < len(SBboxes); i++ {
				block = FeistelNetwork(block, SBboxes[i])
			}
			out = append(out, block...)
		}
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
}
