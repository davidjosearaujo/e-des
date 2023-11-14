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

func Encrypt(blocks []byte) []byte{
	var out []byte

	// Add PKCS#7 padding to the message
	blocks_s, _ := PKCS7pad(blocks, 8)

	// Iterate through all blocks
	for i:=0; i < len(blocks_s); i += 8{
		block := blocks_s[i:i+8]

		// Each block goes through a Feistel network with each S-Box
		for _, sbox := range SBboxes {
			block = EncFeistelNetwork(block, sbox)
		}

		out = append(out, block...)
	}

	return out
}

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt the content of the message",
	PreRun: func(cmd *cobra.Command, args []string) {
		SboxGen([]byte(Password))
	},
	Run: func(cmd *cobra.Command, args []string) {	
		Encrypt([]byte(Message))
		fmt.Printf("%x\n", Encrypt([]byte(Message)))
	},
}



func init() {
	rootCmd.AddCommand(encryptCmd)
}
