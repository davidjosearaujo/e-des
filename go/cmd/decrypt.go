/*
Copyright © 2023 David Araújo <david2araujo5@gmail.com>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt the content of the message",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Implement decryption process
		// 			- F networks
	},
}

func init() {
}
