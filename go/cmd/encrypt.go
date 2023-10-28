/*
Copyright © 2023 David Araújo <david2araujo5@gmail.com>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

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
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
}
