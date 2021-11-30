/*
Copyright © 2021 strixeye keser@strixeye.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// pcapCmd represents the pcap command.
var pcapCmd = &cobra.Command{
	Use:   "pcap",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		viper.Set("CFG.IS_LIVE", false)
	},
}

func init() {
	rootCmd.AddCommand(pcapCmd)

	pcapCmd.PersistentFlags().String("pcap-path", "", "path to pcap file")
	err := viper.BindPFlag("CFG.PCAP_PATH", pcapCmd.PersistentFlags().Lookup("pcap-path"))
	if err != nil {
		panic(err)
	}
}
