package cmd

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

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// sniffCmd represents the sniff command.
var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		viper.Set("CFG.IS_LIVE", true)
	},
}

func init() {
	rootCmd.AddCommand(sniffCmd)

	sniffCmd.PersistentFlags().String("app-filter-hostname", "", "which hostnames should be proxied")

	err := viper.BindPFlag("HTTP_FILTER.HOSTNAME", sniffCmd.PersistentFlags().Lookup("app-filter-hostname"))
	if err != nil {
		log.Fatal(err)
	}
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sniffCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
