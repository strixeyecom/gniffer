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
	"fmt"
	"os"
	
	"github.com/spf13/cobra"
	
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gniffer",
	Short: "very simple gopacket wrapper cli",
	Long: `gniffer is a command line interface to sniff network interfaces and
log, proxy or process sniffed requests.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	
	rootCmd.PersistentFlags().StringVar(
		&cfgFile, "config", "", "config file (default is $HOME/.gniffer.yaml)",
	)
	
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	
	rootCmd.PersistentFlags().StringP("interface", "i", "lo", "which interface to sniff")
	err := viper.BindPFlag("CFG.INTERFACE_NAME", rootCmd.PersistentFlags().Lookup("interface"))
	
	rootCmd.PersistentFlags().StringP("bpf-filter", "f", "", "custom bpf filter")
	err = viper.BindPFlag("CFG.FILTER", rootCmd.PersistentFlags().Lookup("bpf-filter"))
	if err != nil {
		panic(err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)
		
		// Search config in home directory with name ".gniffer" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".gniffer")
	}
	
	viper.AutomaticEnv() // read in environment variables that match
	
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		_, _ = fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
