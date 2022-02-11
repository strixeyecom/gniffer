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
	"context"
	"log"
	"net/http"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/strixeyecom/gniffer/pkg/sniff"
)

// logCmd represents the log command.
var logCmd = &cobra.Command{
	Use:   "log",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var snifferCfg sniff.ProxyCfg
		err := viper.Unmarshal(&snifferCfg)
		if err != nil {
			return err
		}
		sniffer := sniff.New(snifferCfg.Cfg)
		sniffingCtx, cancelSniffing := context.WithCancel(context.Background())
		defer cancelSniffing()

		// add logging handler
		err = sniffer.AddHandler(
			func(ctx context.Context, req *http.Request) error {
				log.Printf("%s-> %s%s", req.RemoteAddr, req.Host, req.RequestURI)
				return nil
			},
		)
		if err != nil {
			return errors.Wrap(err, "failed to add handler")
		}

		if err := sniffer.Run(sniffingCtx); err != nil {
			return err
		}

		return nil
	},
}

// logPcapCmd represents the log command.
// nolint:gochecknoglobals // because cobra thinks this is the correct wawy
var logPcapCmd = &cobra.Command{
	Use:   "log",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var snifferCfg sniff.ProxyCfg
		err := viper.Unmarshal(&snifferCfg)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal config")
		}
		sniffer := sniff.New(snifferCfg.Cfg)
		sniffingCtx, cancelSniffing := context.WithCancel(context.Background())
		defer cancelSniffing()

		// add logging handler
		err = sniffer.AddHandler(
			func(ctx context.Context, req *http.Request) error {
				log.Printf("%s %s", req.RemoteAddr, req.RequestURI)

				return nil
			},
		)
		if err != nil {
			return errors.Wrap(err, "failed to add handler")
		}

		if err := sniffer.Run(sniffingCtx); err != nil {
			return errors.Wrap(err, "failed to run sniffer")
		}

		return nil
	},
}

func init() {
	sniffCmd.AddCommand(logCmd)
	pcapCmd.AddCommand(logPcapCmd)

}
