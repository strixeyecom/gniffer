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
	`bytes`
	`context`
	`io/ioutil`
	`log`
	`net/http`
	
	"github.com/spf13/cobra"
	`github.com/spf13/viper`
	`github.com/strixeyecom/gniffer/api/sniff`
)

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "copy and redirect sniffed requests",
	Long: `proxy command copies the sniffed request and sends to given target server,
without changing the host headers`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var snifferCfg sniff.Cfg
		err := viper.Unmarshal(&snifferCfg)
		if err != nil {
			return err
		}
		
		var proxyCfg sniff.ProxyCfg
		err = viper.Unmarshal(&proxyCfg)
		if err != nil {
			return err
		}
		
		sniffer := sniff.New(snifferCfg)
		sniffingCtx, cancelSniffing := context.WithCancel(context.Background())
		defer cancelSniffing()
		
		client := http.Client{}
		// add logging handler
		err = sniffer.AddHandler(
			func(ctx context.Context, req *http.Request) error {
				dupReq := req.Clone(ctx)
				// modify request so that it goes to the target server but still has the original headers
				dupReq.URL.Scheme = proxyCfg.TargetProtocol
				dupReq.URL.Host = proxyCfg.TargetHost + ":" + proxyCfg.TargetPort
				// request uri is handled by the client library
				dupReq.RequestURI = ""
				
				// should copy the body because the original request body will be emptied
				body, err := ioutil.ReadAll(req.Body)
				if err == nil {
					dupReq.Body = ioutil.NopCloser(bytes.NewReader(body))
				}
				
				_, err = client.Do(dupReq)
				if err != nil {
					return err
				}
				return nil
			},
		)
		
		if err := sniffer.Run(sniffingCtx); err != nil {
			return err
		}
		
		return nil
	},
}

func init() {
	sniffCmd.AddCommand(proxyCmd)
	
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	proxyCmd.PersistentFlags().Int("target-port", 80, "target location's port")
	err := viper.BindPFlag("TARGET_PORT", proxyCmd.PersistentFlags().Lookup("target-port"))
	if err != nil {
		log.Fatal(err)
	}
	
	proxyCmd.PersistentFlags().String("target-host", "localhost", "target location's host")
	err = viper.BindPFlag("TARGET_HOST", proxyCmd.PersistentFlags().Lookup("target-host"))
	if err != nil {
		log.Fatal(err)
	}
	
	proxyCmd.PersistentFlags().String("target-protocol", "http", "target location's protocol")
	err = viper.BindPFlag("TARGET_PROTOCOL", proxyCmd.PersistentFlags().Lookup("target-protocol"))
	if err != nil {
		log.Fatal(err)
	}
	
}
