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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/strixeyecom/gniffer/api/sniff"
)

// proxyCmd represents the proxy command.
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "copy and redirect sniffed requests",
	Long: `proxy command copies the sniffed request and sends to given target server,
without changing the host headers`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var proxyCfg sniff.ProxyCfg
		err := viper.Unmarshal(&proxyCfg)
		if err != nil {
			return err
		}

		sniffer := sniff.New(proxyCfg.Cfg)
		sniffingCtx, cancelSniffing := context.WithCancel(context.Background())
		defer cancelSniffing()

		client := http.Client{}
		// add logging handler
		err = sniffer.AddHandler(
			func(ctx context.Context, req *http.Request) error {
				if proxyCfg.HTTPFilter != nil {
					if !proxyCfg.HTTPFilter.Match(req) {
						return nil
					}
				}

				dupReq := req.Clone(ctx)
				// modify request so that it goes to the target server but still has the original headers
				dupReq.URL.Scheme = proxyCfg.TargetProtocol
				dupReq.URL.Host = proxyCfg.TargetHost + ":" + proxyCfg.TargetPort
				// request uri is handled by the client library
				dupReq.RequestURI = ""

				// add original client information to x- headers while proxying
				ip, port, err := net.SplitHostPort(req.RemoteAddr)
				if proxyCfg.AppendXFF {
					if err != nil {
						return err
					}
					dupReq.Header.Add("X-Forwarded-For", ip)
					dupReq.Header.Set("X-Forwarded-Port", port)
				}

				if proxyCfg.EnableOriginHeaders {
					dupReq.Header.Set("Gniffer-Connecting-Ip", ip)
					dupReq.Header.Set("Gniffer-Connecting-Port", port)
				}
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
		if err != nil {
			return errors.Wrap(err, "failed to add handler")
		}

		fmt.Printf(
			"proxying %s requests to %s://%s:%s", proxyCfg.Cfg.InterfaceName, proxyCfg.TargetProtocol,
			proxyCfg.TargetHost,
			proxyCfg.TargetPort,
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

	proxyCmd.PersistentFlags().Bool("append-xff", false, "append xff header to the request")

	err = viper.BindPFlag("APPEND_XFF", proxyCmd.PersistentFlags().Lookup("append-xff"))
	if err != nil {
		log.Fatal(err)
	}

	proxyCmd.PersistentFlags().Bool(
		"enable-origin-headers", true, "set gniffer-connecting-ip and gniffer-connecting-port headers",
	)

	err = viper.BindPFlag("ENABLE_ORIGIN_HEADERS", proxyCmd.PersistentFlags().Lookup("enable-origin-headers"))
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

	proxyCmd.PersistentFlags().String("app-filter-hostname", "", "which hostnames should be proxied")

	err = viper.BindPFlag("HTTP_FILTER.HOSTNAME", proxyCmd.PersistentFlags().Lookup("app-filter-hostname"))
	if err != nil {
		log.Fatal(err)
	}
}
