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
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/strixeyecom/gniffer/pkg/sniff"
)

const clientTimeout = 20
const MaxWorkers = 1e3 * 2
const MaxIdleConnectionsPerHost = MaxWorkers

// nolint: gochecknoglobals // because we want all workers to share the same client and using a struct is
// overkill.
var client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: MaxIdleConnectionsPerHost,
	},
	Timeout: time.Second * clientTimeout,
}

func worker(ctx context.Context, c chan *http.Request) {

	for {
		select {
		case <-ctx.Done():
			return
		case req := <-c:
			resp, err := client.Do(req)
			if err != nil {
				panic(err)
			}

			_, _ = io.Copy(ioutil.Discard, resp.Body)

			err = resp.Body.Close()
			if err != nil {
				panic(err)
			}
		}
	}
}

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

		sniffingCtx, cancelSniffing := context.WithCancel(context.Background())
		defer cancelSniffing()
		err = RunProxy(sniffingCtx, &proxyCfg)
		if err != nil {
			return errors.Wrap(err, "failed to add handler")
		}

		return nil
	},
}

func RunProxy(ctx context.Context, proxyCfg *sniff.ProxyCfg) error {
	if proxyCfg.TargetPort == "" {
		return errors.New("target port is required")
	}

	sniffer := sniff.New(proxyCfg.Cfg)

	requestChan := make(chan *http.Request)
	for i := 0; i < MaxWorkers; i++ {
		go worker(ctx, requestChan)
	}
	// add logging handler
	err := sniffer.AddHandler(
		func(ctx context.Context, req *http.Request) error {
			return handlerFunc(ctx, req, proxyCfg, requestChan)
		},
	)
	if err != nil {
		return errors.Wrap(err, "failed to add handler")
	}

	log.Printf(
		"proxying %s %s requests to %s://%s:%s", proxyCfg.Cfg.InterfaceName,
		proxyCfg.HTTPFilter.Hostname, proxyCfg.TargetProtocol,
		proxyCfg.TargetHost, proxyCfg.TargetPort,
	)

	if err := sniffer.Run(ctx); err != nil {
		return errors.Wrap(err, "can not run sniffer")
	}

	return nil
}

func handlerFunc(
	ctx context.Context, req *http.Request, proxyCfg *sniff.ProxyCfg, requestChan chan *http.Request,
) error {
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

	req.Header.Set("Connection", "close")
	req.Close = true
	requestChan <- dupReq

	return nil
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
}
