package sniff

import (
	"context"
	"net/http"
)

/*
	Created by aomerk at 2021-11-23 for project strixeye
*/

/*
	contains sniffing interface
*/

// Handler is what the sniffer runs on sniffer/read/captured packets after the tcp reassembly process is
// completed.
type Handler func(ctx context.Context, req *http.Request) error

// Sniffer should be implemented by structs that wants to use the underlying gniffer logic.
type Sniffer interface {
	Run(ctx context.Context) error
	AddHandler(handler Handler) error
}

// New is a factory method for creating a new sniffer.
func New(cfg Cfg) Sniffer {
	return newSniffer(cfg)
}

// Cfg is the configuration for the sniffer. It keeps basic information,
// without referring to the actions that will be taken after the sniffing process is completed such as
// proxying the request to the destination or logging.
type Cfg struct {
	// IsLive is true if the sniffer is running in live mode, meaning it will sniff requests, if false,
	// it will try to read from a pcap file
	IsLive bool `json:"is_live" mapstructure:"IS_LIVE"`

	// InterfaceName is the name of the network interface to sniff on. For now,
	// only single interface per instance is supported.
	InterfaceName string `json:"interface_name" mapstructure:"INTERFACE_NAME"`
	// Filter is bpf filter to apply to the sniffing interface. In this case,
	// most common filter is to set it to "tcp" to sniff only TCP traffic.
	// or filter only requested host and ports on the machine
	// "tcp and port 80 and host omer.beer
	Filter string `json:"filter" mapstructure:"FILTER"`
	// 	PcapPath is the path to the pcap file to write to. It can either be a sniffer or pcap.
	PcapPath string `json:"pcap_path" mapstructure:"PCAP_PATH"`
}

// ProxyCfg is the configuration for the proxy.
// It both has the Cfg and the more advanced configuration parameters for itself such as the target
// destination or how the request should be proxied, filtered etc.
type ProxyCfg struct {
	// Cfg is the configuration for the gniffer application.
	Cfg Cfg `json:"cfg" mapstructure:"CFG"`
	// TargetProtocol http or https
	TargetProtocol string `json:"target_protocol" mapstructure:"TARGET_PROTOCOL"`
	// TargetHost should be a valid hostname
	TargetHost string `json:"target_host" mapstructure:"TARGET_HOST"`
	// TargetPort should be a valid port
	TargetPort string `json:"target_port" mapstructure:"TARGET_PORT"`
	// 	HTTPFilter supports filtering of http requests. In Cfg, the filter works at the network layer,
	// 	this is the filter applied to the application layer.
	HTTPFilter *HTTPFilter `json:"http_filter" mapstructure:"HTTP_FILTER"`
	// AppendXFF is true if the X-Forwarded-For header should be added to the request. (default: false)
	// Also overrides X-Forwarded-Port header.
	AppendXFF bool `json:"append_xff" mapstructure:"APPEND_XFF"`
	// EnableOriginHeaders is true if the Gniffer-Connecting-IP /PORT headers should be added to the request.
	// (default: false)
	EnableOriginHeaders bool `json:"enable_origin_headers" mapstructure:"ENABLE_ORIGIN_HEADERS"`
}

// HTTPFilter supports filtering of http requests. In Cfg, the filter works at the network layer,
// 	this is the filter applied to the application layer.
type HTTPFilter struct {
	Hostname string `json:"server_host" mapstructure:"HOSTNAME"`
}

// Match implements the application layer filtering mechanism similar to the bpf filter in Cfg.
func (f HTTPFilter) Match(req *http.Request) bool {
	if f.Hostname != "" && f.Hostname != req.Host {
		return false
	}

	return true
}
