package sniff

import (
	`context`
	`net/http`
)

/*
	Created by aomerk at 2021-11-23 for project strixeye
*/

/*
	contains sniffing interface
*/

type Handler func(ctx context.Context, req *http.Request) error
type Sniffer interface {
	Run(ctx context.Context) error
	AddHandler(handler Handler) error
}

func New(cfg Cfg) Sniffer {
	return newSniffer(cfg)
}

type Cfg struct {
	InterfaceName string `json:"interface_name" mapstructure:"INTERFACE_NAME"`
	Filter        string `json:"filter" mapstructure:"FILTER"`
}

type ProxyCfg struct {
	// TargetProtocol http or https
	TargetProtocol string `json:"target_protocol" mapstructure:"TARGET_PROTOCOL"`
	// TargetHost should be a valid hostname
	TargetHost string `json:"target_host" mapstructure:"TARGET_HOST"`
	// TargetPort should be a valid port
	TargetPort string `json:"target_port" mapstructure:"TARGET_PORT"`
}
