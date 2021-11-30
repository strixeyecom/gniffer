package sniff

import (
	"context"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/pkg/errors"
)

/*
	Created by aomerk at 2021-11-23 for project strixeye
*/

type sniffer struct {
	assembler *tcpassembly.Assembler
	factory   *httpStreamFactory
	// config contains sniffing related configuration
	config Cfg
	// handler functions to process the http requests
	handlers []Handler
}

func newSniffer(cfg Cfg) *sniffer {
	s := &sniffer{
		config:  cfg,
		factory: &httpStreamFactory{requestChan: make(chan *http.Request)},
	}

	streamPool := tcpassembly.NewStreamPool(s.factory)
	s.assembler = tcpassembly.NewAssembler(streamPool)

	return s
}

func (s *sniffer) AddHandler(handler Handler) error {
	s.handlers = append(s.handlers, handler)

	return nil
}

const maxSnapLen = 65536

const timeoutDuration = time.Second * 3

func (s *sniffer) readPackets(
	ctx context.Context, packets chan gopacket.Packet,
) {
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packets:
			var (
				tcp         *layers.TCP
				networkFlow gopacket.Flow
				err         error
			)

			// handle vxlan configuration
			networkFlow, tcp, err = s.handleVXLAN(packet)
			if tcp == nil || err != nil {
				continue
			}

			s.assembler.AssembleWithTimestamp(
				networkFlow, tcp, packet.Metadata().Timestamp,
			)

		case <-ticker.C:
			// Every minute, flush connections that haven't seen activity in the past 2 seconds.
			s.assembler.FlushOlderThan(time.Now().Add(time.Second * -2))
		}
	}
}

func (s *sniffer) Run(ctx context.Context) error {
	var (
		handle *pcap.Handle
		err    error
	)

	switch s.config.IsLive {
	case true:
		handle, err = pcap.OpenLive(
			s.config.InterfaceName, maxSnapLen, false, timeoutDuration,
		)
	case false:
		handle, err = pcap.OpenOffline(s.config.PcapPath)
	}

	if err != nil {
		return errors.Wrap(err, "failed to open packet capture")
	}

	if err := handle.SetBPFFilter(s.config.Filter); err != nil {
		return errors.WithMessagef(err, "failed to set bpf filter \"%s\"", s.config.Filter)
	}

	defer handle.Close()

	// Loop through packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// start collecting packets
	readCtx, readCancel := context.WithCancel(ctx)

	go func() {
		s.readPackets(ctx, packets)
		readCancel()
	}()

	// start consuming deliveries
	return s.handleAssembledRequests(readCtx)
}

func (s *sniffer) handleAssembledRequests(readCtx context.Context) error {
	for {
		select {
		case <-readCtx.Done():
			return errors.Wrap(readCtx.Err(), "stop handling assembled requests")

		// 	run handlers on packets.
		case req := <-s.factory.requestChan:
			for _, handler := range s.handlers {
				if err := handler(context.Background(), req); err != nil {
					return err
				}
			}
		}
	}
}

func (s *sniffer) handleVXLAN(packet gopacket.Packet) (
	gopacket.Flow, *layers.TCP, error,
) {
	var (
		tcp         *layers.TCP
		networkFlow gopacket.Flow
	)

	// Either packet is nil, or a necessary layer is missing.
	if err := validatePacket(packet); err != nil {
		return networkFlow, tcp, err
	}

	var err error
	for _, layer := range packet.Layers() {
		// for vxlan packets, last network layer is the correct one
		networkFlow, err = checkIPv4Layer(layer, networkFlow)
		if err != nil {
			return networkFlow, tcp, err
		}

		networkFlow, err = checkIPv6Layer(layer, networkFlow)
		if err != nil {
			return networkFlow, tcp, err
		}

		tcp, err = checkTCPLayer(layer, tcp)
		if err != nil {
			return networkFlow, tcp, err
		}
	}

	return networkFlow, tcp, nil
}

func checkTCPLayer(layer gopacket.Layer, tcp *layers.TCP) (*layers.TCP, error) {
	if layer.LayerType() == layers.LayerTypeTCP {
		var ok bool
		tcp, ok = layer.(*layers.TCP)
		if !ok {
			return tcp, errors.New("TCP layer is not TCP")
		}
	}

	return tcp, nil
}

func checkIPv4Layer(layer gopacket.Layer, flow gopacket.Flow) (gopacket.Flow, error) {
	var (
		ipv4Layer *layers.IPv4
		ok        bool
	)

	if layer.LayerType() == layers.LayerTypeIPv4 {
		ipv4Layer, ok = layer.(*layers.IPv4)
		if !ok {
			return gopacket.Flow{}, errors.New("IPv4 layer is not a valid network layer")
		}

		return ipv4Layer.NetworkFlow(), nil
	}

	return flow, nil
}

func checkIPv6Layer(layer gopacket.Layer, flow gopacket.Flow) (gopacket.Flow, error) {
	var ipv6Layer *layers.IPv6

	if layer.LayerType() == layers.LayerTypeIPv6 {
		var ok bool

		ipv6Layer, ok = layer.(*layers.IPv6)
		if !ok {
			return gopacket.Flow{}, errors.New("IPv6 layer is not a valid network layer")
		}

		return ipv6Layer.NetworkFlow(), nil
	}

	return flow, nil
}

func validatePacket(packet gopacket.Packet) error {
	if packet == nil {
		return errors.New("packet is nil")
	}

	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return errors.New("packet is unusable")
	}

	return nil
}
