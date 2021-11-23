package sniff

import (
	`context`
	`log`
	`net/http`
	`time`
	
	`github.com/google/gopacket`
	`github.com/google/gopacket/layers`
	`github.com/google/gopacket/pcap`
	`github.com/google/gopacket/tcpassembly`
	`github.com/pkg/errors`
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

func (s *sniffer) Run(ctx context.Context) error {
	var (
		handle *pcap.Handle
		err    error
	)
	
	handle, err = pcap.OpenLive(
		s.config.InterfaceName, 65536, false, time.Second*3,
	)
	if err != nil {
		return err
	}
	
	if err := handle.SetBPFFilter(s.config.Filter); err != nil {
		return errors.WithMessagef(err, "failed to set bpf filter \"%s\"",s.config.Filter)
	}
	
	defer handle.Close()
	
	// Loop through packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	
	go s.sniffInterface(packets, ctx)
	
	// start consuming deliveries
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case req := <-s.factory.requestChan:
			for _, handler := range s.handlers {
				if err := handler(context.Background(), req); err != nil {
					return err
				}
			}
		}
	}
}

func (s *sniffer) sniffInterface(
	packets chan gopacket.Packet, ctx context.Context,
) {
	
	ticker := time.Tick(time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				log.Println(errors.New("nil packet received"))
				continue
			}
			
			// check if the packet is OK
			if packet.NetworkLayer() == nil {
				log.Println(errors.New("nil network layer received"))
				continue
			}
			if packet.TransportLayer() == nil {
				log.Println(errors.New("nil transport layer received"))
				continue
			}
			
			var tcp *layers.TCP
			networkFlow := packet.NetworkLayer().NetworkFlow()
			
			// handle vxlan configuration
			for _, layer := range packet.Layers() {
				// for vxlan packets, last network layer is the correct one
				if layer.LayerType() == layers.LayerTypeIPv4 {
					networkFlow = layer.(*layers.IPv4).NetworkFlow()
				}
				
				// extract tcp layer
				if layer.LayerType() == layers.LayerTypeTCP {
					tcp = layer.(*layers.TCP)
				}
			}
			
			if tcp == nil {
				continue
			}
			
			s.assembler.AssembleWithTimestamp(
				networkFlow, tcp, packet.Metadata().Timestamp,
			)
		
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			s.assembler.FlushOlderThan(time.Now().Add(time.Second * -2))
		}
	}
}
