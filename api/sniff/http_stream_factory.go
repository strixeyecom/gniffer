package sniff

import (
	`net/http`
	
	`github.com/google/gopacket`
	`github.com/google/gopacket/tcpassembly`
	`github.com/google/gopacket/tcpassembly/tcpreader`
)

/*
	Created by aomerk at 2021-11-23 for project strixeye
*/

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	// This part is what we get from config
	requestChan chan *http.Request
}


func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	httpStream := &httpStream{
		net:         net,
		transport:   transport,
		r:           tcpreader.NewReaderStream(),
		requestChan: h.requestChan,
	}
	
	// Important... we must guarantee that data from the reader stream is read.
	go httpStream.run()
	
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &httpStream.r
}
