package sniff

import (
	`bufio`
	`bytes`
	`io`
	`io/ioutil`
	`log`
	`net/http`
	
	`github.com/google/gopacket`
	`github.com/google/gopacket/tcpassembly/tcpreader`
)

/*
	Created by aomerk at 2021-11-23 for project strixeye
*/


// global constants for file
const ()

// global variables (not cool) for this file
var ()

// httpStream will handleProfiling the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	requestChan    chan *http.Request
}

func (h *httpStream) run() {
	defer func() {
		dErr := recover()
		if dErr != nil {
			log.Fatal(dErr.(error))
		}
	}()
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			continue
		} else {
			req.RemoteAddr = h.net.Src().String() + ":" + h.transport.Src().String()
			// body is a tricky mistress. To guarantee we don't lose it, just a trick to be safe
			body, _ := ioutil.ReadAll(req.Body)
			req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			h.requestChan <- req
		}
	}
}
