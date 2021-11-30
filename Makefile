# musl installs musl to /usr/local/musl. Needed because musl works better with creating static compilations with golang.
musl:
	wget http://www.musl-libc.org/releases/musl-1.2.2.tar.gz
	tar -xvf musl-1.2.2.tar.gz
	cd musl-1.2.2 ;\
	./configure;\
	export CFLAGS_ALL_STATIC=true;\
	make;\
	sudo  make install

initialize:
	go mod tidy

libpcap:
	wget -O libpcap-1.10.0.tar.gz http://www.tcpdump.org/release/libpcap-1.10.0.tar.gz;\
 	tar -xf libpcap-1.10.0.tar.gz;\
 	cd libpcap-1.10.0; \
 	./configure; \
 	export CC=/usr/local/musl/bin/musl-gcc; \
 	make && make install;\
 	ldconfig

build: initialize
	CGO_ENABLED=1 \
 	GOOS=linux go build \
 	-ldflags="-extldflags=-static -s -w" \
	-a -o gniffer  main.go

build-standalone:
	docker run --rm=true -itv $$PWD:/mnt $$DOCKER_REGISTRY/builder

release:
	docker run --rm \
      -v $$PWD:/go/src/github.com/strixeyecom/gniffer \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -w /go/src/github.com/strixeyecom/gniffer \
      -e $$RELEASE_TOKEN_KEY=$$RELEASE_TOKEN_VALUE \
      -e DOCKER_USERNAME \
      -e DOCKER_PASSWORD \
      -e DOCKER_REGISTRY \
      $$DOCKER_REGISTRY/releaser release --rm-dist

