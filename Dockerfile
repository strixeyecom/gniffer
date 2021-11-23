FROM alpine

# Copy gniffer
COPY gniffer /dist/gniffer

# Command to run when starting the container
ENTRYPOINT ["/dist/gniffer"]