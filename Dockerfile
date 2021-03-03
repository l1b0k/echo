FROM golang:1.15 as builder
WORKDIR /go/src/github.com/l1b0k/echo/
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X \"main.gitCommit=`git rev-parse --short HEAD 2>/dev/null`\" -X \"main.buildDate=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \" " -o echo .

FROM ubuntu:20.10
RUN apt-get update && apt-get install -y iproute2 dnsutils ipvsadm iptables kmod curl ipset bash ethtool bridge-utils socat grep findutils jq && \
    apt-get purge --auto-remove && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /go/src/github.com/l1b0k/echo/echo /usr/bin/echo
ENTRYPOINT ["/usr/bin/echo"]