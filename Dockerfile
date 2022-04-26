FROM golang:1.18.1 as builder
WORKDIR /go/src/github.com/l1b0k/echo/
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X \"main.gitCommit=`git rev-parse --short HEAD 2>/dev/null`\" -X \"main.buildDate=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \" " -o echo .

FROM ubuntu:20.04
RUN apt-get update && apt-get install -y iproute2 dnsutils ipvsadm iptables kmod curl wget ipset bash ethtool bridge-utils socat grep findutils jq netcat netperf iperf procps net-tools strace vim iputils-ping && \
    apt-get purge --auto-remove && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /go/src/github.com/l1b0k/echo/echo /usr/bin/echo
ENTRYPOINT ["/usr/bin/echo"]