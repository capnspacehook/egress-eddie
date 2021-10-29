# egress-eddie

Egress Eddie is a simple tool designed to do one thing: filter outbound traffic by hostnames.
Iptables and nftables both only let you filter by IP addresses, generally if you want to filter
by hostname you need a proxy for the specific protocol you're trying to filter. But Egress Eddie
allows you to filter all TCP and UDP traffic by hostnames, regardless of the protocol being used
on top.

## How it works

Egress Eddie utilizes nfqueue to intercept packets from iptables or nftables. It then filters DNS
requests, only allowing requests for allowed hostnames. DNS responses to those requests are tracked,
and the IP addresses or hostnames present in DNS responses are allowed outbound for the TTL specified
by the DNS answer.

## Getting started

After building, either run the binary as root or give it necessary capabilities:

```bash
setcap 'cap_net_admin=+ep' egress-eddie
```

Special permissions are needed to interface with nfqueue.

# Example

Here's an example that will only allow apt to connect to the default debian repos, and only allow all 
other users to pull Go modules.

Iptables rules:

```bash
# send all DNS replies to be inspected
# inbound traffic can't be filtered by user
iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1

# filter DNS requests from apt
iptables -A OUTPUT -m owner --uid-owner _apt -p udp --dport 53 -j NFQUEUE --queue-num 1000
# filter HTTP/S requests from apt
iptables -A OUTPUT -m owner --uid-owner _apt -m state --state NEW -p tcp --dport 80 -j NFQUEUE --queue-num 1001
iptables -A OUTPUT -m owner --uid-owner _apt -m state --state NEW -p tcp --dport 443 -j NFQUEUE --queue-num 1001

# filter all other DNS requests 
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 2000
# filter all other HTTP/S requests
iptables -A OUTPUT -m state --state NEW -p tcp --dport 80 -j NFQUEUE --queue-num 2001
iptables -A OUTPUT -m state --state NEW -p tcp --dport 443 -j NFQUEUE --queue-num 2001

```

Config:

```toml
inboundDNSQueue = 1
ipv6 = false

# filter apt updating
[[filters]]
dnsQueue = 1000
trafficQueue = 1001
ipv6 = false
hostnames = [
    "deb.debian.org",
]

# filter go module traffic
[[filters]]
dnsQueue = 2000
trafficQueue = 2001
ipv6 = false
hostnames = [
    "proxy.golang.org",
    "sum.golang.org",
]
```
