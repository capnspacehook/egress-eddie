# egress-eddie

Egress Eddie is a simple tool designed to do one thing: filter outbound traffic by hostname.
Iptables and nftables both only let you filter by IP address, generally if you want to filter
by hostname you need a proxy for the specific protocol you're trying to filter. But Egress Eddie
allows you to filter all TCP and UDP traffic by hostname, regardless of the protocol being used
on top.

Filtering by hostname can make it exceedingly difficult for both malware to phone home and misbehaving
software to send unwanted telemetry. Combined with strong egress firewall rules, Egress Eddie can
act as a failsafe, preventing attackers that are able to execute code on your machine from exfiltrating
data or interactively taking control.

## How it works

Egress Eddie utilizes nfqueue to intercept configured packets from iptables or nftables. It then filters
DNS requests, only allowing requests for allowed hostnames. DNS responses to those requests are tracked,
and only the IP addresses or hostnames present in DNS responses are allowed outbound for a configurable 
amount of time.

## Details

All DNS requests that are sent to Egress Eddie are filtered to make sure the questions contain allowed
hostnames, and all DNS responses are also filtered in the same way. Additionally, only DNS responses from
an established connection are accepted, but DNS requests from either a new or established connections
are accepted.

A DNS message is allowed if all of the questions in that message have an explicitly allowed hostname as
a suffix. For example, if `google.com` is an allowed hostname, DNS requests for
`blog.google.com`, `groups.google.com`, and `google.com` would all be allowed.

Accepted DNS answers of type `A` and `AAAA` cause the contained IPs to be allowed. DNS answers of type
`CNAME` and `SRV` cause the contained hostnames to be allowed to be queried. All other accepted DNS
answer types are passed through to the sender with no action taken by Egress Eddie.

Normal traffic is only parsed up to the network layer (`IPv4` or `IPv6`). The source and destination
IP addresses are inspected to ensure they match IPs returned from accepted DNS answers.

## Security

Egress Eddie leverages `seccomp` to ensure that it will only use a handful of syscalls (default 24)
with filtered arguments. This makes it very difficult for an attacker to do anything of value if
they are somehow able to execute code in the context of a running Egress Eddie process.

## Permissions required

After building, give the binary necessary capabilities:

```bash
setcap 'cap_net_admin=+ep' egress-eddie
```

Special permissions are needed to interface with nfqueue. 

Alternatively, you *could* run Egress Eddie as root, though that is not recommended from a security standpoint.

## Installing

Either download the latest release or build the code yourself:

```bash
go install github.com/capnspacehook/egress-eddie@latest
```

# Configuration

Egress Eddie requires both iptables rules that send appropriate packets to Egress Eddie for
inspection, and to be configured to look for those packets.

## Iptables rules:

The requirements for iptables rules are pretty simple. Egress Eddie requires 3 sets of
rules: sending DNS responses, sending DNS requests, and sending traffic to Egress Eddie.

### Sending DNS responses

First, you'll need to add a rule that sends all DNS responses to Egress Eddie. This can be
accomplished as so:

```bash
# filter all DNS responses
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j NFQUEUE --queue-num 1
```

Note here that only UDP traffic over port 53 is sent to Egress Eddie, but DNS traffic can
be sent over TCP as well. Additional rules are omitted for brevity.

Sending only established traffic isn't required, but it is recommended as starting a DNS
conversation with a response doesn't make any sense. 

This rule only needs to be added once, regardless of how many different types of traffic
you want to filter.

### Sending DNS requests

Next, you'll need to add a rule that sends DNS requests to Egress Eddie. You can either
send all DNS requests and filter all hostnames at once, or send specific DNS requests
so that you can more granularly filter by hostname. For example, you can filter outbound
traffic by the user who created the connection in iptables, allowing you to filter DNS
requests differently depending on who sent it.

```bash
# filter all DNS requests
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000

# OR

# filter DNS requests from a specific user, in this case admin
iptables -A OUTPUT -m owner --uid-owner admin -p udp --dport 53 -j NFQUEUE --queue-num 1000
```

### Sending traffic

Finally, you'll need to add a rule that sends the actual traffic you want to filter to
Egress Eddie. As before, you can send all traffic, or traffic from certain
users. The following example rules will filter HTTP traffic:

```bash
# filter HTTP requests
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1001

# OR

# filter HTTP requests from a specific user, in this case admin
iptables -A OUTPUT -p tcp --dport 80 -m owner --uid-owner admin -m state --state NEW -j NFQUEUE --queue-num 1001
```

Notice how only new packets are being sent to Egress Eddie. This is purely for performance
reasons. You could send new and established HTTP packets for Egress Eddie to inspect,
but that would have needless overhead; if the first packet is going to an allowed IP, all
following packets in the same connection will also go to that allowed IP and can be safely
allowed.

## Config file

The various options in the config file mostly boil down to telling Egress Eddie which nfqueue
numbers to open and use. Here's a simple config that only allows traffic to `github.com`, 
using the same nfqueue numbers that were set in iptables rules above:

```toml
inboundDNSQueue = 1
ipv6 = false

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
ipv6 = false
allowAnswersFor = "5m"
allowedHostnames = [
    "github.com",
]
```

The nfqueue number for DNS responses is set to 1, and `ipv6` is set to `false` as we are
filtering `IPv4` traffic. If you are filtering `IPv6` traffic and using ip6tables, set
that to `true`.

Next we create a filter, setting the nfqueue numbers used for DNS requests and traffic
that we want filtered. 

`allowAnswersFor` controls how long IPs and hostnames returned
from DNS responses are allowed for. The syntax for specifying a duration is the 
[Go duration syntax](https://pkg.go.dev/time#ParseDuration). If `allowAnswersFor` is
not set, it defaults to the TTL of the DNS response.

Finally `hostnames` controls the hostnames that are allowed, which here is just `github.com`.

### Allowing all hostnames

There may be situations where you want to filter the hostnames of a specific user or type
of traffic, but allow other users or types of traffic flow unrestricted. I like to allow
the root user to have unrestricted HTTP/S access for example, as if someone compromises the
root account, then all other bets are off.

To accomplish this, set `allowAllHostnames = true` and don't set either `trafficQueue` or
`hostnames`. Because all DNS responses must be inspected by Egress Eddie in order for it to
function properly, all DNS requests must go through Egress Eddie as well.

## Example

Here's an example that ties everything mentioned above together. It allows `apt` to access
the standard Debian repositories, the `dev` user to pull Go modules, and the `root` user
to have unrestricted DNS traffic.

iptables rules:

```bash
# filter all DNS responses
iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1

# filter DNS requests from apt
iptables -A OUTPUT -p udp --dport 53 -m owner --uid-owner _apt -j NFQUEUE --queue-num 1000
# filter HTTP/S requests from apt
iptables -A OUTPUT -p tcp --dport 80 -m owner --uid-owner _apt -m state --state NEW -j NFQUEUE --queue-num 1001
iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner _apt -m state --state NEW -j NFQUEUE --queue-num 1001

# filter DNS requests from the dev user
iptables -A OUTPUT -p udp --dport 53 -m owner --uid-owner dev -j NFQUEUE --queue-num 2000
# filter HTTP/S requests from the dev user
iptables -A OUTPUT -p tcp --dport 80 -m owner --uid-owner dev -m state --state NEW -j NFQUEUE --queue-num 2001
iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner dev -m state --state NEW -j NFQUEUE --queue-num 2001

# allow all DNS requests from the root user
iptables -A OUTPUT -p udp --dport 53 -m owner --uid-owner root -j NFQUEUE --queue-num 3000
```

config file:

```toml
inboundDNSQueue = 1
ipv6 = false

# filter apt updating
[[filters]]
dnsQueue = 1000
trafficQueue = 1001
ipv6 = false
allowAnswersFor = "30m"
allowedHostnames = [
    "deb.debian.org",
    "security.debian.org",
]

# filter go module traffic
[[filters]]
dnsQueue = 2000
trafficQueue = 2001
ipv6 = false
allowAnswersFor = "5m"
allowedHostnames = [
    "proxy.golang.org",
    "sum.golang.org",
]

# allow all root DNS requests
[[filters]]
dnsQueue = 3000
ipv6 = false
allowAllHostnames = true
```
