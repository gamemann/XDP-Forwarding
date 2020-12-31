# XDP Forwarding (WIP)
## Description
A program that attaches to the [XDP](https://www.iovisor.org/technology/xdp) hook and performs basic layer 3/4 forwarding. This program does source port mapping similar to IPTables and NFTables for handling connections.

**WARNING** - There are still many things that need to be done to this project and as of right now, it only supports IPv4. IPv6 support will be added before official release. As of right now, the program may include bugs and forwarding features aren't yet available.

**Note** - Before release, I plan on making benchmarks on the XDP Forwarding program vs IPTables/NFTables. As of right now, I have no benchmarks.

## Limitations
The default maximum ports that can be used per bind address is **1000** and is set [here](https://github.com/gamemann/XDP-Forwarding/blob/master/src/xdpfwd.h#L6). You may raise this constant if you'd like along with the others there.

At first, I was trying to use all available ports (1 - 65535). However, due to BPF verifier limitations, I had to raise some constants inside the Linux kernel and recompile the kernel. I made patches for these and have everything documented [here](https://github.com/gamemann/XDP-Forwarding/tree/master/patches). Unfortunately, when trying to use 65535 as the max port range (with 256 rules) without running into verifier limitations, the BPF program ends up taking a very long time to load. It doesn't result in any errors, but it'll hang for a very long time and I haven't seen it load yet with this number. I'm still trying to see if there's anything I can do to speed up the loading time. However, I'm not really sure how else I can optimize the program at the moment.

## Mounting The BPF File System
In order to use `xdpfwd-add` and `xdpfwd-del`, you must mount the BPF file system since the XDP program pins the BPF maps to `/sys/fs/bpf/xdpfwd`. There's a high chance this is already done for you via `iproute2` or something similar, but if it isn't, you may use the following command:

```
mount -t bpf bpf /sys/fs/bpf/
```
## Command Line Usage
### Basic
Basic command line usage includes:

```
-o --offload => Attempt to load XDP program with HW/offload mode. If fails, will try DRV and SKB mode in that order.
-c --config => Location to XDP Forward config (default is /etc/xdpfwd/xdpfwd.conf).
-h --help => Print out command line usage. (Not implemented yet).
```

### XDP Add Program
The `xdpfwd-add` executable which is added to the `$PATH` via `/usr/bin` on install accepts the following arguments:

```
-b --baddr => The address to bind/look for.
-B --bport => The port to bind/look for.
-d --daddr => The destination address.
-D --dport => The destination port.
-p --protocol => The protocol number to use (17 for UDP, 6 for TCP, and 1 for ICMP).
```

This will add a forwarding rule while the XDP program is running. As of right now, it does **not** save this rule into the XDP config file. However, I will be implementing save functionality before release.

Additionally, the protocol will accept a string input in the future (before release) such as "udp", "tcp", and "icmp". This functionality is not currently implemented, though.

### XDP Delete Program
The `xdpfwd-del` executable which is added to the `$PATH` via `/usr/bin` on install accepts the following arguments:

```
-b --baddr => The address to bind/look for.
-B --bport => The port to bind/look for.
-p --protocol => The protocol number to use (17 for UDP, 6 for TCP, and 1 for ICMP).
```

This will delete a forwarding rule while the XDP program is running. As of right now, it does **not** save the results into the XDP config file. However, I will be implementing save functionality before release.

Additionally, the protocol will accept a string input in the future (before release) such as "udp", "tcp", and "icmp". This functionality is not currently implemented, though.

## Configuration
The default config file is at `/etc/xdpfwd/xdpfwd.conf` and uses the `libconfig` syntax. Here's an example config using all of its current features.

```
interface = "ens18"; // The interface the XDP program attaches to.

// Forwarding rules array.
forwarding = (
    {
        bind = "10.50.0.3",     // The bind address which incoming packets must match.
        bindport = 80,          // The bind port which incoming packets must match.

        protocol = "udp",       // The protocol (as of right now "udp", "tcp", and "icmp" are supported). Right now, you must specify a protocol. However, in the future I will be implementing functionality so you don't have to and it'll do full layer-3 forwarding.

        dest = "10.50.0.4",     // The address we're forwarding to.
        destport = 8080         // The port we're forwarding to (if not set, will use the bind port).
    },
    ...
);
```

## Credits
* [Christian Deacon](https://github.com/gamemann)