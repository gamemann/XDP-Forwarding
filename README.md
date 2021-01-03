# XDP Forwarding (WIP)
## Description
A program that attaches to the [XDP](https://www.iovisor.org/technology/xdp) hook and performs basic layer 3/4 forwarding. This program does source port mapping similar to IPTables and NFTables for handling connections. Existing connections are prioritized based off of the connection's packets per nanosecond. This means on port exhaustion, connections with the least packets per nanosecond will be replaced. I feel this is best since connections with higher packets per nanosecond will be more sensitive.

The XDP program tries to use DRV mode at first, but if that does not attach properly, it will fall back to SKB mode. You may specify the `-o` flag (as seen below) to use HW mode.

**WARNING** - There are still many things that need to be done to this project and as of right now, it only supports IPv4. IPv6 support will be added before official release. As of right now, the program may include bugs and forwarding features aren't yet available.

**Note** - Before release, I plan on making benchmarks on the XDP Forwarding program vs IPTables/NFTables. As of right now, I have no benchmarks.

## Limitations
The default maximum source ports that can be used per bind address is **20** and is set [here](https://github.com/gamemann/XDP-Forwarding/blob/master/src/xdpfwd.h#L8). You may raise this constant if you'd like along with the others there.

At first, I was trying to use all available ports (1 - 65535). However, due to BPF verifier limitations, I had to raise a couple constants inside the Linux kernel and recompile the kernel. I made patches for these and have everything documented [here](https://github.com/gamemann/XDP-Forwarding/tree/master/patches). I am able to run the program with 65535 max ports per bind address without any issues with the custom kernel I built using the patches I made.

If you plan to use this for production, I'd highly suggest compiling your own kernel with the constants raised above. 30 maximum source ports per bind address is not much, but unfortunately, the default BPF verifier restrictions don't allow us to go any further currently.

The main code that causes these limitations is located [here](https://github.com/gamemann/XDP-Forwarding/blob/master/src/xdp_prog.c#L337) and occurs when we're trying to find the best source port to use for a new connection. There's really no other way to check for the best source port available with the amount of flexibility we have to my understanding since we must loop through all source ports and check the last seen time value (BPF maps search by key).

## Requirements
### Packages
You will need `make`, `clang`, `libelf`, and `llvm` since we use these packages to build the project. Additionally, you will also need `libconfig` (`libconfig-dev` is the package on Ubuntu/Debian systems) for parsing the config file.

For Ubuntu/Debian, the following should work.

```
apt install build-essential make clang libelf-dev llvm libconfig-dev
```

I'd assume package names should be similar on other Linux distros.

### Mounting The BPF File System
In order to use `xdpfwd-add` and `xdpfwd-del`, you must mount the BPF file system since the XDP program pins the BPF maps to `/sys/fs/bpf/xdpfwd`. There's a high chance this is already done for you via `iproute2` or something similar, but if it isn't, you may use the following command.

```
mount -t bpf bpf /sys/fs/bpf/
```

## Command Line Usage
### Basic
Basic command line usage includes the following.

```
-o --offload => Attempt to load XDP program with HW/offload mode. If fails, will try DRV and SKB mode in that order.
-s --skb => Force program to load in SKB/generic mode.
-c --config => Location to XDP Forward config (default is /etc/xdpfwd/xdpfwd.conf).
-h --help => Print out command line usage. (Not implemented yet).
```

### XDP Add Program
The `xdpfwd-add` executable which is added to the `$PATH` via `/usr/bin` on install accepts the following arguments.

```
-b --baddr => The address to bind/look for.
-B --bport => The port to bind/look for.
-d --daddr => The destination address.
-D --dport => The destination port.
-p --protocol => The protocol (either "tcp", "udp", "icmp", or unset for all).
```

This will add a forwarding rule while the XDP program is running. As of right now, it does **not** save this rule into the XDP config file. However, I will be implementing save functionality before release.

### XDP Delete Program
The `xdpfwd-del` executable which is added to the `$PATH` via `/usr/bin` on install accepts the following arguments.

```
-b --baddr => The address to bind/look for.
-B --bport => The port to bind/look for.
-p --protocol => The protocol (either "tcp", "udp", "icmp", or unset for all).
```

This will delete a forwarding rule while the XDP program is running. As of right now, it does **not** save the results into the XDP config file. However, I will be implementing save functionality before release.

## Configuration
The default config file is located at `/etc/xdpfwd/xdpfwd.conf` and uses the `libconfig` syntax. Here's an example config using all of its current features.

```
interface = "ens18"; // The interface the XDP program attaches to.

// Forwarding rules array.
forwarding = (
    {
        bind = "10.50.0.3",     // The bind address which incoming packets must match.
        bindport = 80,          // The bind port which incoming packets must match.

        protocol = "tcp",       // The protocol (as of right now "udp", "tcp", and "icmp" are supported). Right now, you must specify a protocol. However, in the future I will be implementing functionality so you don't have to and it'll do full layer-3 forwarding.

        dest = "10.50.0.4",     // The address we're forwarding to.
        destport = 8080         // The port we're forwarding to (if not set, will use the bind port).
    },
    ...
);
```

## Credits
* [Christian Deacon](https://github.com/gamemann)