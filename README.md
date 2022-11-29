# XDP Forwarding
[![XDP Forwarding Build Workflow](https://github.com/gamemann/XDP-Forwarding/actions/workflows/build.yml/badge.svg)](https://github.com/gamemann/XDP-Forwarding/actions/workflows/build.yml) [![XDP Forwarding Run Workflow](https://github.com/gamemann/XDP-Forwarding/actions/workflows/run.yml/badge.svg)](https://github.com/gamemann/XDP-Forwarding/actions/workflows/run.yml)

## Description
A program that attaches to the Linux kernel's [XDP](https://www.iovisor.org/technology/xdp) hook through [(e)BPF](https://ebpf.io/) for fast packet processing and performs basic layer 3/4 forwarding. This program does source port mapping similar to IPTables and NFTables for handling connections. Existing connections are prioritized based off of the connection's packets per nanosecond. This means on port exhaustion, connections with the least packets per nanosecond will be replaced. I believe this is best since connections with higher packets per nanosecond will be more sensitive.

Additionally, if the host's network configuration or network interface card (NIC) doesn't support the XDP DRV hook (AKA native; occurs before [SKB creation](http://vger.kernel.org/~davem/skb.html)), the program will attempt to attach to the XDP SKB hook (AKA generic; occurs after SKB creation which is where IPTables and NFTables are processed via the `netfilter` kernel module). You may use overrides through the command-line to force SKB or offload modes.

With that said, reasons for a host's network configuration not supporting XDP's DRV hook may be the following.

* Running an outdated kernel that doesn't support your NIC's driver.
* Your NIC's driver not yet being supported. [Here's](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp) a NIC driver XDP support list. With enough Linux kernel development knowledge, you could try implementing XDP DRV support into your non-supported NIC's driver (I'd highly recommend giving [this](https://www.youtube.com/watch?v=ayFWnFj5fY8) video a watch!).
* You don't have enough RX/TX queues (e.g. not enabling multi-queue) or your RX/TX queue counts aren't matching. From the information I gathered, it's recommended to have one RX and TX queue per CPU core/thread. You could try learning how to use [ethtool](https://man7.org/linux/man-pages/man8/ethtool.8.html) and try altering the NIC's RX/TX queue settings ([this](https://www.linode.com/docs/guides/multiqueue-nic/) article may be helpful!).

I hope this project helps existing network engineers/programmers interested in utilizing XDP or anybody interested in getting into those fields! High performing routers/packet forwarding and (D)DoS mitigation/prevention are such important parts of Cyber Security and understanding the concept of networking and packet flow on a low-medium level would certainly help those who are pursuing a career in the field 🙂

**WARNING** - There are still many things that need to be done to this project and as of right now, it only supports IPv4. IPv6 support will be added before official release. As of right now, the program may include bugs and forwarding features aren't yet available.

## Limitations
The default maximum source ports that can be used per bind address is **21** and is set [here](https://github.com/gamemann/XDP-Forwarding/blob/master/src/xdpfwd.h#L8) (you may adjust these if you'd like). We use port range **500** - **520** by default, but this can be configured.

At first, I was trying to use most available ports (1 - 65534). However, due to BPF verifier limitations, I had to raise a couple constants inside the Linux kernel and recompile the kernel. I made patches for these and have everything documented [here](https://github.com/gamemann/XDP-Forwarding/tree/master/patches). I am able to run the program with 65534 max ports per bind address without any issues with the custom kernel I built using the patches I made. Though, keep in mind, the more source ports there are available, the more processing the XDP program will have to do when checking for available ports.

If you plan to use this for production, I'd highly suggest compiling your own kernel with the constants raised above. 21 maximum source ports per bind address is not much, but unfortunately, the default BPF verifier restrictions don't allow us to go any further currently.

The main code that causes these limitations is located [here](https://github.com/gamemann/XDP-Forwarding/blob/master/src/xdp_prog.c#L536) and occurs when we're trying to find the best source port to use for a new connection. There's really no other way to check for the best source port available with the amount of flexibility we have to my understanding since we must loop through all source ports and check the packets per nanosecond value (BPF maps search by key).

## Requirements
### Packages
You will need `make`, `clang`, `libelf`, and `llvm` since we use these packages to build the project. Additionally, you will also need `libconfig` (`libconfig-dev` is the package on Ubuntu/Debian systems) for parsing the config file.

For Ubuntu/Debian, the following should work.

```
apt install build-essential make clang libelf-dev llvm libconfig-dev
```

I'd assume package names are similar on other Linux distros.

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
-t --time => The amount of time in seconds to run the program for. Unset or 0 = infinite.
-c --config => Location to XDP Forward config (default is /etc/xdpfwd/xdpfwd.conf).
-l --list => List all forwarding rules.
-h --help => Print out command line usage.
```

### Offload Information
Offloading your XDP/BPF program to your system's NIC allows for the fastest packet processing you can achieve due to the NIC processing/forwarding the packets with its hardware. However, there are **not** many NIC manufacturers that do support this feature **and** you're limited to the NIC's memory/processing (e.g. your BPF map sizes will be extremely limited). Additionally, there are usually stricter BPF verifier limitations for offloaded BPF programs, but you may try reaching out to the NIC's manufacturer to see if they will give you a special version of their NIC driver raising these limitations (this is what I did with one manufacturer I used).

As of this time, I am not aware of any NIC manufacturers that will be able to offload this tool completely to the NIC due to its BPF complexity and loop requirements. To be honest, in the current networking age, I believe it's best to leave offloaded programs to BPF map lookups and minimum packet inspection. For example, a simple BPF layer 2 route table map lookup and then *TX* the packets back out of the NIC. However, XDP is still very new and I would imagine we're going to see these limitations loosened or lifted in the next upcoming years. This is why I added support for offload mode into this program. 

### XDP Add Program
The `xdpfwd-add` executable which is added to the `$PATH` via `/usr/bin` on install accepts the following arguments.

```
-b --baddr => The address to bind/look for.
-B --bport => The port to bind/look for.
-d --daddr => The destination address.
-D --dport => The destination port.
-p --protocol => The protocol (either "tcp", "udp", "icmp", or unset for all).
-a --save => Save rule to config file.
```

This will add a forwarding rule while the XDP program is running.

### XDP Delete Program
The `xdpfwd-del` executable which is added to the `$PATH` via `/usr/bin` on install accepts the following arguments.

```
-b --baddr => The address to bind/look for.
-B --bport => The port to bind/look for.
-p --protocol => The protocol (either "tcp", "udp", "icmp", or unset for all).
-a --save => Remove rule from config file.
```

This will delete a forwarding rule while the XDP program is running.

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
