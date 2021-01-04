# Patches To Kernel 5.10.1
## Description
This directory includes two patches (`bpf.patch` and `verifier.patch`). These patches raise the limits of the maximum BPF program size (`bpf.patch`) and max jump sequences (`verifier.patch`). I made these patches with Linux kernel 5.10.1 which can be found [here](https://cdn.kernel.org/pub/linux/kernel/v5.x/). 

A good guide on compiling your own Linux kernel into `.deb` files can be found [here](https://www.linode.com/docs/guides/custom-compiled-kernel-debian-ubuntu/) for Ubuntu/Debian. You can then install the kernel via `dpkg -i *.deb` after finished. Additionally, I found the command `make bindeb-pkg -j <core count>` to be useful if you're recompiling the kernel after the first time since `make deb-pkg -j <core count>` performs `make clean` which results in the building process taking a lot longer. 

Sadly, the XDP Forwarding program will not work with > 20 source ports per bind address without these modifications to the Linux kernel since I was running into limitations no matter what I tried.

## Limitations
If you want to increase these limitations manually, you'll need to raise `BPF_COMPLEXITY_LIMIT_JMP_SEQ` constant from within the `kernel/bpf/verifier.c` [file](https://elixir.bootlin.com/linux/latest/source/kernel/bpf/verifier.c#L178). This raises the max jump sequences limitation.

Secondly, you'll need to raise the `BPF_COMPLEXITY_LIMIT_INSNS` constant from within the `include/linux/bpf.h` [file](https://elixir.bootlin.com/linux/v5.10.1/source/include/linux/bpf.h#L964). This increases the maximum BPF program size to my understanding.