LIBBPFSRC = libbpf/src

LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/str_error.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/xsk.o

LOADEROBJS += src/config.o src/cmdline.o
LOADERSRC += src/xdpfwd.c
LOADERFLAGS += -lelf -lz -lconfig

ADDOBJS += src/config.o src/cmdline.o
ADDSRC += src/xdpfwd-add.c

DELOBJS += src/config.o src/cmdline.o
DELSRC += src/xdpfwd-del.c

UTILSOBJ += src/utils.o
UTILSSRC += src/utils.c

all: loader utils xdp_add xdp_del xdp_prog
loader: libbpf utils $(LOADEROBJS)
	clang -I$(LIBBPFSRC) $(LOADERFLAGS) -O3 -o xdpfwd $(LIBBPFOBJS) $(LOADEROBJS) $(UTILSOBJ)  $(LOADERSRC)
xdp_add: libbpf utils $(ADDOBJS)
	clang -I$(LIBBPFSRC) $(LOADERFLAGS) -O3 -o xdpfwd-add $(LIBBPFOBJS) $(ADDOBJS) $(UTILSOBJ) $(ADDSRC)
xdp_del: libbpf utils $(DELOBJS)
	clang -I$(LIBBPFSRC) $(LOADERFLAGS) -O3 -o xdpfwd-del $(LIBBPFOBJS) $(DELOBJS) $(UTILSOBJ) $(DELSRC)
xdp_prog:
	clang -I$(LIBBPFSRC) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/xdp_prog.c -o src/xdp_prog.bc
	llc -march=bpf -filetype=obj src/xdp_prog.bc -o src/xdp_prog.o
libbpf:
	$(MAKE) -C $(LIBBPFSRC)
utils: libbpf $(LOADEROBJS)
	clang -I$(LIBBPFSRC) -Wno-unused-command-line-argument $(LOADERFLAGS) -c -o $(UTILSOBJ) $(LIBBPFOBJS) $(LOADEROBJS) $(UTILSSRC)
clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	rm -f src/*.o src/*.bc
	rm -f xdpfwd
	rm -f xdpfwd-add
install:
	mkdir -p /etc/xdpfwd
	cp -n xdpfwd.conf.example /etc/xdpfwd/xdpfwd.conf
	cp src/xdp_prog.o /etc/xdpfwd/xdp_prog.o
	cp xdpfwd /usr/bin/xdpfwd
	cp xdpfwd-add /usr/bin/xdpfwd-add
	cp xdpfwd-del /usr/bin/xdpfwd-del
	cp -n xdpfwd.service /etc/systemd/system/
.PHONY: libbpf all
.DEFAULT: all