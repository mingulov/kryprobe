# kcrypto_fixture kbuild (TEST ONLY, see README.md).
#
# Out-of-tree build against the exact guest kernel build tree:
#   make KDIR=<headers/usr/src/linux-headers-...> [KCFLAGS=-g]
# pahole BTF stamping (needs the matching vmlinux, see README):
#   pahole -J --btf_base <vmlinux> kcrypto_fixture.ko
obj-m += kcrypto_fixture.o
kcrypto_fixture-objs := provider.o consumer.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
