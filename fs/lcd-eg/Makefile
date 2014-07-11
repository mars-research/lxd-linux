#
# Makefile for the Linux minix filesystem routines in LCD.
#

obj-m += lcd-minix.o

lcd-minix-objs := bitmap.o itree_v1.o itree_v2.o namei.o inode.o file.o dir.o lcdlib.o rwlock.o

ccflags-y := -DLCD_BUILD

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
