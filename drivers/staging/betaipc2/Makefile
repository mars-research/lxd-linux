obj-m := test.o
#CFLAGS_test.o = -DDEBUG -DDEBUG_MWAIT_RETRY  -DTIMING -g -Wall
#CFLAGS_betaModule2.o = -DDEBUG -DDEBUG_MWAIT_RETRY  -DTIMING -g -Wall
#CFLAGS_ring-channel.o = -DDEBUG -DDEBUG_MWAIT_RETRY -DTIMING -g -Wall

CFLAGS_test.o = -O2 -DTIMING
CFLAGS_betaModule2.o = -O2 -DTIMING
CFLAGS_ring-channel.o = -O2


test-objs := ./ring-chan/ring-channel.o ./betaModule2.o

KDIR := /lib/modules/`uname -r`/build

default:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
