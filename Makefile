all::

LIB_LDFLAGS := $(shell net-snmp-config --libs) -Lccan -lccan
LIB_CFLAGS := $(shell net-snmp-config --cflags)

ALL_CFLAGS += -I. -Iccan -DSANE_DLL=SANE_DLL

CCAN_CFLAGS = $(C_CFLAGS) -fPIC -DCCAN_STR_DEBUG=1

obj-libsane-bro2.so = brother2.o sane_strstatus.o
ldflags-libsane-bro2.so = -shared $(LIB_LDFLAGS)
cflags-libsane-bro2.so = -fPIC $(LIB_CFLAGS)

obj-bro2-serv = brother2-serv.o
ldflags-bro2-serv = -lev -Lccan -lccan
cflags-bro2-serv = -fno-strict-aliasing # libev :(

TARGETS = libsane-bro2.so bro2-serv

get-deps:
	apt-get install sane-dev

include base-ccan.mk
include base.mk
$(obj-all) : ccan
