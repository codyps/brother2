all::

LIB_LDFLAGS := $(shell net-snmp-config --libs)
LIB_CFLAGS := $(shell net-snmp-config --cflags)

ALL_CFLAGS += -I. -Iccan

obj-libsane-bro2.so = brother2.o sane_strstatus.o
libsane-bro2.so : ALL_LDFLAGS+= -shared $(LIB_LDFLAGS)
libsane-bro2.so : ALL_CFLAGS+= -fpic $(LIB_CFLAGS)

obj-bro2-serv = brother2-serv.o
bro2-serv : ALL_LDFLAGS+= -lev
bro2-serv : ALL_CFLAGS += -fno-strict-aliasing # libev :(

TARGETS = libsane-bro2.so bro2-serv

include ~/trifles/base-ccan.mk
include base.mk
$(obj-all) : ccan
