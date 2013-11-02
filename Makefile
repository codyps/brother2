all::

LIB_LDFLAGS := $(shell net-snmp-config --libs) -Lccan -lccan
LIB_CFLAGS := $(shell net-snmp-config --cflags)

ALL_CFLAGS += -I. -Iccan

obj-libsane-bro2.so = brother2.o sane_strstatus.o
ldflags-libsane-bro2.so = -shared $(LIB_LDFLAGS)
ldflags-libsane-bro2.so = -fpic $(LIB_CFLAGS)

obj-bro2-serv = brother2-serv.o
bro2-serv : ALL_LDFLAGS+= -lev
bro2-serv : ALL_CFLAGS += -fno-strict-aliasing # libev :(

TARGETS = libsane-bro2.so bro2-serv

include base-ccan.mk
include base.mk
$(obj-all) : ccan
