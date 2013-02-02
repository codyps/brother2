all::

LIB_LDFLAGS := $(shell net-snmp-config --libs)
LIB_CFLAGS := $(shell net-snmp-config --cflags)

obj-libsane-bro2.so = brother2.o penny/tcp.o sane_strstatus.o
libsane-bro2.so : LDFLAGS+= -shared $(LIB_LDFLAGS)
libsane-bro2.so : CFLAGS+= -fpic $(LIB_CFLAGS)

obj-bro2-serv = brother2-serv.o penny/tcp.o
bro2-serv : LDFLAGS+= -lev
bro2-serv : CFLAGS += -fno-strict-aliasing # libev :(

TARGETS = libsane-bro2.so bro2-serv

include base.mk
