all::

obj-libsane-bro2.so = brother2.o penny/tcp.o sane_strstatus.o
libsane-bro2.so : LDFLAGS+= -shared
libsane-bro2.so : CFLAGS+= -fpic

obj-bro2-serv = brother2-serv.o penny/tcp.o
bro2-serv : LDFLAGS+= -lev
bro2-serv : CFLAGS += -fno-strict-aliasing # libev :(

TARGETS = libsane-bro2.so bro2-serv

include base.mk
