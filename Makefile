all::

obj-libsane-bro2.so = brother2.o tcp.o sane_strstatus.o
libsane-bro2.so : LDFLAGS+= -shared
libsane-bro2.so : CFLAGS+= -fpic
TARGETS = libsane-bro2.so

include base.mk
