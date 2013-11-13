## base.mk: 1706e2c, see https://github.com/jmesmon/trifles.git
CCAN_CFLAGS ?= $(C_CFLAGS)

ccan: FORCE
	$(MAKE) $(MAKE_ENV) CCAN_CFLAGS="$(CCAN_CFLAGS)" CCAN_LDFLAGS="$(CCAN_LDFLAGS)" \
		LD="ld" --no-print-directory -C ccan $(MAKEFLAGS)
dirclean: clean
	$(MAKE) $(MAKE_ENV) --no-print-directory -C ccan $(MAKEFLAGS) clean

