#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>

#include "tcp.h"
#include "bro2.h"

int main(int argc, char **argv)
{
	const char *bind_addr = NULL, *port = BRO2_PORT_STR;
	int opt;

	while ((opt = getopt(argc, argv, "a:p:")) != -1) {
		switch (opt) {
		case 'a':
			bind_addr = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default: /* '?' */
			fprintf(stderr, "usage: %s [-a bind_addr] [-p bind_port]\n",
					argv[0]);
			return 1;
		}
	}

	struct addrinfo *res;
	int r = tcp_resolve_listen(bind_addr, port, &res);
	if (r) {
		fprintf(stderr, "could not resolve %s: %s\n", bind_addr, gai_strerror(r));
		return 1;
	}

	int fd = tcp_bind(res);
	if (fd == -1) {
		fprintf(stderr, "could not bind to addr %s, port %s: %s\n", bind_addr, port, strerror(errno));
		return 1;
	}

	/* TODO: accept loop */
	return 0;
}
