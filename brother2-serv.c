#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <ev.h>

#include "tcp.h"
#include "bro2.h"

struct peer {
	ev_io w;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	char buf[128];
	size_t pos;
};

static void peer_scan_buf_for_start_byte(struct peer *p)
{
	size_t i;
	for (i = 0; i < p->pos; i++) {
		if (p->buf[i] == BRO2_MSG_PREFIX)
			break;
	}

	if (i != 0) {
		fprintf(stderr, "discarding %zu input bytes.\n", i);
	}

	memmove(p->buf, &p->buf[i], p->pos - i);
}

static ssize_t peer_scan_buf_for_end_byte(struct peer *p)
{
	size_t i;
	for (i = 1; i < p->pos; i++) {
		if (p->buf[i] == BRO2_MSG_SUFFIX)
			return i;
	}

	return -1;
}

static const char hex_lookup[] = "0123456789abcdef";
static void print_hex_byte(uint8_t byte, FILE *f)
{
	putc(hex_lookup[byte >> 4], f);
	putc(hex_lookup[byte & 0x0f], f);
}

static void print_bytes_as_cstring(void *data, size_t data_len, FILE *f)
{
	putc('"', f);
	char *p = data;
	size_t i;
	for (i = 0; i < data_len; i++) {
		char c = p[i];
		if (iscntrl(c) || !isprint(c)) {
			switch (c) {
			case '\n':
				putc('\\', f);
				putc('n', f);
				break;
			case '\r':
				putc('\\', f);
				putc('r', f);
				break;
			default:
				putc('\\', f);
				putc('x', f);
				print_hex_byte(c, f);
			}
		} else  {
			switch (c) {
			case '"':
			case '\\':
				putc('\\', f);
			default:
			}
			putc(c, f);
		}
	}
	putc('"', f);
}

static int peer_ct;
static void peer_cb(EV_P_ ev_io *w, int revents)
{
	fprintf(stderr, "Peer cb\n");
	struct peer *peer= (struct peer *)w;
	ssize_t r = read(w->fd, peer->buf + peer->pos, sizeof(peer->buf) - peer->pos);
	if (r == 0) {
		fprintf(stderr, "peer disconnected.\n");
		goto close_con;
	} else if (r < 0) {
		fprintf(stderr, "probably a bug: %zd %s\n", r, strerror(errno));
		goto close_con;
	}

	fprintf(stderr, "recved %zd bytes: ", r);
	print_bytes_as_cstring(peer->buf + peer->pos, r, stderr);
	peer->pos += r;
	fprintf(stderr, "\npeer buffer is: ");
	print_bytes_as_cstring(peer->buf, peer->pos, stderr);
	putc('\n', stderr);

	peer_scan_buf_for_start_byte(peer);

	if (peer->buf[0] == BRO2_MSG_PREFIX) {
		ssize_t p = peer_scan_buf_for_end_byte(peer);
		if (p > 0) {
			/* we have a complete message */
			fprintf(stderr, "WOULD PARSE MESSAGE.\n");
		} else {
			/* not complete, check if we have more room */
			fprintf(stderr, "Message not complete.\n");
			if (sizeof(peer->buf) == peer->pos) {
				fprintf(stderr, "ran out of buffer space.\n");
				goto close_con;
			}
		}
	}
	return;
close_con:
	peer_ct --;
	ev_io_stop(EV_A_ w);
	close(w->fd);
	free(peer);
}


static struct peer *accept_peer;
static void accept_cb(EV_P_ ev_io *w, int revents)
{
	for(;;) {
		if (!accept_peer) {
			accept_peer = malloc(sizeof(*accept_peer));
			memset(accept_peer, 0, sizeof(*accept_peer));
			accept_peer->addr_len = sizeof(accept_peer->addr);
		}

		int fd = accept(w->fd, (struct sockaddr *)&accept_peer->addr,
				&accept_peer->addr_len);
		if (fd == -1) {
			switch (errno) {
			case EBADF:
			case ENOTSOCK:
			case EINVAL:
			case EMFILE:
			case ENFILE:
			case ENOBUFS:
			case ENOMEM:
			case EPROTO:
			default:
				/* DIE A HORRIBLE DEATH */
				fprintf(stderr, "listener recieved error, exiting: %s\n", strerror(errno));
				ev_break(EV_A_ EVBREAK_ONE);
				return;
			case ECONNABORTED:
			case EINTR:
				continue;
			case EAGAIN:
				return;
			}
		}

		if (peer_ct == 0) {
			peer_ct ++;
			write(fd, "+OK 200\r\n", 9);
			ev_io_init(&accept_peer->w, peer_cb, fd, EV_READ);
			ev_io_start(EV_A_ &accept_peer->w);
			accept_peer = NULL;
		} else {
			write(fd, "-NG 401\r\n", 9);
			close(fd);
		}
	}
}

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

	freeaddrinfo(res);

	r = listen(fd, 128);
	if (r == -1) {
		fprintf(stderr, "could not listen.\n");
		return 1;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		fprintf(stderr, "could not get flags.\n");
		return 1;
	}

	r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (r == -1) {
		fprintf(stderr, "could not set flags.\n");
		return 1;
	}

	flags = 1;
	r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
	if (r == -1) {
		fprintf(stderr, "could not set sockopt.\n");
	}

	ev_io accept_listener;
	ev_io_init(&accept_listener, accept_cb, fd, EV_READ);
	ev_io_start(EV_DEFAULT_ &accept_listener);

	ev_run(EV_DEFAULT_ 0);

	return 0;
}
