#define BACKEND_NAME bro2

#include <stddef.h>
#include <sane/sane.h>
#include <sane/saneopts.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "tcp.h"
#include "bro2.h"

#define ARRAY_SZ(a) (sizeof(a) / sizeof(a[0]))

#ifndef NDEBUG
#include <stdio.h>
#define pr_debug(...) fprintf(stderr, __VA_ARGS__)
#define DBG(n, ...) fprintf(stderr, __VA_ARGS__)
#else
#define pr_debug(...)
#define DBG(n, ...)
#endif

static SANE_Auth_Callback auth;

struct bro2_device {
	int fd;
	const char *addr;
	struct addrinfo *res;

	/* settings */
	int x_res, y_res;
	int lt_x, lt_y, br_x, br_y;
	const char *mode, *d, *compression;
	int brightness, contrast;
};

SANE_Status sane_init(SANE_Int *ver, SANE_Auth_Callback authorize)
{
	if (ver)
		ver = 0;
	auth = authorize;
	return SANE_STATUS_GOOD;
}

void sane_exit(void)
{}

/* return an empty list of detected devices */
static SANE_Device *_device_list = NULL, **device_list = &_device_list;
SANE_Status sane_get_devices(const SANE_Device ***dev_list,
			     SANE_Bool local_only)
{
	*dev_list = (const SANE_Device **)device_list;
	pr_debug("GET IT\n");
	return SANE_STATUS_GOOD;
}

static int bro2_connect(struct bro2_device *dev)
{
	/* Hook up the connection */
	struct addrinfo *res;
	int r = tcp_resolve_as_client(dev->addr, BRO2_PORT_STR, &res);

	pr_debug("resolve: %d\n", r);
	if (r) {
		fprintf(stderr, "failed to resolve %s: %s\n",
				dev->addr, gai_strerror(r));
		return -1;
	}

	int fd = tcp_connect(res);

	dev->fd = fd;
	dev->res = res;

	if (fd == -1) {
		fprintf(stderr, "failed to connect to %s: %s\n",
				dev->addr, strerror(r));
		return -2;
	}
	return 0;
}

static void bro2_init(struct bro2_device *dev, const char *addr)
{
	memset(dev, 0, sizeof(*dev));

	dev->fd = -1;
	dev->addr = addr;

	/* set some default values */
	dev->x_res = dev->y_res = 300;
	dev->mode = "CGREY";
	dev->d = "SIN";
	dev->compression = "NONE";
	dev->brightness = dev->contrast = 50;
}

/* Must be called immediately after connecting, status is only sent at that
 * time. */
static int bro2_read_status(struct bro2_device *dev)
{
	char buf[512];
	ssize_t r = read(dev->fd, buf, sizeof(buf) - 1);

	if (r == 0) {
		pr_debug("eof?\n");
		return -1;
	} else if (r == -1) {
		pr_debug("error?\n");
		return -1;
	}

	buf[r] = '\0';

	if (r <= 4 || strncmp("+OK ", buf, 4)) {
		DBG(1, "Not a status string : \"%.*s\"\n", (int)r, buf);
		return -1;
	}

	char *end;
	errno = 0;
	long it = strtol(buf + 4, &end, 10);

	if (errno) {
		DBG(1, "Could not get number.\n");
		return -2;
	}

	if (it < 0) {
		DBG(1, "negative status??\n");
	}

	if (strncmp("\r\n", end, 2)) {
		DBG(1, "not terminated properly.\n");
		return -1;
	}

	return it;
}

static int bro2_send_I(struct bro2_device *dev)
{
	char buf[512];
	int l = snprintf(buf, sizeof(buf),
			"\x1bI\n"
			"R=%u,%u\n"
			"M=%s\n"
			"\x80",
			dev->x_res, dev->y_res, dev->mode);

	if (l > sizeof(buf)) {
		DBG(1, "too much for buffer.\n");
		return -1;
	}

	ssize_t r = write(dev->fd, buf, l);
	if (r != l) {
		DBG(1, "write failed.\n");
		return -1;
	}

	return 0;
}

/* Parses a comma seperated list of integers, which is terminated by
 * a newline or the end of the buffer */
static int parse_num_list(void const *v_buf, size_t buf_bytes, int *nums,
		size_t num_ct, char **end)
{
	char const *buf = v_buf;
	int n = 0, i = 0, p = 0;
	while (p < buf_bytes && i < num_ct) {
		int c = buf[p];
		p++;

		if (c == ',') {
			nums[i] = n;
			i ++;
			n = 0;
			continue;
		}

		if (c == '\n') {
			break;
		}

		if (!isdigit(c)) {
			DBG(1, "killed on a %x '%c' (%d %zu) \n", c, c, p, buf_bytes);
			return -1;
		}

		n *= 10;
		n += c - '0';
	}

	if (i < num_ct) {
		nums[i] = n;
		i++;
	}

	*end = (char *)buf + p;

	return i;
}

static void hex_dump(char *buf, size_t buf_len) {
	int i;
	for (i = 0; i < buf_len; i++) {
		if (!iscntrl(buf[i])) {
			fprintf(stderr, " %c ", buf[i]);
		} else {
			fprintf(stderr, "%02X ", buf[i]);
		}
	}
	putchar('\n');
}

static int bro2_recv_I_response(struct bro2_device *dev)
{
	char buf[512];
	ssize_t l = read(dev->fd, buf, sizeof(buf) - 1);

	if (l <= 0) {
		DBG(1, "error in read\n");
		return -1;
	}

	hex_dump(buf, l);

#if 0
	if (buf[l-1] != 0x80) {
		DBG(1, "wrong terminator: %c %x\n", buf[l-1], buf[l-1]);
		return -1;
	}
#endif
	buf[l] = '\0';

	if (buf[0] != 0x1b) {
		DBG(1, "wrong start: %c %x\n", buf[0], buf[0]);
		return -1;
	}

	if (buf[1] != 0x00) {
		DBG(1, "wrong 2: %c %x\n", buf[1], buf[1]);
		return -1;
	}

	int nums[7];
	char *end;
	int c = parse_num_list(buf + 2, l - 2, nums, 7, &end);
	if (c != 7) {
		DBG(1, "Did not get enough numbers: %d\n", c);
		return -1;
	}

	DBG(1, "Nums: %d %d %d %d %d %d %d\n",
			nums[0],nums[1],nums[2],nums[3],nums[4],nums[5],nums[6]);

	if (end != buf + l) {
		DBG(1, "end doesn't match up.\n");
		return -1;
	}

	return 0;
}

#define STR(x) STR_(x)
#define STR_(x) #x
#define NAME_PREFIX STR(BACKEND_NAME) ":"
#define NAME_PREFIX_LEN (ARRAY_SZ(NAME_PREFIX) - 1)

SANE_Status sane_open(SANE_String_Const name, SANE_Handle *h)
{
	if (strncmp(NAME_PREFIX, name, NAME_PREFIX_LEN)) {
		return SANE_STATUS_INVAL;
	}

	const char *n = name + NAME_PREFIX_LEN;
	/* welp, what type of device do we have here? */
	/* FIXME: right now, IP address is assumed. */

	struct bro2_device *dev = malloc(sizeof(*dev));
	*h = dev;

	bro2_init(dev, n);
	int r = bro2_connect(dev);
	if (r)
		return SANE_STATUS_INVAL;

	r = bro2_read_status(dev);
	if (r != 200) {
		pr_debug("Funky status code: %d\n", r);
	}

	return SANE_STATUS_GOOD;
}

void sane_close(SANE_Handle h)
{}

#define SANE_STR(thing)		\
	.name = SANE_NAME_##thing,	\
	.title = SANE_TITLE_##thing,	\
	.desc = SANE_DESC_##thing

static SANE_Range range_percent = {
	.min = 0,
	.max = 100,
	.quant = 1
};

enum opts {
	OPT_MODE,
	OPT_X_RES,
	OPT_Y_RES,
	OPT_TL_X,
	OPT_TL_Y,
	OPT_BR_X,
	OPT_BR_Y,
	OPT_B,
	OPT_C,
	OPT_COMPRESS,
	OPT_D
};

#define OPT_PX_CORD(it)				\
	SANE_STR(SCAN_##it),			\
	.type = SANE_TYPE_INT,			\
	.unit = SANE_UNIT_PIXEL,		\
	.constraint_type = SANE_CONSTRAINT_NONE

static SANE_Option_Descriptor mfc7820n_opts [] = {
	{
		SANE_STR(SCAN_MODE),
		/* ERRDIF or CGRAY or TEXT */
		.type = SANE_TYPE_STRING,
		.unit = SANE_UNIT_NONE,
		.size = 0,
		.cap = 0,
		.constraint_type = SANE_CONSTRAINT_NONE,
	}, {
		SANE_STR(SCAN_X_RESOLUTION),
		/* 300, ??? */
		.type = SANE_TYPE_INT,
		.unit = SANE_UNIT_DPI,
		.size = sizeof(SANE_Int),
		.cap = 0,
		.constraint_type = SANE_CONSTRAINT_NONE,
	}, {
		SANE_STR(SCAN_Y_RESOLUTION),
		.type = SANE_TYPE_INT,
		.unit = SANE_UNIT_DPI,
		.size = sizeof(SANE_Int),
		.cap = 0,
		.constraint_type = SANE_CONSTRAINT_NONE,
	}, {
		OPT_PX_CORD(TL_X),
	}, {
		OPT_PX_CORD(TL_Y),
	}, {
		OPT_PX_CORD(BR_X),
	}, {
		OPT_PX_CORD(BR_Y),
	}, {
		SANE_STR(BRIGHTNESS),
		.type = SANE_TYPE_INT,
		.unit = SANE_UNIT_NONE,
		.size = sizeof(SANE_Int),
		.cap = 0,
		.constraint_type = SANE_CONSTRAINT_RANGE,
		.constraint = { .range = &range_percent }
	}, {
		SANE_STR(CONTRAST),
		.type = SANE_TYPE_INT,
		.unit = SANE_UNIT_NONE,
		.size = sizeof(SANE_Int),
		.cap = 0,
		.constraint_type = SANE_CONSTRAINT_RANGE,
		.constraint = { .range = &range_percent }
	}, {
		.name = "compession",
		.title = "Image Compression Type",
		.desc = "Image Compression Type. NONE or RLENGTH.",
		.type = SANE_TYPE_STRING,
		.unit = SANE_UNIT_NONE,
		.size = 0,
		.cap = 0,
		.constraint_type = SANE_CONSTRAINT_NONE,
	}, {
		.name = "D",
		.title = "D value",
		.desc = "The D value. Only \"SIN\" has been observed.",
		.type = SANE_TYPE_STRING,
		.unit = SANE_UNIT_NONE,
		.size = 0,
		.cap = 0,
		.constraint_type = SANE_CONSTRAINT_NONE,
	}
};

static SANE_Option_Descriptor num_opts_opt = {
	.name = "",
	.title = SANE_TITLE_NUM_OPTIONS,
	.desc = SANE_DESC_NUM_OPTIONS,
	.type = SANE_TYPE_INT,
	.unit = SANE_UNIT_NONE,
	.size = sizeof(SANE_Word),
	.cap = SANE_CAP_SOFT_DETECT,
	.constraint_type = SANE_CONSTRAINT_NONE,
	.constraint = { .range = 0 },
};
const SANE_Option_Descriptor *sane_get_option_descriptor(SANE_Handle h, SANE_Int n)
{
	if (n == 0)
		return &num_opts_opt;

	n--;

	if (n < ARRAY_SZ(mfc7820n_opts)) {
		return &mfc7820n_opts[n];
	}

	return NULL;
}

SANE_Status sane_control_option(SANE_Handle h, SANE_Int n, SANE_Action a, void *v, SANE_Int *i)
{
	/* XXX: TODO: */
	switch (a) {
	case SANE_ACTION_GET_VALUE:
		if (!n) {
			SANE_Int *r = v;
			*r = ARRAY_SZ(mfc7820n_opts);
			return SANE_STATUS_GOOD;
		}

		n--;
		break;
	case SANE_ACTION_SET_VALUE:
		break;
	case SANE_ACTION_SET_AUTO:
		break;
	}

	return SANE_STATUS_IO_ERROR;
}

SANE_Status sane_get_parameters(SANE_Handle h, SANE_Parameters *p)
{
	p->lines = -1; /* we don't know */
	//p->depth = ;
	//p->bytes_per_line = ;
	//p->pixels_per_line = ;
	return SANE_STATUS_IO_ERROR;
}

SANE_Status sane_start(SANE_Handle h)
{
#if 0
SANE STATUS CANCELLED: The operation was cancelled through a call to sane cancel.
SANE STATUS DEVICE BUSY: The device is busy. The operation should be retried later.
SANE STATUS JAMMED: The document feeder is jammed.
SANE STATUS NO DOCS: The document feeder is out of documents.
SANE STATUS COVER OPEN: The scanner cover is open.
SANE STATUS IO ERROR: An error occurred while communicating with the device.
SANE STATUS NO MEM: An insufficent amount of memory is available.
SANE STATUS INVAL: The scan cannot be started with the current set of options. The fron-
tend should reload the option descriptors, as if SANE INFO RELOAD OPTIONS had been
returned from a call to sane control option(), since the device’s capabilities may
have changed.
#endif

	struct bro2_device *dev = h;
	/* negotiate parameters */
	int r = bro2_send_I(dev);

	if (r) {
		DBG(1, "send I failed\n");
		return SANE_STATUS_IO_ERROR;
	}

	r = bro2_recv_I_response(dev);
	if (r) {
		DBG(1, "handle I resp failed\n");
		return SANE_STATUS_IO_ERROR;
	}

	return SANE_STATUS_IO_ERROR;
}

SANE_Status sane_read(SANE_Handle h, SANE_Byte *buf, SANE_Int maxlen, SANE_Int *len)
{
#if 0
SANE STATUS CANCELLED: The operation was cancelled through a call to sane cancel.
SANE STATUS EOF: No more data is available for the current frame.
SANE STATUS JAMMED: The document feeder is jammed.
SANE STATUS NO DOCS: The document feeder is out of documents.
SANE STATUS COVER OPEN: The scanner cover is open.
SANE STATUS IO ERROR: An error occurred while communicating with the device.
SANE STATUS NO MEM: An insufficent amount of memory is available.
SANE STATUS ACCESS DENIED: Access to the device has been denied due to insufficient
or invalid authentication.
#endif
	return SANE_STATUS_IO_ERROR;
}

void sane_cancel(SANE_Handle h)
{}

SANE_Status sane_set_io_mode(SANE_Handle h, SANE_Bool m)
{
#if 0
SANE STATUS INVAL: No image acquisition is pending.
SANE STATUS UNSUPPORTED: The backend does not support the requested I/O mode.
#endif
	return SANE_STATUS_UNSUPPORTED;
}

SANE_Status sane_get_select_fd(SANE_Handle h, SANE_Int *fd)
{
#if 0
SANE STATUS INVAL: No image acquisition is pending.
SANE STATUS UNSUPPORTED: The backend does not support this operation.
#endif
	return SANE_STATUS_UNSUPPORTED;
}


