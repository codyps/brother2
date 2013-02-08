#ifndef BRO2_H_
#define BRO2_H_

/* be careful comparing these to (potentially signed) chars, sign extention will occur. */
#define BRO2_MSG_PREFIX 0x1bu
#define BRO2_MSG_SUFFIX 0x80u

#define BRO2_MSG_C_PREFIX '\x1b'
#define BRO2_MSG_C_SUFFIX '\x80'

#define BRO2_PORT_STR "54921"

/* Observed 'C' ("compression") optins */
__attribute__((unused))
static const char *bro2_compression[] = {
	"NONE",		/* noted in usb driver */
	"RLENGTH",
	"JPEG"		/* noted in usb driver */
};

/* Observed 'M' ("Mode") options */
__attribute__((unused))
static const char *bro2_modes[] = {
	"CGRAY",
	"ERRDIF",
	"C256",
	"TEXT",		/* noted in usb driver */
};

/* An I msg responce is composed of 7 numbers. */
#define BRO2_MSG_I_XRES 0
#define BRO2_MSG_I_YRES 1
#define BRO2_MSG_I_UNK0 2

/* Extremely pesimistic line length maximum */
#define BRO2_MAX_LINE_SZ (~(uint16_t)0)
#define BRO2_MAX_LINE_MSG_SZ (BRO2_MAX_LINE_SZ + 3) /* type + 2byte length */

/* Line types */
#define BRO2_LINE_TYPE_GRAY  0x40
#define BRO2_LINE_TYPE_BW    0x42
#define BRO2_LINE_TYPE_RED   0x44
#define BRO2_LINE_TYPE_GREEN 0x48
#define BRO2_LINE_TYPE_BLUE  0x4c

#endif
