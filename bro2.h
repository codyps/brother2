#ifndef BRO2_H_
#define BRO2_H_

#define BRO2_MSG_PREFIX 0x1b
#define BRO2_MSG_SUFFIX 0x80

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


#endif
