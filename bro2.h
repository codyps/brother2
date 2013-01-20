#ifndef BRO2_H_
#define BRO2_H_

#define BRO2_PORT_STR "54921"

/* Observed 'C' ("compression") optins */
__attribute__((unused))
static const char *bro2_compression[] = {
	"NONE",
	"RLENGTH",
	"JPEG"
};

/* Observed 'M' ("Mode") options */
__attribute__((unused))
static const char *bro2_modes[] = {
	"CGRAY",
};


#endif
