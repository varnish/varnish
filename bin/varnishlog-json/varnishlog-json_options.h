#include "vapi/vapi_options.h"
#include "vut_options.h"

#define JSON_OPT_a							\
	VOPT("a", "[-a]", "Append to file",				\
	    "When writing output to a file with the -w option, append"	\
	    " to it rather than overwrite it. This option has no"	\
	    " effect without the -w option."				\
	)

#define JSON_OPT_g							\
	VOPT("g:", "[-g <probe|request|vxid>]",				\
	    "Grouping mode (default: vxid)",				\
	    "The grouping of transactions. The default is to group"	\
	    " by vxid."							\
	)

#define JSON_OPT_p							\
	VOPT("p", "[-p]", "Pretty-print",				\
	    "Pretty-print transactions rather than using NDJSON"	\
	)

#define JSON_OPT_w							\
	VOPT("w:", "[-w <filename>]", "Output filename",		\
	    "Redirect output to file. The file will be overwritten"	\
	    " unless the -a option was specified. If the application"	\
	    " receives a SIGHUP in daemon mode the file will be"	\
	    " reopened allowing the old one to be rotated away. This"	\
	    " option is required when running in daemon mode. If the"	\
	    " filename is -, varnishlog-json writes to the standard"	\
	    " output and cannot work as a daemon."			\
	)

JSON_OPT_a
VSL_OPT_b
VSL_OPT_c
VSL_OPT_C
VUT_OPT_d
VUT_GLOBAL_OPT_D
#ifdef VSL_OPT_E
VSL_OPT_E
#endif
JSON_OPT_g
VUT_OPT_h
VSL_OPT_i
VSL_OPT_I
VUT_OPT_k
VSL_OPT_L
VUT_OPT_n
JSON_OPT_p
VUT_GLOBAL_OPT_P
#ifdef VUT_OPT_Q
VUT_OPT_Q
#endif
VUT_OPT_q
VUT_OPT_r
VSL_OPT_R
VUT_OPT_t
VSL_OPT_T
VUT_GLOBAL_OPT_V
JSON_OPT_w
VSL_OPT_x
VSL_OPT_X
