#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils_int.h"
#include <string.h>

static const char* errstr[ERROR_LAST - ERROR_FIRST] = {
  /* ERROR_FIRST */ NULL,

  /* ERROR_CAPFILE_INVALID   */ "not a valid capfile.",
  /* ERROR_CAPFILE_TRUNCATED */ "file is truncated.",

  /* ERROR_INVALID_PROTOCOL */  "unsupported protocol",
  /* ERROR_INVALID_HWADDR */    "failed to parse hwaddr",
  /* ERROR_INVALID_HWADDR_MULTICAST */ "invalid hwaddr: not multicast",
  /* ERROR_INVALID_IFACE */     "invalid interface",
  /* ERROR_BUFFER_LENGTH */     "read buffer must be greater than MTU",

  /* ERROR_NOT_IMPLEMENTED */   "feature not implemented.",
};

const char* caputils_error_string(int code){
	if ( code == -1 ){
		return "stream eof\n";
	} else if ( code & ERROR_FIRST ){
    return errstr[code^ERROR_FIRST];
  } else {
    return strerror(code);
  }
}
