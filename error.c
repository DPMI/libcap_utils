#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils_int.h"
#include <string.h>

static const char* errstr[MAX_ERRORS - 0x80000000] = {
  /* __UNUSED */ NULL,

  /* ERROR_CAPFILE_INVALID   */ "not a valid capfile.",
  /* ERROR_CAPFILE_TRUNCATED */ "file is truncated.",

  /* ERROR_INVALID_PROTOCOL */  "unsupported protocol",
  /* ERROR_NOT_IMPLEMENTED */   "feature not implemented.",
};

const char* caputils_error_string(int code){
  if ( code & 0x80000000 ){
    return errstr[code^0x80000000];
  } else {
    return strerror(code);
  }
}
