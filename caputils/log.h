#ifndef CAPUTILS_LOG_H
#define CAPUTILS_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>

int vlogmsg(FILE* fp, const char* tag, const char* fmt, va_list ap);
int logmsg(FILE* fp, const char* tag, const char* fmt, ...) __attribute__ ((format (printf, 3, 4)));

/**
 * Dump the content of data as hexadecimal (and its ascii repr.)
 */
void hexdump(FILE* fp, const char* data, size_t size);

/**
 * Dump the content of data as hexadecimal (and its ascii repr.) into a string.
 * Memory should be freed with free.
 */
char* hexdump_str(const char* data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_LOG_H */
