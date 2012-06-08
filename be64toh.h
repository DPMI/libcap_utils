#ifndef __WORKAROUND_BE64TOH_H
#define __WORKAROUND_BE64TOH_H

#include <stdint.h>

#ifdef HAVE_BE64TOH
#include <endian.h>
#else

#ifdef __cplusplus
extern "C" {
#endif

uint64_t htobe64(uint64_t val) __attribute__((alias("_int_htobe64")));
uint64_t be64toh(uint64_t val) __attribute__((alias("_int_be64toh")));

#ifdef __cplusplus
}
#endif

#endif /* HAVE_BE64TOH */

#endif /* __WORKAROUND_BE64TOH_H */
