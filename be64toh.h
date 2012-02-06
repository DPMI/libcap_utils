#ifndef __WORKAROUND_BE64TOH_H
#define __WORKAROUND_BE64TOH_H

#include <stdint.h>

#ifdef HAVE_BE64TOH
#include <endian.h>
#else

#ifdef __cplusplus
extern "C" {
#endif

void htobe64() __attribute__((weak, alias ("_int_htobe64")));
void be64toh() __attribute__((weak, alias ("_int_be64toh")));

#ifdef __cplusplus
}
#endif

#endif /* HAVE_BE64TOH */

#endif /* __WORKAROUND_BE64TOH_H */
