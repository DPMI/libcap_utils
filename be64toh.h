#ifndef __WORKAROUND_BE64TOH_H
#define __WORKAROUND_BE64TOH_H

#include <stdint.h>

#ifdef HAVE_BE64TOH
#include <endian.h>
#else
extern "C" uint64_t htobe64(uint64_t host_64bits);
extern "C" uint64_t be64toh(uint64_t big_endian_64bits);
#endif

#endif /* __WORKAROUND_BE64TOH_H */
