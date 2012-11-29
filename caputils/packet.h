#ifndef PACKET_H
#define PACKET_H

#include "capture.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

enum Level {
	LEVEL_INVALID = 0,
	LEVEL_PHYSICAL,
	LEVEL_LINK,
	LEVEL_NETWORK,
	LEVEL_TRANSPORT,
	LEVEL_APPLICATION,     /* not supported yet */
};

enum Level level_from_string(const char* str);

/**
 * Get payload sizes at the various levels.
 */
size_t payload_size(enum Level level, const cap_head* caphead);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_H */
