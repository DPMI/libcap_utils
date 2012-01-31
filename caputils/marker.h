#ifndef CAPUTILS__MARKER_H
#define CAPUTILS__MARKER_H

#include <stdint.h>

enum MarkerFlags {
	MARKER_TERMINATE = (1<<0),
};

struct marker {
	uint32_t magic;
	uint8_t version;
	uint8_t flags;
	uint16_t reserved;

	uint32_t exp_id;
	uint32_t run_id;
	uint32_t key_id;
	uint32_t seq_num;
	uint64_t starttime;
	uint64_t stoptime;

	/* timeval depttime; */
} __attribute__((packed));

#endif /* CAPUTILS__MARKER_H */
