#ifndef CAPUTILS__MARKER_H
#define CAPUTILS__MARKER_H

#include <stdint.h>
#include <caputils/capture.h>

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
	uint64_t timestamp;
	char comment[64];

	/* timeval depttime; */
} __attribute__((packed));

/**
 * Test if packet is a marker packet.
 * If port is non-zero an additional test is made to ensure the marker was sent
 * on the given port. If zero the marker is searched for on any port. For
 * reliable usage a port should always be given.
 *
 * It returns the port the marker was detected on or 0 if packet wasn't a
 * marker. ptr is undefined if packet isn't a marker.
 */
int is_marker(struct cap_header* cp, struct marker* ptr, int port);

#endif /* CAPUTILS__MARKER_H */
