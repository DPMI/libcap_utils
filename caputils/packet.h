#ifndef PACKET_H
#define PACKET_H

#include <caputils/capture.h>

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

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
 * Get payload sizes at the various levels (same as layer_size but excludes header).
 */
size_t payload_size(enum Level level, const cap_head* caphead);

/**
 * Get layer sizes at the various levels (same as payload_size but includes header).
 */
size_t layer_size(enum Level level, const cap_head* caphead);

/**
 * Get IPv4 header from packet.
 *
 * @param ether Ethernet header
 * @param payload If non-null returns a pointer to the IPv4 payload (not including optional header). Payload is undefined if packet is not IPv4.
 * @return Pointer to IPv4 header or NULL if packet does not contain IPv4.
 */
const struct ip* find_ipv4_header(const struct ethhdr* ether, const char** payload);

const struct tcphdr* find_tcp_header(const void* pkt, const struct ethhdr* ether, const struct ip* ip, uint16_t* src, uint16_t* dest);
const struct udphdr* find_udp_header(const void* pkt, const struct ethhdr* ether, const struct ip* ip, uint16_t* src, uint16_t* dest);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* PACKET_H */
