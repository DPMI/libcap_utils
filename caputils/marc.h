/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef CAPUTILS_MARC_H
#define CAPUTILS_MARC_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <caputils/filter.h>

#include <sys/time.h>
#include <net/if.h>
#include <arpa/inet.h>

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct marc_context* marc_context_t;

/**
 * Using a specialized datatype for MAMPid as it is very easy to get its
 * handling wrong. The problem is that it _might_ not be a null-terminated
 * string, i.e. if the MAMPid is exactly 16 chars long.
 */
typedef char mampid_t[16];

/**
 * Set MAMPid to src, or if src is NULL reset it.
 */
void mampid_set(mampid_t dst, const char* src);

/**
 * Get pointer to char-buffer suitable for printing. Returns pointer to static
 * memory.
 */
const char* mampid_get(const mampid_t src);

enum MPEvent {
	/* Events compatable with legacy code */
	/* Sadly event type are depending on whose sending them, so the same type shares values */
	/* DO NOT USE IN NEW CODE. New events are translated automatically if MArCd version is to old. */
	MP_LEGACY_INIT_EVENT = 1,          /* init request */
	MP_LEGACY_AUTH_EVENT = 1,          /* authorize MP */
	MP_LEGACY_STATUS_EVENT = 2,        /* status report */
	MP_LEGACY_FILTER_RELOAD_EVENT = 2, /* reload all filters */
	MP_LEGACY_FILTER_ADD_EVENT = 3,    /* add a single filter */
	MP_LEGACY_FILTER_UPDATE_EVENT = 4, /* update a filter */
	MP_LEGACY_FILTER_DEL_EVENT = 5,    /* delete filter */
	MP_LEGACY_VERIFY = 6,              /* verify a filter */
	MP_LEGACY_VERIFY_ALL = 7,          /* verify all filters */
	MP_LEGACY_SHUTDOWN = 8,            /* terminate MP */
	MP_LEGACY_FLUSH_ALL = 9,           /* force flush all CI */
	MP_LEGACY_FLUSH = 10,              /* force flush single CI */

	/* libmarc client -> server filter events */
	MP_STATUS_EVENT = 64,              /* status report */
	MP_STATUS2_OLD_EVENT,              /* Old extended status report */
	MP_FILTER_REQUEST_EVENT,           /* request filter (client should handle
	                                    * this event as well and resend it to the
	                                    * server. (happens when libmarc rewrites
	                                    * events and the full filter wasn't
	                                    * available) */

	/* libmarc server -> client filter events */
	MP_FILTER_EVENT = 67,              /* new or updated filter */
	MP_FILTER_RELOAD_EVENT,            /* reload all filters */
	MP_FILTER_DEL_EVENT,               /* delete filter */
	MP_FILTER_VERIFY_EVENT,            /* verify given filter */
	MP_FILTER_VERIFY_ALL_EVENT,        /* verify all filters */
	MP_FILTER_INVALID_ID,              /* an invalid filter was requested */

	/* libmarc client -> server control events */
	MP_STATUS3_EVENT = 100,            /* Extended status report (yet another old event) */
	MP_DSTAT_EVENT = 101,              /* Dynamic extended report (based on separate and extendable headers) */
	MP_CONTROL_INIT_EVENT = 1,         /* init request */


	/* libmarc server -> client control events */
	MP_CONTROL_AUTHORIZE_EVENT = 128,  /* authorize MP */
	MP_CONTROL_AUTHORIZE_REQUEST,      /* request the MP to ask for authorization. Used by webgui. */
	MP_CONTROL_TERMINATE_EVENT,        /* terminate MP */
	MP_CONTROL_FLUSH_EVENT,            /* flush all CI buffers */
	MP_CONTROL_FLUSH_ALL_EVENT,        /* flush single CI buffer */
	MP_CONTROL_PING_EVENT,             /* ping request, client should return message ASAP */

	/* other */
	MP_CONTROL_DISTRESS = 256,         /* MP is distress, probably crashing [mampid_t] */
	MP_CONTROL_STOP_EVENT,             /* stop capture but don't terminate (nop if already stopped) [mampid_t] */
	MP_CONTROL_START_EVENT,            /* start capture (nop if already running) [mampid_t] */
};

typedef struct {
	uint16_t major;
	uint16_t minor;
} version_t;

typedef struct {
	uint8_t major;
	uint8_t minor;
	uint8_t micro;
	uint8_t __padding;
} versionex_t;

struct CIinitialization {
	char iface[8];
};

struct MPinitialization {
	uint32_t type;
	struct ether_addr hwaddr; // MAC address of Measurement Point
	char __padding[2];      // Padding for compatability
	char hostname[198];     // Name of MP
	uint16_t ma_mtu;        // MTU on MA interface (available since 0.7.14)
	uint8_t ipaddress[4];   // ipaddress
	uint16_t port;          // UDP port that the MP listens to
	uint16_t maxFilters;    // Maximum number of filters
	uint16_t noCI;          // Number of capture interfaces
	mampid_t MAMPid;        // ID string provided by MARC.

	/* legacy MP's only send the fields above (and protocol version below), must
	 * look at the version header to detect if fields below are available. */
	struct {
		version_t protocol;
		versionex_t caputils;
		versionex_t self; /* MP version */
	} version;

	uint32_t drivers; /* bitmask 1:raw 2:pcap 4:dag */
	struct CIinitialization CI[0];
};

struct MPauth {
	uint32_t type;
	mampid_t MAMPid;
	version_t version;      // protocol version
};

struct MPFilterID {
	uint32_t type;
	mampid_t MAMPid;
	uint32_t id;
};

struct MPFilter {
	uint32_t type;
	mampid_t MAMPid;                 // Name of MP
	struct filter_packed filter;      // Filter specification.
};

struct MPVerifyFilter{
	int type;
	mampid_t MAMPid;
	int filter_id;
	int flags; // 0 No filter present,i.e., no filter matched the requested id.
	struct filter_packed filter;
};

struct MPstatusLegacy {
	uint32_t type;
	mampid_t MAMPid;        // Name of MP.
	int noFilters;          // Number of filters present on MP.
	int matched;            // Number of matched packets
	int noCI;               // Number of CIs
	char CIstats[1100];     // String specifying CI status.
};

struct CIstats {
	char iface[8];
	uint32_t packet_count;
	uint32_t matched_count;
	uint32_t dropped_count;
	uint32_t buffer_usage;
};

struct MPstatusLegacyExt {
	uint32_t type;
	mampid_t MAMPid;

	uint32_t packet_count;
	uint32_t matched_count;

	uint8_t status;
	uint8_t noFilters;
	uint8_t noCI;
	uint8_t __padding;

	struct {
		char iface[8];
		uint32_t packet_count;
		uint32_t matched_count;
		uint32_t buffer_usage;
	} CI[0];
};

struct MPstatusExtended {
	uint32_t type;
	mampid_t MAMPid;
	uint8_t version;
	uint8_t _res1;
	uint16_t MTU;                   /* MP MTU on MArC interface */

	uint32_t packet_count;
	uint32_t matched_count;
	uint32_t dropped_count;

	uint8_t status;
	uint8_t noFilters;
	uint8_t noCI;
	uint8_t _res4;

	struct CIstats CI[0];
};

struct MPDStatHdr {
	uint16_t type;
	uint16_t len;
};

struct MPDStat {
	uint32_t type;                /* marcd event type */
	mampid_t MAMPid;              /* sender mampid */
	uint8_t version;              /* version of this message */

	uint8_t  _res1;
	uint16_t _res2;

	struct MPDStatHdr next[0];    /* extension header (last is always a trailer) */
};

typedef union {
	struct {
		uint32_t type;
		mampid_t MAMPid;
		char payload[1400]; /* maximum size of MPMessages, clients may recv sizeof(MPMessage) */
	};

	struct MPinitialization init;
	struct MPauth auth;
	struct MPFilter filter;
	struct MPFilterID filter_id;
	struct MPstatusLegacy legacy_status;
	struct MPstatusLegacyExt legacy_ext_status;
	struct MPstatusExtended status;
	struct MPDStat dstat;
} MPMessage;

/**
 * Passed to marc_init_client
 * @param client_ip Optional ip to use when connecting.
 * @param server_ip Optional ip to use when connecting.
 * @param client_port Optional port number. Use 0 for default.
 * @param max_filters
 * @param noCI
 */
struct marc_client_info {
	const char* client_ip;
	const char* server_ip;
	int client_port;

	int max_filters;
	int noCI;
	int ma_mtu;

	struct {
		versionex_t caputils;
		versionex_t self;
	} version;

	uint32_t drivers; /* bitmask 1:raw 2:pcap 4:dag */
	struct CIinitialization CI[8];
};

/**
 * Initialize a MArCd client.
 * @param ctxptr MArCd context pointer
 * @param iface Which interface the MArC daemon runs on.
 * @return On success, ctxptr contains a valid context and 0 is returned. On
 *         error, errno is returned. ctxptr is undefined on errors.
 */
int marc_init_client(marc_context_t* ctxptr, const char* iface, struct marc_client_info* info);

/**
 * Initialize a MArCd server.
 * @param ctxptr MArCd context pointer
 * @param port Listen port. Use 0 for default.
 * @return On success, ctrptr contains a valid context and 0 is returned. On
 *         error, errno is returned. ctxptr is undefined on errors.
 */
int marc_init_server(marc_context_t* ctxptr, int port);
int marc_cleanup(marc_context_t ctx);

/**
 * Send an initialization event to MArCd.
 */
int marc_client_init_request(marc_context_t ctx, struct marc_client_info* info);

/**
 * Send message to/from MArCd.
 * @param ctx MArCd context.
 * @param event Event to send, cast struct to MPMessage*.
 * @param dst Set to NULL in clients, server should set address to send to.
 */
int marc_push_event(marc_context_t ctx, MPMessage* event, struct sockaddr* dst);

/**
 * Wait for a message to arrive.
 * @param ctx MArCd context pointer.
 * @param event [IN] Stores event information in this memory.
 * @param bytes [OUT] How many bytes the message is.
 * @param from [OUT] If not NULL, stores the address of the sender.
 * @param addrlen [IN/OUT] If from is set this is the size of it.
 * @param timeout [IN/OUT] How long to wait, or NULL to block indefinitely.
 * @return Zero if a message arrived and was sucessfully read, or errno is
 *         returned on errors. EAGAIN if timeout is reached and EINTR if an
 *         interupt was detected. For other errors see select(2) and recv(2).
 *         The content of event, bytes, from, timeout is undefined if an
 *         error occurs.
 */
int marc_poll_event(marc_context_t ctx, MPMessage* event, size_t* bytes, struct sockaddr* from, socklen_t* addrlen, struct timeval* timeout);

/* helper functions */
int marc_filter_request(marc_context_t ctx, const char* MAMPid, uint32_t filter_id);

typedef int (*marc_output_handler_t)(FILE*, const char*, ...);
typedef int (*marc_output_handlerv_t)(FILE*, const char*, va_list);

int marc_set_output_handler(marc_output_handler_t, marc_output_handlerv_t, FILE* errors, FILE* verbose);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_MARC_H */
