#ifndef LIBMARC_H
#define LIBMARC_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <caputils/filter.h>

#include <sys/time.h>
#include <net/if.h>
#include <arpa/inet.h>

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
	MP_STATUS2_EVENT,                  /* Extended status report */
	MP_FILTER_REQUEST_EVENT,           /* request filter (client should handle
	                                    * this event as well and resend it to the
	                                    * server. (happens when libmarc rewrites
	                                    * events and the full filter wasn't
	                                    * available) */

	/* libmarc server -> client filter events */
	MP_FILTER_EVENT,                   /* new or updated filter */
	MP_FILTER_RELOAD_EVENT,            /* reload all filters */
	MP_FILTER_DEL_EVENT,               /* delete filter */
	MP_FILTER_VERIFY_EVENT,            /* verify given filter */
	MP_FILTER_VERIFY_ALL_EVENT,        /* verify all filters */
	MP_FILTER_INVALID_ID,              /* an invalid filter was requested */

	/* libmarc client -> server control events */
	MP_CONTROL_INIT_EVENT = 1,         /* init request */

	/* libmarc server -> client control events */
	MP_CONTROL_AUTHORIZE_EVENT = 128,  /* authorize MP */
	MP_CONTROL_AUTHORIZE_REQUEST,      /* request the MP to ask for authorization. Used by webgui. */
	MP_CONTROL_TERMINATE_EVENT,        /* terminate MP */
	MP_CONTROL_FLUSH_EVENT,            /* flush all CI buffers */
	MP_CONTROL_FLUSH_ALL_EVENT,        /* flush single CI buffer */

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
	char hostname[200];     // Name of MP
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

struct MPstatus {
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
	uint32_t buffer_usage;
};

struct MPstatus2 {
	uint32_t type;
	mampid_t MAMPid;

	uint32_t packet_count;
	uint32_t matched_count;

	uint8_t status;
	uint8_t noFilters;
	uint8_t noCI;
	uint8_t __padding;

	struct CIstats CI[0];
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
	struct MPstatus status;
	struct MPstatus2 status2;
} MPMessage;

/**
 * Passed to marc_init_client
 * @param client_ip Optional ip to use when connecting.
 * @param client_port Optional port number. Use 0 for default.
 * @param max_filters
 * @param noCI
 */
struct marc_client_info {
	const char* client_ip;
	int client_port;

	int max_filters;
	int noCI;

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

#endif /* LIBMARC_H */
