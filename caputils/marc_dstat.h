#ifndef MARC_DSTAT_H
#define MARC_DSTAT_H

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <caputils/marc.h>

enum MPDStatType {
	MP_DSTAT_TRAILER = 0,                /* Last extension header (must always be present) */
	MP_DSTAT_SUMMARY,                    /* Overall statistics */
	MP_DSTAT_IFACE,                      /* Statistics for an interface */
	MP_DSTAT_DAG_IFACE,                  /* Statistics for a DAG interface */
	MP_DSTAT_DAG_VERSION,                /* Version of DAG software */
};

enum MPDStatDAGFlags {
	MP_DAG_CLOCK_SYNC = (1<<0),           /* Clock was syncronized during the entire period since last report */
	MP_DAG_LINK_A = (1<<1),               /* Port A had link */
	MP_DAG_LINK_B = (1<<2),               /* Port B had link */
	MP_DAG_VARLEN = (1<<3),               /* Variable-length capturing was used */
};

struct MPDStat_Summary {
	uint16_t type;
	uint16_t len;

	uint16_t MTU;                         /* MP MTU on MArC interface */
	uint16_t _res1;

	uint32_t packet_count;                /* Total number of packet processed by this MP (on all interfaces)*/
	uint32_t matched_count;               /* Total number of matched packets */
	uint32_t dropped_count;               /* Total number of dropped packets */
	uint8_t status;                       /* Current MP state */
	uint8_t noFilters;                    /* Number of filters present */
	uint8_t noCI;                         /* Number of capture interfaces available */
	uint8_t _res2;
};

/**
 * Interface statistics
 */
struct MPDStat_Iface {
	uint16_t type;
	uint16_t len;

	char iface[8];                        /* Interface name */
	uint32_t packet_count;                /* Number of packets processed in total */
	uint32_t matched_count;               /* Number of packets matched filter */
	uint32_t dropped_count;               /* Number of packets dropped */
	uint32_t buffer_usage;                /* Current buffer usage */
};

/**
 * Extra statistics for DAG interfaces.
 */
struct MPDStat_DAG {
	uint16_t type;
	uint16_t len;

	char iface[8];                        /* Interface name */
	uint32_t flags;                       /* DAG flags (see MPDStatDAGFlags) */
	uint32_t rxerrors;                    /* Number of rx errors */
	uint32_t dserrors;                    /* Number of internal errors */
	uint32_t trunc;                       /* Number of truncations */
	uint16_t slen;                        /* Current snaplen */
	uint16_t _res1;
};

struct MPDStat_DAGVersion {
	uint16_t type;
	uint16_t len;
	char harware[12];                     /* Physical version, e.g. 3.6GE */
	char driver[12];                      /* Software driver */
};

/**
 * Get a pointer to the next header.
 */
const struct MPDStatHdr* mp_dstat_next(const struct MPDStatHdr* cur);
struct MPDStatHdr* mp_dstat_nextw(struct MPDStatHdr* cur);

/**
 * Get total size of message.
 */
size_t mp_dstat_size(const struct MPDStat* event);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* MARC_DSTAT_H */
