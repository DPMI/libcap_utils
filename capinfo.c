#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define __STDC_FORMAT_MACROS

#include "caputils/caputils.h"
#include "caputils/marker.h"
#include "caputils_int.h"
#include <getopt.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netdb.h>

struct stats {
	unsigned long int packets;             /* total number of packets */
	unsigned long int bytes;               /* sum of all bytes */
	unsigned long int byte_min, byte_max;  /* smallest/largest packet_size */
	timepico first, last;                  /* timestamp of first/last packet */
};

struct simple_list {
	char** key;         /* group key */
	struct stats value; /* statistics for this group */

	size_t size;        /* slots in use */
	size_t capacity;    /* slots available */
};

static void slist_clear(struct simple_list* slist){
	for ( unsigned int i = 0; i < slist->size; i++ ){
		free(slist->key[i]);
	}
	slist->size = 0;
}

static void slist_alloc(struct simple_list* slist, size_t growth){
	slist->capacity += growth;
	slist->key = realloc(slist->key, sizeof(char*) * slist->capacity);
}

static void slist_free(struct simple_list* slist){
	slist_clear(slist);
	free(slist->key);
	slist->capacity = 0;
}

struct count {
	uint64_t packets;
	uint64_t bytes;
};

static struct stats total;
static stream_t st = NULL;
static int marker_present = 0;
static struct count ipv4;
static struct count ipv6;
static struct count arp;
static struct count stp;
static struct count cdpvtp;
static struct count other;
static struct count  ieee8023;
static struct count ipproto[UINT8_MAX]; /* protocol is defined as 1 octet */
static struct simple_list mpid = {NULL, {}, 0, 0};
static struct simple_list CI = {NULL, {}, 0, 0};

static const char* shortopts = "h";
static struct option longopts[] = {
	{"help",    no_argument, 0, 'h'},
	{0, 0, 0, 0}, /* sentinel */
};

static void show_usage(void){
	printf("capinfo-%s\n", caputils_version(NULL));
	printf("(c) 2011 David Sveningsson\n\n");
	printf("Open a capstream and show information about it.\n");
	printf("Usage: capinfo [OPTIONS] FILENAME..\n\n");
	printf("  -h, --help                 Show this help.\n");
	printf("\n");
	printf("Hint: use `capfilter | capinfo` need to run capinfo on a filtered trace.\n");
}

static void reset(){
	total.packets = 0;
	total.bytes = 0;
	total.byte_min = UINT16_MAX;
	total.byte_max = 0;
	marker_present = 0;
	ipv4.packets = 0;
	ipv4.bytes = 0;
	ipv6.packets = 0;
	ipv6.bytes = 0;
	arp.packets = 0;
	arp.bytes = 0;
	stp.packets = 0;
	stp.bytes = 0;
	cdpvtp.packets = 0;
	cdpvtp.bytes = 0;
	ieee8023.packets = 0;
	ieee8023.bytes = 0;
	other.packets = 0;
	other.bytes = 0;
	for ( int i = 0; i < UINT8_MAX; i++ ){
		ipproto[i].packets = 0;
		ipproto[i].bytes = 0;
	}
}

static unsigned int min(unsigned int a, unsigned int b){
	return (a<b) ? a : b;
}

static unsigned int max(unsigned int a, unsigned int b){
	return (a>b) ? a : b;
}

void store_packet_stats(struct stats* stat, struct cap_header* cp){
	stat->packets++;

	if ( stat->packets == 1 ){
		stat->first = cp->ts;
	}
	stat->last = cp->ts; /* overwritten each time */
	stat->bytes += cp->len;
	stat->byte_min = min(stat->byte_min, cp->len);
	stat->byte_max = max(stat->byte_max, cp->len);
}

static void format_bytes(char* dst, size_t size, uint64_t bytes){
	static const char* prefix[] = { "", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
	unsigned int n = 0;
	uint64_t multiplier = 1;
	while ( bytes / multiplier >= 1024 && n < 8 ){
		multiplier *= 1024;
		n++;
	}

	/* Special case when there is no prefix. Since bytes cannot be fractional
	 * it prints number of bytes directly without division and decimal. It also
	 * "removes" the double space that was added when the prefix was empty. */
	if ( n == 0 ){
		snprintf(dst, size, "%"PRIu64" (%"PRIu64" bytes)", bytes, bytes);
		return;
	}

	float tmp = (float)bytes / multiplier;
	snprintf(dst, size, "%.1f %s (%"PRIu64" bytes)", tmp, prefix[n], bytes);
}

static void format_rate(char* dst, size_t size, uint64_t bytes, uint64_t seconds){
	static const char* prefix[] = { "bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps", "Zbps", "Ybps" };
	const uint64_t rate = (bytes*8) / (seconds > 0 ? seconds : 1);
	unsigned int n = 0;
	uint64_t multiplier = 1;
	while ( rate / multiplier >= 1024 && n < 8 ){
		multiplier *= 1024;
		n++;
	}
	float tmp = (float)rate / multiplier;
	snprintf(dst, size, "%.1f %s", tmp, prefix[n]);
}

static void format_seconds(char* dst, size_t size, timepico first, timepico last){
	const timepico time_diff = timepico_sub(last, first);
	uint64_t hseconds = time_diff.tv_sec * 10 + time_diff.tv_psec / (PICODIVIDER / 10);

	int s = hseconds % 600;
	hseconds /= 600;
	int m = hseconds % 60;
	int h = hseconds / 60;

	snprintf(dst, size, "%02d:%02d:%04.1f", h, m, s > 0 ? (float)s/10 : 0);
}

static const char* array_join(char* dst, char* const src[], size_t n, const char* delimiter){
	char* cur = dst;
	for ( unsigned int i = 0; i < n; i++ ){
		cur += sprintf(cur, "%s%s", (i>0?delimiter:""), src[i]);
	}
	return dst;
}

static const char* get_mampid_list(const char* delimiter){
	static char buffer[2048];
	return array_join(buffer, mpid.key, mpid.size, delimiter);
}

static const char* get_CI_list(const char* delimiter){
	static char buffer[2048];
	return array_join(buffer, CI.key, CI.size, delimiter);
}

static const char* get_comment(stream_t st){
	const char* comment = stream_get_comment(st);
	return comment ? comment : "(unset)";
}

static void print_overview(){
	char byte_str[128];
	char rate_str[128];
	char first_str[128];
	char last_str[128];
	char sec_str[128];
	char marker_str[128] = "no";
	if ( marker_present ){
		sprintf(marker_str, "present on port %d", marker_present);
	}
	const timepico time_diff = timepico_sub(total.last, total.first);
	uint64_t hseconds = time_diff.tv_sec * 10 + time_diff.tv_psec / (PICODIVIDER / 10);
	timepico_to_string_r(&total.first, first_str, 128, "%F %T");
	timepico_to_string_r(&total.last,  last_str,  128, "%F %T");
	format_bytes(byte_str, 128, total.bytes);
	format_rate(rate_str, 128, total.bytes, hseconds/10);
	format_seconds(sec_str, 128, total.first, total.last);
	const int local_byte_min = total.packets > 0 ? total.byte_min : 0;
	const int local_byte_max = total.packets > 0 ? total.byte_max : 0;
	const int local_byte_avg = total.packets > 0 ? total.bytes / total.packets : 0;

	printf("Overview\n"
	       "--------\n");
	printf("       CI: %s\n", get_CI_list(", "));
	printf("     mpid: %s\n", get_mampid_list(", "));
	printf("  comment: %s\n", get_comment(st));
	printf(" captured: %s to %s\n", first_str, last_str);
	printf("  markers: %s\n", marker_str);
	printf(" duration: %s (%.1f seconds)\n", sec_str, (float)hseconds/10);
	printf("  packets: %"PRIu64"\n", total.packets);
	printf("    bytes: %s\n", byte_str);
	printf(" pkt size: min/avg/max = %d/%d/%d\n", local_byte_min, local_byte_avg, local_byte_max);
	printf(" avg rate: %s\n", rate_str);
	printf("\n");
}

static void print_distribution(){
	printf("Network protocols\n"
	       "-----------------\n");

	if ( ipv4.packets > 0 ){
		printf("     IPv4: %"PRIu64" packets, %"PRIu64" bytes\n", ipv4.packets, ipv4.bytes);
	}
	if ( ipv6.packets > 0 ){
		printf("     IPv6: %"PRIu64" packets, %"PRIu64" bytes\n", ipv6.packets, ipv6.bytes);
	}
	if ( arp.packets > 0 ){
		printf("      ARP: %"PRIu64" packets, %"PRIu64" bytes\n", arp.packets, arp.bytes);
	}
	if ( stp.packets > 0 ){
		printf("      STP: %"PRIu64" packets, %"PRIu64" bytes\n", stp.packets, stp.bytes);
	}
	if ( cdpvtp.packets > 0 ){
		printf("   cdpvtp: %"PRIu64" packets, %"PRIu64" bytes\n", cdpvtp.packets, cdpvtp.bytes);
	}
	if ( ieee8023.packets > 0 ){
		printf("IEEE802.3: %"PRIu64" packets, %"PRIu64" bytes\n", ieee8023.packets, ieee8023.bytes);
	}
	if ( other.packets > 0 ){
		printf("    Other: %"PRIu64" packets, %"PRIu64" bytes\n", other.packets, other.bytes);
	}

	printf("\nTransport protocols\n"
	       "-------------------\n");

	if ( ipv4.packets > 0 || ipv4.packets > 0 ){
		struct count ipother = {0, 0};
		for ( int i = 0; i < UINT8_MAX; i++ ){
			if ( ipproto[i].packets == 0 ){
				continue;
			}

			struct protoent* protoent = getprotobynumber(i);

			if ( !protoent ){
				ipother.packets += ipproto[i].packets;
				ipother.bytes   += ipproto[i].bytes;
				continue;
			}

			printf("%9s: %"PRIu64" packets, %"PRIu64" bytes\n", protoent->p_name, ipproto[i].packets, ipproto[i].bytes);
		}
		if ( ipother.packets > 0 ){
			printf("    other: %"PRIu64" packets, %"PRIu64" bytes\n", other.packets, other.bytes);
		}
	}
}

static unsigned int store_unique(struct simple_list* slist, const char* key, size_t maxlen){
	/* try to locate an existing string */
	for ( unsigned int i = 0; i < slist->size; i++ ){
		if ( strncmp(slist->key[i], key, maxlen) == 0 ) return i;
	}

	/* allocate more memory if needed */
	if ( slist->size == slist->capacity ){
		slist_alloc(slist, /* growth = */ slist->capacity);
	}

	/* store key */
	unsigned int index = slist->size;
	slist->key[index] = strndup(key, maxlen);
	slist->size++;
	return index;
}

static void store_mampid(struct cap_header* cp){
	store_unique(&mpid, cp->mampid, 8);
}

static void store_CI(struct cap_header* cp){
	store_unique(&CI, cp->nic, CAPHEAD_NICLEN);
}

static int show_info(const char* filename){
	stream_addr_t addr;
	stream_addr_str(&addr, filename, 0);
	long ret = 0;

	if ( (ret=stream_open(&st, &addr, NULL, 0)) != 0 ){
		fprintf(stderr, "%s: %s\n", filename, caputils_error_string(ret));
		return ret;
	}

	struct cap_header* cp;
	while ( (ret=stream_read(st, &cp, NULL, NULL)) == 0 ){
		if ( !marker_present ){
			marker_present = is_marker(cp, NULL, 0);
		}

		store_packet_stats(&total, cp);
		store_mampid(cp);
		store_CI(cp);

		const struct ethhdr* eth = cp->ethhdr;
		const uint16_t h_proto = ntohs(eth->h_proto);
		struct iphdr* ip = NULL;

		if ( h_proto < 0x0600 ){
			ieee8023.packets++;
			ieee8023.bytes += cp->len;
			continue;
		}

		switch ( h_proto ){
		case ETHERTYPE_VLAN:
			ip = (struct iphdr*)(cp->payload + sizeof(struct ether_vlan_header));
			/** @todo handle h_proto */
			/* fallthrough */

		case ETHERTYPE_IP:
			if ( !ip ){
				ip = (struct iphdr*)(cp->payload + sizeof(struct ethhdr));
			}

			ipv4.packets++;
			ipv4.bytes += cp->len;
			ipproto[ip->protocol].packets++;
			ipproto[ip->protocol].bytes += cp->len;
			break;

		case ETHERTYPE_IPV6:
			/** @todo handle ipproto */
			ipv6.packets++;
			ipv6.bytes += cp->len;
			break;

		case ETHERTYPE_ARP:
			arp.packets++;
			arp.bytes += cp->len;
			break;

		case STPBRIDGES:
			stp.packets++;
			stp.bytes += cp->len;
			break;

		case CDPVTP:
			cdpvtp.packets++;
			cdpvtp.bytes += cp->len;
			break;

		default:
			other.packets++;
			other.bytes += cp->len;
			break;
		}
	}

	if ( ret > 0 ){
		fprintf(stderr, "stream_read() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
	}

	/* write header */
	struct file_version version;
	stream_get_version(st, &version);
	int n = printf("%s: caputils %d.%d stream\n", filename, version.major, version.minor);
	while ( n-- ){ putchar('='); } puts("\n");

	print_overview();
	print_distribution();

	stream_close(st);
	return 0;
}

int main(int argc, char* argv[]){
	/* no arguments */
	if ( argc == 1 ){
		show_usage();
		return 0;
	}

	/* parse arguments */
	int option_index = 0;
	int op;
	while ( (op=getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch ( op ){
		case 'h':
			show_usage();
			return 0;
		}
	}

	/* no targets */
	if ( optind == argc ){
		show_usage();
		return 0;
	}

	/* initial storage */
	slist_alloc(&mpid, 8);
	slist_alloc(&CI, 8);

	/* visit all targets */
	int status = 0;
	while ( optind < argc ){
		reset();
		status |= show_info(argv[optind++]);

		if ( optind < argc ){
			putchar('\n');
		}

		/* reset storage (must be done for each iteration so the results is
		 * only for the current file.) */
		slist_clear(&mpid);
		slist_clear(&CI);
	}

	/* release resources */
	slist_free(&mpid);
	slist_free(&CI);

	return status == 0 ? 0 : 1;
}
