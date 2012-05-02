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

#define STPBRIDGES 0x0026
#define CDPVTP 0x016E

static stream_t st = NULL;
static long int packets = 0;
static uint64_t bytes = 0;
static int marker_present = 0;
static long ipv4 = 0;
static long ipv6 = 0;
static long arp = 0;
static long stp = 0;
static long cdpvtp = 0;
static long other = 0;
static long ipproto[UINT8_MAX] = {0,}; /* protocol is defined as 1 octet */
static timepico first, last;
static char** mpid;
static size_t mpid_num = 0;

static struct option long_options[] = {
	{"help",    no_argument, 0, 'h'},
	{0, 0, 0, 0}, /* sentinel */
};

static void show_usage(void){
	printf("capinfo-" VERSION_FULL "\n");
	printf("(c) 2011 David Sveningsson\n\n");
	printf("Open a capstream and show information about it.\n");
	printf("Usage: capinfo [OPTIONS] FILENAME..\n\n");
	printf("  -h, --help                 Show this help.\n");
}

static void reset(){
	packets = 0;
	bytes = 0;
	marker_present = 0;
	ipv4 = 0;
	ipv6 = 0;
	arp = 0;
	stp = 0;
	cdpvtp = 0;
	other = 0;
	for ( int i = 0; i < UINT8_MAX; i++ ){
		ipproto[i] = 0;
	}
}

static void format_bytes(char* dst, size_t size, uint64_t bytes){
	static const char* prefix[] = { "", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
	unsigned int n = 0;
	uint64_t multiplier = 1;
	while ( bytes / multiplier >= 1024 && n < 8 ){
		multiplier *= 1024;
		n++;
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

	snprintf(dst, size, "%02d:%02d:%02.1f", h, m, s > 0 ? (float)s/10 : 0);
}

static void print_overview(){
	const char* comment = stream_get_comment(st);

	printf("Overview\n"
	       "--------\n");

	/* show mampids */
	printf("     mpid: ");
	for ( int i = 0; i < mpid_num && mpid[i]; i++ ){
		printf("%s%s", (i>0?", ":""), mpid[i]);
	}
	printf("\n");

	printf("  comment: %s\n", comment ? comment : "(unset)");

	char byte_str[128];
	char rate_str[128];
	char first_str[128];
	char last_str[128];
	char sec_str[128];
	char marker_str[128] = "no";
	if ( marker_present ){
		sprintf(marker_str, "present on port %d\n", marker_present);
	}
	const timepico time_diff = timepico_sub(last, first);
	uint64_t hseconds = time_diff.tv_sec * 10 + time_diff.tv_psec / (PICODIVIDER / 10);
	timepico_to_string_r(&first, first_str, 128, "%F %T");
	timepico_to_string_r(&last,  last_str,  128, "%F %T");
	format_bytes(byte_str, 128, bytes);
	format_rate(rate_str, 128, bytes, hseconds/10);
	format_seconds(sec_str, 128, first, last);
	printf(" captured: %s to %s\n", first_str, last_str);
	printf("  markers: %s\n", marker_str);
	printf(" duration: %s (%.1f seconds)\n", sec_str, (float)hseconds/10);
	printf("  packets: %ld\n", packets);
	printf("    bytes: %s\n", byte_str);
	printf(" avg rate: %s\n", rate_str);
	printf("\n");
}

static void print_distribution(){
	printf("Packet distribution\n"
	       "-------------------\n");

	long ipother = 0;
	if ( ipv4 > 0 ){
		printf("     IPv4: ");
		for ( int i = 0; i < UINT8_MAX; i++ ){
			if ( ipproto[i] == 0 ){
				continue;
			}

			struct protoent* protoent = getprotobynumber(i);

			if ( !protoent ){
				ipother += ipproto[i];
				continue;
			}

			printf("%s(%ld) ", protoent->p_name, ipproto[i]);
		}
		if ( ipother > 0 ){
			printf("other(%ld)", other);
		}
		printf("\n");
	}
	if ( ipv6 > 0 ){
		printf("     IPv6: %ld\n", ipv6);
	}
	if ( arp > 0 ){
		printf("      ARP: %ld\n", arp);
	}
	if ( stp > 0 ){
		printf("      STP: %ld\n", stp);
	}
	if ( cdpvtp > 0 ){
		printf("   cdpvtp: %ld\n", cdpvtp);
	}
	if ( other > 0 ){
		printf("    Other: %ld\n", other);
	}

}

static void store_mampid(struct cap_header* cp){
	static char mampid[9] = {0,};
	memcpy(mampid, cp->mampid, 8); /* last by is left as null-terminator */

	int i;
	for ( i = 0; i < mpid_num && mpid[i]; i++ ){
		if ( strcmp(mpid[i], mampid) == 0 ){
			return;
		}
	}

	/* allocate more memory if needed */
	if ( i == mpid_num ){
		mpid_num *= 2;
		mpid = realloc(mpid, sizeof(char*) * mpid_num);
	}

	mpid[i] = strdup(mampid);
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
		packets++;

		if ( packets == 1 ){
			first = cp->ts;
		}
		last = cp->ts; /* overwritten each time */
		bytes += cp->len;
		if ( !marker_present ){
			marker_present = is_marker(cp, NULL, 0);
		}

		store_mampid(cp);

		struct ethhdr* eth = (struct ethhdr*)cp->payload;
		struct iphdr* ip = NULL;
		uint16_t h_proto = ntohs(eth->h_proto);

		switch ( h_proto ){
		case ETHERTYPE_VLAN:
			ip = (struct iphdr*)(cp->payload + sizeof(struct ether_vlan_header));
			/* fallthrough */

		case ETHERTYPE_IP:
			if ( !ip ){
				ip = (struct iphdr*)(cp->payload + sizeof(struct ethhdr));
			}

			ipv4++;
			ipproto[ip->protocol]++;
			break;

		case ETHERTYPE_IPV6:
			ipv6++;
			break;

		case ETHERTYPE_ARP:
			arp++;
			break;

		case STPBRIDGES:
			stp++;
			break;

		case CDPVTP:
			cdpvtp++;
			break;

		default:
			other++;
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
	while ( (op=getopt_long(argc, argv, "h", long_options, &option_index)) != -1 ){
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

	/* initial mampid storage */
	mpid_num = 8;
	mpid = malloc(sizeof(char*) * mpid_num);
	memset(mpid, 0, sizeof(char*) * mpid_num);

	/* visit all targets */
	while ( optind < argc ){
		reset();
		show_info(argv[optind++]);

		if ( optind < argc ){
			putchar('\n');
		}

		/* reset mampid storage (must be done for each iteration so the results is
		 * only for the current file.) */
		for ( int i = 0; i < mpid_num; i++ ){
			free(mpid[i]);
			mpid[i] = NULL;
		}
	}

	return 0;
}
