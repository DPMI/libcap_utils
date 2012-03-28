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

static void show_usage(void){
	printf("capinfo  caputils-" CAPUTILS_VERSION "\n");
	printf("(c) 2011 David Sveningsson\n\n");
	printf("Open a capstream and show information about it.\n");
	printf("Usage: capinfo [OPTIONS] FILENAME..\n\n");
	printf("  -h, --help                 Show this help.\n");
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

static void format_seconds(char* dst, size_t size, timepico first, timepico last){
	const timepico time_diff = timepico_sub(last, first);
	uint64_t hseconds = time_diff.tv_sec * 10 + time_diff.tv_psec / (PICODIVIDER / 10);

	int s = hseconds % 600;
	hseconds /= 600;
	int m = hseconds % 60;
	int h = hseconds / 60;

	snprintf(dst, size, "%02d:%02d:%02.1f", h, m, (float)s/10);
}

static void print_overview(){
	const char* mampid = stream_get_mampid(st);
	const char* comment = stream_get_comment(st);

	printf("Overview\n"
	       "--------\n");
	printf("     mpid: %s\n", mampid != 0 ? mampid : "(unset)");
	printf("  comment: %s\n", comment ? comment : "(unset)");

	char byte_str[128];
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
	format_seconds(sec_str, 128, first, last);
	printf(" captured: %s to %s\n", first_str, last_str);
	printf("  markers: %s\n", marker_str);
	printf(" duration: %s (%.1f seconds)\n", sec_str, (float)hseconds/10);
	printf("  packets: %ld\n", packets);
	printf("    bytes: %s\n", byte_str);
	printf(" avg rate: %.1fkbps\n", (float)(bytes / (hseconds/10)) / 1024);
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
	while (1){
		static struct option long_options[] = {
			{"help",    0,            0, 'h'}
		};

		int option_index = 0;

		int c = getopt_long(argc, argv, "h", long_options, &option_index);

		if ( c == -1 ){
			break;
		}

		switch (c){
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

	/* visit all targets */
	while ( optind < argc ){
		show_info(argv[optind++]);
		if ( optind < argc ){
			putchar('\n');
		}
	}

	return 0;
}
