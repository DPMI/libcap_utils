#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/marker.h"
#include "caputils_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include "be64toh.h" /* for compability */

static enum {
	MODE_UDP,
	MODE_TCP,
	MODE_ETH,
} mode = MODE_UDP;

static struct marker marker = {
	.magic = MARKER_MAGIC,
	.version = 1,
	.flags = 0,
	.reserved = 0,
	.exp_id = 0,
	.run_id = 0,
	.key_id = 0,
	.seq_num = 0,
	.timestamp = 0,
};

static const char* program_name = NULL;
static const char* shortopts = "e:r:k:s:c:utxh";
static struct option longopts[]= {
	{"experiment", required_argument, 0, 'e'},
	{"run",        required_argument, 0, 'r'},
	{"key",        required_argument, 0, 'l'},
	{"sequence",   required_argument, 0, 's'},
	{"comment",    required_argument, 0, 'c'},
	{"help",       no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(void){
	printf("capmarker-%s\n", caputils_version(NULL));
	printf("(C) 2012 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] IP:PORT..\n", program_name);
	printf("  -e, --experiment=ID  Current experiment ID.\n"
	       "  -r, --run=ID         Current run ID.\n"
	       "  -k, --key=INT        Domain information. [default: 0]\n"
	       "  -s, --sequence       Sequence start number. [default: 0].\n"
	       "  -c, --comment        Comment\n"
	       "  -u                   UDP packet [default]\n"
	       "  -t                   TCP packet\n"
	       "  -x                   Ethernet packet\n"
	       "  -h, --help           This text.\n");
}

static int send_udp(const struct in_addr dst, in_port_t port){
	/* open socket */
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( sd == -1 ){
		fprintf(stderr, "%s: failed to open socket: %s\n", program_name, strerror(errno));
		return 1;
	}

	int on = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0) {
		fprintf(stderr, "%s: setsockopt(SO_REUSEADDR) failed: %s\n", program_name, strerror(errno));
		return 1;
	}

	/* setup source address */
	static struct sockaddr_in src_addr;
	memset(&src_addr, 0, sizeof(struct sockaddr_in));
	src_addr.sin_family = AF_INET;
	src_addr.sin_port = (in_port_t)htons(MARKERPORT);
	src_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* setup destination address */
	static struct sockaddr_in dst_addr;
	memset(&dst_addr, 0, sizeof(struct sockaddr_in));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = port;
	dst_addr.sin_addr.s_addr = dst.s_addr;

	if ( bind(sd, &src_addr, sizeof(struct sockaddr_in)) == -1 ){
		fprintf(stderr, "%s: failed to bind socket: %s\n", program_name, strerror(errno));
		return 1;
	}

	/* send marker */
	if ( sendto(sd, &marker, sizeof(struct marker), 0, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr_in)) == -1 ){
		fprintf(stderr, "%s: sendto failed: %s\n", program_name, strerror(errno));
	}

	return 0;
}

int main(int argc, char **argv){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	/* reset marker */
	marker.timestamp = htobe64(time(NULL));
	memset(marker.comment, 0, 64);

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'e':
			marker.exp_id = atoi(optarg);
			if ( marker.exp_id == 0 ){
				fprintf(stderr, "%s: Experiment ID must be greater than 0.\n", program_name);
				return 1;
			}
			break;

		case 'r':
			marker.run_id = atoi(optarg);
			if ( marker.run_id == 0 ){
				fprintf(stderr, "%s: Run ID must be greater than 0.\n", program_name);
				return 1;
			}
			break;

		case 'k':
			marker.key_id = atoi(optarg);
			break;

		case 's':
			marker.seq_num = atoi(optarg);
			break;

		case 'c':
			strncpy(marker.comment, optarg, 63); /* 63 so that 64 will always be a NULL-terminator */
			break;

		case 'u':
			mode = MODE_UDP;
			break;

		case 't':
			mode = MODE_TCP;
			break;

		case 'x':
			mode = MODE_ETH;
			break;

		case 'h':
			show_usage();
			exit(0);
			break;

		default:
			if ( option_index >= 0 ){
				fprintf(stderr, "flag --%s declared but not handled\n", longopts[option_index].name);
			} else {
				fprintf(stderr, "flag -%c declared but not handled\n", op);
			}
			abort();
		}
		option_index = -1;
	}

	/* network order */
	marker.magic = htonl(marker.magic);
	marker.reserved = htons(marker.reserved);
	marker.exp_id = htonl(marker.exp_id);
	marker.run_id = htonl(marker.run_id);
	marker.key_id = htonl(marker.key_id);
	marker.seq_num = htonl(marker.seq_num);

	/* ensure at least one destination exists */
	if ( optind == argc ){
		fprintf(stderr, "%s: no destination\n", program_name);
		return 1;
	}

	/* send marker */
	for ( int i = optind; i < argc; i++ ){
		struct in_addr ip_addr;
		in_port_t ip_port = 0; /* silence gcc stupid warning about initialized value, it is never used uninitialized */
		char* tmp;

		/* parse address */
		switch ( mode ){
		case MODE_UDP:
		case MODE_TCP:
			strtok(argv[i], ":");
			tmp = strtok(NULL, "");
			if ( !tmp ){
				fprintf(stderr, "%s: bad address `%s'\n", program_name, argv[i]);
				return 1;
			}
			inet_aton(argv[i], &ip_addr);
			ip_port = htons(atoi(tmp));

			fprintf(stderr, "%s: Sending marker to %s:%d\n", program_name, inet_ntoa(ip_addr), ntohs(ip_port));
		}

		/* send */
		switch ( mode ){
		case MODE_UDP:
			send_udp(ip_addr, ip_port);
		}
	}

	return 0;
}
