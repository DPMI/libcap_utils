#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include <caputils/marker.h>
#include "caputils_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/udp.h>
#include "be64toh.h" /* for compability */

static int keep_running = 1;
static int marker = 0;
static char* fmt_basename = NULL;  /* used by format_filename */
static char* fmt_extension = NULL; /* used by format_filename */
static const char* program_name = NULL;
static struct option long_options[]= {
	{"output",  required_argument, 0, 'o'},
	{"packets", required_argument, 0, 'p'},
	{"iface",   required_argument, 0, 'i'},
	{"comment", required_argument, 0, 'c'},
	{"timeout", required_argument, 0, 't'},
	{"marker",  required_argument, 0, 'm'},
	{"marker-format", required_argument, 0, 'f'},
	{"help",    no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void sigint_handler(int signum){
	if ( keep_running == 0 ){
		fprintf(stderr, "\rGot SIGINT again, terminating.\n");
		abort();
	}
	fprintf(stderr, "\rAborting capture.\n");
	keep_running = 0;
}

static void show_usage(void){
	printf("capdump-" VERSION "\n");
	printf("(C) 2011 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] STREAM\n", program_name);
	printf("  -o, --output=FILE    Save output in capfile. [default=stdout]\n"
	       "  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	       "                       on. For other streams it is ignored.\n"
	       "  -p, --packets=INT    Stop capture after INT packages.\n"
	       "  -c, --comment        Set stream comment.\n"
	       "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	       "      --marker=PORT    Split streams based on marker packet. See capdump(1) for\n"
	       "                       further description of this feature.\n"
	       "      --marker-format  Renaming format for marker.\n"
	       "  -h, --help           This text.\n");
	printf("\n");
	printf("Streams can be specified in the following formats:\n");
	printf("  - NN:NN:NN:NN:NN:NN  Listen to ethernet multicast stream.\n"
	       "  - tcp://IP[:PORT]    Listen to TCP unicast.\n"
	       "  - udp://IP[:PORT]    Listen to UDP broadcast.\n"
	       "  - FILENAME           Open capfile for reading.\n");
}

/**
 * Test if packet is a marker packet.
 * ptr is undefined if packet isn't a marker.
 */
static int is_marker(struct cap_header* cp, struct marker* ptr){
	/* match ip packet */
	const struct ip* ip = find_ip_header(cp->ethhdr);
	if ( !ip ){ return 0; }

	/* match udp packet */
	uint16_t src, dst;
	const struct udphdr* udp = find_udp_header(cp->payload, cp->ethhdr, ip, &src, &dst);
	if ( !(udp && src == MARKERPORT && dst == marker) ){ return 0; }

	/* match magic */
	struct marker* marker = (struct marker*)((char*)udp + sizeof(struct udphdr));
	if ( ntohl(marker->magic) != MARKER_MAGIC ){ return 0; }

	/* assume it is a marker */
	ptr->magic = ntohl(marker->magic);
	ptr->version = marker->version;
	ptr->flags = marker->flags;
	ptr->reserved = ntohs(marker->reserved);
	ptr->exp_id = ntohl(marker->exp_id);
	ptr->run_id = ntohl(marker->run_id);
	ptr->key_id = ntohl(marker->key_id);
	ptr->seq_num = ntohl(marker->seq_num);
	ptr->timestamp = be64toh(marker->timestamp);
	return 1;
}

static const char* format_filename(const char* fmt, const struct marker* marker){
	static char buffer[1024];
	char* dst = buffer;
	const char* src = fmt;

	while ( *src ){
		const char ch = *src;

		switch ( ch ){
		case '%':
			{
				char w[4] = {0,};
				int n = 0;
				while ( isdigit(*(++src)) ) {
					if ( n == 4 ){ fprintf(stderr, "field width specifier to great"); abort(); }
					w[n++] = *src;
				}

				const int zeropad = w[0] == '0';
				const int width = atoi(w);
				const char specifier = *src++;

				switch ( specifier ){
				case 'e': /* extension */
					dst += sprintf(dst, "%s", fmt_extension);
					break;

				case 'f': /* filename */
					dst += sprintf(dst, "%s", fmt_basename);
					break;

				case 's': /* sequence number */
					dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->seq_num);
					break;

				case 'k': /* key */
					dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->key_id);
					break;

				case 'r': /* run id */
					dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->run_id);
					break;

				case 'x': /* experiment id */
					dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->exp_id);
					break;

				default:
					fprintf(stderr, "unknown specifier `%c'\n", specifier);
					abort();
				}
				break;
			}

		default:
			*dst++ = ch;
			src++;
		}
	}
	*dst = 0;
	printf("filename: %s\n", buffer);

	return buffer;
}

int main(int argc, char **argv){
	int op, option_index = -1;

  /* extract program name from path. e.g. /path/to/MArCd -> MArCd */
  const char* separator = strrchr(argv[0], '/');
  if ( separator ){
    program_name = separator + 1;
  } else {
    program_name = argv[0];
  }

  const char* marker_format = "%f-%x-%03s.%e";
	const char* comment = "capdump-" VERSION " stream";
	char* iface = NULL;
	struct timeval timeout = {1, 0};
	stream_addr_t input;
	stream_addr_t output;
	stream_addr_aton(&output, "/dev/stdout", STREAM_ADDR_CAPFILE, STREAM_ADDR_LOCAL);

	long max_packets = -1;

	while ( (op = getopt_long(argc, argv, "ho:p:c:i:t:", long_options, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'o':
			stream_addr_aton(&output, optarg, STREAM_ADDR_CAPFILE, STREAM_ADDR_LOCAL);
			free(fmt_basename);
			fmt_basename = strdup(optarg);
			fmt_extension = fmt_basename;
			while ( *fmt_extension && *fmt_extension != '.' ){
				fmt_extension++;
			}
			if ( *fmt_extension ){
				*fmt_extension++ = 0;
			}
			break;

		case 'p':
			max_packets = atoi(optarg);
			break;

		case 'c':
			comment = optarg;
			break;

		case 't':
			{
				int tmp = atoi(optarg);
				timeout.tv_sec  = tmp / 1000;
				timeout.tv_usec = tmp % 1000 * 1000;
			}
			break;

		case 'i':
			iface = optarg;
			break;

		case 'm': /* --marker */
			marker = atoi(optarg);
			break;

		case 'f': /* --marker-format */
			marker_format = optarg;
			break;

		case 'h':
			show_usage();
			exit(0);
			break;

		default:
			if ( option_index >= 0 ){
				fprintf(stderr, "flag --%s declared but not handled\n", long_options[option_index].name);
			} else {
				fprintf(stderr, "flag -%c declared but not handled\n", op);
			}
			abort();
		}
		option_index = -1;
	}

	if ( optind == argc ){
		show_usage();
		exit(0);
	}

	stream_t src;
	stream_t dst;
	long ret;

	/* parse stream address */
	if ( (ret=stream_addr_aton(&input, argv[optind], STREAM_ADDR_GUESS, 0)) != 0 ){
		fprintf(stderr, "Failed to parse stream address: %s\n", caputils_error_string(ret));
		return 1;
	}

	/* ensure iface has been configured for ethernet streams */
	if ( stream_addr_type(&input) == STREAM_ADDR_ETHERNET && !iface ){
		fprintf(stderr, "Ethernet streams require --iface\n");
		return 1;
	}

	/* cannot output to stdout if it is a terminal */
	if ( stream_addr_type(&output) == STREAM_ADDR_CAPFILE &&
	     strcmp("/dev/stdout", output.local_filename) == 0 &&
	     isatty(STDOUT_FILENO) ){
		fprintf(stderr, "Cannot output to stdout when is is connected to a terminal.\n");
		fprintf(stderr, "Either specify another destination with --output, use redirection or pipe to another process.\n");
		return 1;
	}

	/* open input stream */
	if ( (ret=stream_from_getopt(&src, argv, optind, argc, iface, "-", program_name, 0)) != 0 ) {
		return 1;
	}

	/* open output stream */
	if ( (ret=stream_create(&dst, &output, NULL, stream_get_mampid(src), comment)) != 0 ){
		fprintf(stderr, "stream_create() failed with code 0x%08lX: %s\n", ret, caputils_error_string(ret));
		return 1;
	}

	/* install signal handler so loop can be aborted */
	signal(SIGINT, sigint_handler);

	const size_t len = sizeof(struct cap_header);
	long int pkts = 0;

	while( keep_running ){
		/* A short timeout is used to allow the application to "breathe", i.e
		 * terminate if SIGINT was received. */
		struct timeval tv = timeout;

		/* Read the next packet */
		cap_head* cp;
		ret = stream_read(src, &cp, NULL, &tv);
		if ( ret == EAGAIN ){ /* a timeout occured */
			continue;
		} else if ( ret != 0 ){ /* either an error or proper shutdown */
			break;
		}
		pkts++;

		/* Detect marker in stream */
		struct marker mark;
		if ( marker && is_marker(cp, &mark) ){
			char timestamp[200];
			struct tm* tm = localtime((time_t*)&mark.timestamp);
			strftime(timestamp, 200, "%a, %d %b %Y %T %z", tm);
			fprintf(stderr, "marker v%d found\n", mark.version);
			fprintf(stderr, "  flags: %d\n", mark.flags);
			fprintf(stderr, "  exp id: %d\n", mark.exp_id);
			fprintf(stderr, "  run id: %d\n", mark.run_id);
			fprintf(stderr, "  key id: %d\n", mark.key_id);
			fprintf(stderr, "  seq num: %d\n", mark.seq_num);
			fprintf(stderr, "  timestamp: %s\n", timestamp);

			/* abort if output is pipe */
			if ( strcmp("/dev/stdout", output.local_filename) == 0 ){
				break;
			}

			/* close current stream */
			stream_close(dst);

			stream_addr_str(&output, format_filename(marker_format, &mark), STREAM_ADDR_LOCAL);
			if ( (ret=stream_create(&dst, &output, NULL, stream_get_mampid(src), comment)) != 0 ){
				fprintf(stderr, "stream_create() failed with code 0x%08lX: %s\n", ret, caputils_error_string(ret));
				return 1;
			}
		}

		if( stream_write(dst, (char*)cp, cp->caplen + len) != 0 ) {
			fprintf(stderr, "Problems writing data to file!");
		}

		if ( max_packets > 0 && pkts >= max_packets ){
			break;
		}
	}

	/* if ret == -1 the stream was closed properly (e.g EOF or TCP shutdown)
	 * In addition EINTR should not give any errors because it is implied when the
	 * user presses C-c */
	if ( ret > 0 && ret != EINTR ){
		fprintf(stderr, "stream_read() returned 0x%08lX: %s\n", ret, caputils_error_string(ret));
	}

	stream_close(src);
	stream_close(dst);

	fprintf(stderr, "There was a total of %'ld packets read.\n", pkts);
	return 0;
}
