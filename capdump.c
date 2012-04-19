#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include <caputils/marker.h>
#include <caputils/picotime.h>
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
#include <libgen.h> /* for dirname */
#include <sys/stat.h>
#include <netinet/udp.h>
#include <inttypes.h>
#include "be64toh.h" /* for compability */
#include <time.h>

static const size_t FILENAME_SUFFIX_MAX = 1000; /* maximum number of filename suffixes */
static const size_t PROGRESS_REPORT_DELAY = 60;  /* seconds between progress reports */
static int keep_running = 1;
static int marker = 0;
static char* fmt_basename = NULL;  /* used by generate_filename */
static char* fmt_extension = NULL; /* used by generate_filename */
static const char* program_name = NULL;
static const struct stream_stat* stream_stat = NULL;
static int progress = -1;          /* if >0 progress reports is written to this file descriptor */
static struct option long_options[]= {
	{"output",  required_argument, 0, 'o'},
	{"packets", required_argument, 0, 'p'},
	{"iface",   required_argument, 0, 'i'},
	{"comment", required_argument, 0, 'c'},
	{"timeout", required_argument, 0, 't'},
	{"bufsize", required_argument, 0, 'b'},
	{"marker",  required_argument, 0, 'm'},
	{"marker-format", required_argument, 0, 'f'},
	{"progress", optional_argument, 0, 's'},
	{"help",    no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void sig_handler(int signum){
	static const char* names[] = {"SIGINT", "SIGTERM", "unknown signal"};
	const char* name;
	switch ( signum ){
	case SIGINT: name = names[0];
	case SIGTERM: name = names[1];
	default: name = names[2];
	}

	if ( keep_running == 0 ){
		fprintf(stderr, "\r%s: Got %s again, aborting.\n", program_name, name);
		abort();
	}
	fprintf(stderr, "\r%s: Got %s, terminating gracefully.\n", program_name, name);
	keep_running = 0;
}

static void progress_report(int signum){
	static char buf[1024];
	static char timestr[64];
	time_t t = time(NULL);
	struct tm tm = *gmtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S +0000", &tm);

	static uint64_t last = 0;
	const uint64_t delta = stream_stat->read - last;
	last = stream_stat->read;
	const uint64_t pps = delta / PROGRESS_REPORT_DELAY;
	const float rate = (float)(delta * 8 / PROGRESS_REPORT_DELAY / 1024 / 1024);

	ssize_t bytes = snprintf(buf, 1024, "%s: [%s] progress report: %'"PRIu64" packets read (%"PRIu64" new, %"PRIu64"pkt/s, avg bitrate %.1fMpbs).\n", program_name, timestr, stream_stat->read, delta, pps, rate);
	if ( write(progress, buf, bytes) == -1 ){
		fprintf(stderr, "progress report failed: %s\n", strerror(errno));
	}
}

static void marker_report(const struct marker* marker){
	static char timestr[64];
	static char timestamp[200];
	static struct tm* tm;

	/* timestamp for log */
	time_t t = time(NULL);
	tm = gmtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S +0000", tm);

	/* timestamp from marker */
	tm = localtime((time_t*)&marker->timestamp);
	strftime(timestamp, 200, "%a, %d %b %Y %T %z", tm);

	fprintf(stderr, "%s: [%s] marker v%d found (flags: %d)\n", program_name, timestr, marker->version, marker->flags);
	fprintf(stderr, "\texp / run / key id: %d / %d / %d\n", marker->exp_id, marker->run_id, marker->key_id);
	fprintf(stderr, "\tseq num: %d\n", marker->seq_num);
	fprintf(stderr, "\ttimestamp: %s\n", timestamp);
}

static void show_usage(void){
	printf("(C) 2011 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] STREAM\n", program_name);
	printf("  -o, --output=FILE    Save output in capfile. [default=stdout]\n"
	       "  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	       "                       on. For other streams it is ignored.\n"
	       "  -p, --packets=INT    Stop capture after INT packages.\n"
	       "  -c, --comment        Set stream comment.\n"
	       "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	       "  -b, --bufsize=BYTES  Use BYTES buffer size [default depends on driver].\n"
	       "      --marker=PORT    Split streams based on marker packet. See capdump(1) for\n"
	       "                       further description of this feature.\n"
	       "      --marker-format  Renaming format for marker.\n"
	       "      --progress[=FD]  Write progress report to FD every 60 seconds.\n"
	       "  -h, --help           This text.\n");
	printf("\n");
	printf("Streams can be specified in the following formats:\n");
	printf("  - NN:NN:NN:NN:NN:NN  Listen to ethernet multicast stream.\n"
	       "  - tcp://IP[:PORT]    Listen to TCP unicast.\n"
	       "  - udp://IP[:PORT]    Listen to UDP broadcast.\n"
	       "  - FILENAME           Open capfile for reading.\n");
}

static const char* generate_filename(const char* fmt, const struct marker* marker){
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

	/* try if the file exists already and append a suffix if it does */
	int suffix = 1;
	do {

		/* if tried to many times, give up and randomize name */
		if ( suffix > FILENAME_SUFFIX_MAX ){
			*dst = 0;
			char* tmp = tempnam("./", NULL);
			fprintf(stderr, "%s: more than %zd filename collisions detected for `%s', giving up and using `%s.%s'.\n", program_name, FILENAME_SUFFIX_MAX, buffer, buffer, tmp+2);
			sprintf(dst, ".%s", tmp+2); /* +2 to to ignore ./ */ /** @todo potential overflow */
			free(tmp);
			break;
		}

		/* test if filename already exists */
		struct stat st;
		if ( stat(buffer, &st) == -1  ){
			if ( errno == ENOENT ){
				break; /* exit loop and return filename */
			} else {
				fprintf(stderr, "%s: stat() returned %d: %s\n", program_name, errno, strerror(errno));
			}
			break;
		}

		/* append suffix */
		sprintf(dst, ".%d", suffix++); /** @todo potential buffer overflow */
	} while (1);

	return buffer;
}

int main(int argc, char **argv){
	fprintf(stderr, "capdump-" VERSION_FULL "\n");
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
	size_t buffer_size = 0;
	stream_addr_t output;
	stream_addr_aton(&output, "/dev/stdout", STREAM_ADDR_CAPFILE, STREAM_ADDR_LOCAL);

	long max_packets = -1;

	while ( (op = getopt_long(argc, argv, "ho:p:c:i:t:b:", long_options, &option_index)) != -1 ){
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

		case 'b': /* --bufsize */
			buffer_size = atoi(optarg);
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

		case 's': /* --progress */
			progress = STDERR_FILENO;
			if ( optarg ){
				progress = atoi(optarg);
				int fd = dup(progress);
				if (fd < 0) {
					fprintf(stderr, "%s: invalid progress file descriptor: %s\n", program_name, strerror(errno));
					return 1;
				}
				close(fd);
				break;

			}
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

	/* cannot output to stdout if it is a terminal */
	if ( stream_addr_type(&output) == STREAM_ADDR_CAPFILE &&
	     strcmp("/dev/stdout", output.local_filename) == 0 &&
	     isatty(STDOUT_FILENO) ){
		fprintf(stderr, "Cannot output to stdout when is is connected to a terminal.\n");
		fprintf(stderr, "Either specify another destination with --output, use redirection or pipe to another process.\n");
		return 1;
	}

	/* open input stream (using a small buffer so pipes will fill faster) */
	if ( (ret=stream_from_getopt(&src, argv, optind, argc, iface, "-", program_name, buffer_size)) != 0 ) {
		return 1;
	}

	/* open output stream */
	if ( (ret=stream_create(&dst, &output, NULL, stream_get_mampid(src), comment)) != 0 ){
		fprintf(stderr, "stream_create() failed with code 0x%08lX: %s\n", ret, caputils_error_string(ret));
		return 1;
	}
	stream_stat = stream_get_stat(src);

	/* install signal handler so loop can be aborted */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* progress report */
	if ( progress > 0 ){
		struct itimerval tv = {
			{PROGRESS_REPORT_DELAY, 0},
			{PROGRESS_REPORT_DELAY, 0},
		};
		setitimer(ITIMER_REAL, &tv, NULL);
		signal(SIGALRM, progress_report);
	}

	while( keep_running ){
		/* A short timeout is used to allow the application to "breathe", i.e
		 * terminate if SIGINT was received. */
		struct timeval tv = timeout;

		/* Read the next packet */
		cap_head* cp;
		ret = stream_read(src, &cp, NULL, NULL);
		if ( ret == EAGAIN ){ /* a timeout occured */
			continue;
		} else if ( ret == EINTR && keep_running != 0 ){ /* don't abort unless signal caused a halt */
			continue;
		} else if ( ret > 0 ){ /* either an error or proper shutdown */
			fprintf(stderr, "%s: stream_read() returned 0x%08lX: %s\n", program_name, ret, caputils_error_string(ret));
			break;
		} else if ( ret == -1 ){
			break;
		} else if ( ret != 0 ){
			abort();
		}

		/* Detect marker in stream */
		struct marker mark;
		if ( marker && is_marker(cp, &mark, marker) ){
			/* show marker */
			marker_report(&mark);

			/* abort if output is pipe */
			if ( strcmp("/dev/stdout", output.local_filename) == 0 ){
				break;
			}

			/* close current stream */
			stream_close(dst);

			/* generate next filename */
			const char* filename = generate_filename(marker_format, &mark);
			fprintf(stderr, "\tfilename: `%s'\n", filename);

			/* open new stream */
			stream_addr_str(&output, filename, STREAM_ADDR_LOCAL);
			if ( (ret=stream_create(&dst, &output, NULL, stream_get_mampid(src), comment)) != 0 ){
				fprintf(stderr, "%s: stream_create() failed with code 0x%08lX: %s\n", program_name, ret, caputils_error_string(ret));
				return 1;
			}
		}

		if ( (ret=stream_copy(dst, cp)) != 0 ) {
			fprintf(stderr, "%s: stream_copy() failed with code 0x%08lX: %s\n", program_name, ret, caputils_error_string(ret) );
			break;
		}

		if ( max_packets > 0 && stream_stat->read >= max_packets ){
			break;
		}
	}

	fprintf(stderr, "%s: There was a total of %'"PRIu64" packets recv.\n", program_name, stream_stat->recv);
	fprintf(stderr, "%s: There was a total of %'"PRIu64" packets read.\n", program_name, stream_stat->read);

	stream_close(src);
	stream_close(dst);
	free(fmt_basename);

	return 0;
}
