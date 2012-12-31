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

enum MarkerMode {
	MARKER_INCREMENT,
	MARKER_OVERWRITE,
	MARKER_APPEND,
};

static const size_t FILENAME_SUFFIX_MAX = 1000; /* maximum number of filename suffixes */
static const size_t PROGRESS_REPORT_DELAY = 60;  /* seconds between progress reports */
static int keep_running = 1;
static int marker = 0;
static int marker_comment = 0;
static const char* marker_format = "%f-%x-%03s.%e";
static enum MarkerMode marker_mode = MARKER_INCREMENT;
static char* fmt_basename = NULL;  /* used by generate_filename */
static char* fmt_extension = NULL; /* used by generate_filename */
static const char* program_name = NULL;
static const char* comment = "capdump-" VERSION " stream";
static const struct stream_stat* stream_stat = NULL;
static char mpid[8];
static int progress = -1;          /* if >0 progress reports is written to this file descriptor */

static const char* shortopts = "o:p:i:c:b:m:f:M:C:s::h";
static struct option longopts[]= {
	{"output",  required_argument, 0, 'o'},
	{"packets", required_argument, 0, 'p'},
	{"iface",   required_argument, 0, 'i'},
	{"comment", required_argument, 0, 'c'},
	{"bufsize", required_argument, 0, 'b'},
	{"marker",  required_argument, 0, 'm'},
	{"marker-format", required_argument, 0, 'f'},
	{"marker-mode",   required_argument, 0, 'M'},
	{"marker-comment", required_argument, 0, 'C'},
	{"progress", optional_argument, 0, 's'},
	{"help",    no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(void){
	printf("(C) 2011 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] [INPUT..] [OUTPUT]\n", program_name);
	printf("  -o, --output=FILE    Save output in capfile. [default=stdout]\n"
	       "  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	       "                       on. For other streams it is ignored.\n"
	       "  -p, --packets=INT    Stop capture after INT packages.\n"
	       "  -c, --comment        Set stream comment.\n"
	       "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	       "  -b, --bufsize=BYTES  Use BYTES buffer size [default depends on driver].\n"
	       "  -m, --marker=PORT    Split streams based on marker packet. See capdump(1) for\n"
	       "                       further description of this feature.\n"
	       "  -f, --marker-format  Renaming format for marker.\n"
	       "      --marker-mode    What to do when identical filename is generated. Valid\n"
	       "                       modes are [I]crement (default), [O]verwrite and [A]ppend.\n"
	       "      --marker-comment Use marker comment as the stream comment.\n"
	       "      --progress[=FD]  Write progress report to FD every 60 seconds.\n"
	       "  -h, --help           This text.\n");
	printf("\n");
	printf("Streams can be specified in the following formats:\n");
	printf("  - NN:NN:NN:NN:NN:NN  Listen to ethernet multicast stream.\n"
	       "  - tcp://IP[:PORT]    Listen to TCP unicast.\n"
	       "  - udp://IP[:PORT]    Listen to UDP broadcast.\n"
	       "  - FILENAME           Open capfile for reading.\n");
}

static void sig_handler(int signum){
	static const char* names[] = {"SIGINT", "SIGTERM", "unknown signal"};
	const char* name;
	switch ( signum ){
	case SIGINT: name = names[0]; break;
	case SIGTERM: name = names[1]; break;
	default: name = names[2];
	}

	static char timestr[64];
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

	if ( keep_running == 0 ){
		fprintf(stderr, "\r%s: [%s] Got %s again, aborting.\n", program_name, timestr, name);
		abort();
	}
	fprintf(stderr, "\r%s: [%s] Got %s, terminating gracefully.\n", program_name, timestr, name);
	keep_running = 0;
}

static void progress_report(int signum){
	static char buf[1024];
	static char timestr[64];
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

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

static const char* marker_flags(const struct marker* marker){
	static char buf[12];
	static char flag[8] = {'T', 0, };
	if ( marker->flags == 0 ){
		return "(not set)";
	}

	char* dst = buf;
	*dst++ = '[';
	for ( int i = 0; i < 8; i++ ){
		if ( marker->flags & (1<<i) ){
			*dst++ = flag[i];
		}
	}
	*dst++ = ']';
	return buf;
}

static void marker_report(const struct marker* marker){
	static char timestr[64];
	static char timestamp[200];
	static struct tm tm;

	/* timestamp for log */
	time_t t = time(NULL);
	tm = *localtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

	/* timestamp from marker */
	tm = *localtime((const time_t*)&marker->timestamp);
	strftime(timestamp, 200, "%a, %d %b %Y %T %z", &tm);

	fprintf(stderr, "%s: [%s] marker v%d found\n", program_name, timestr, marker->version);
	fprintf(stderr, "\tdata: exp=%d run=%d key=%d seq=%d\n", marker->exp_id, marker->run_id, marker->key_id, marker->seq_num);
	fprintf(stderr, "\tflags: %s [0x%02x]\n", marker_flags(marker), marker->flags);
	fprintf(stderr, "\ttimestamp: %s\n", timestamp);
}

static enum MarkerMode parse_marker_mode(const char* str){
	const char ch = tolower(str[0]);
	switch ( ch ){
	case 'i': return MARKER_INCREMENT;
	case 'o': return MARKER_OVERWRITE;
	case 'a': return MARKER_APPEND;
	default: 	return MARKER_INCREMENT;
	}
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

	if ( marker_mode == MARKER_INCREMENT ){
		/* try if the file exists already and append a suffix if it does */
		unsigned int suffix = 1;
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
	}

	return buffer;
}

static int open_next(stream_addr_t* addr, stream_t st, const struct marker* marker){
	/* generate next filename */
	const char* filename = generate_filename(marker_format, marker);

	/* test if user want to append to existing stream */
	if ( marker_mode == MARKER_APPEND && strcmp(filename, addr->local_filename) == 0){
		char* abs = realpath(filename, NULL);
		fprintf(stderr, "\tfilename: `%s' (appending)\n", abs ? abs : filename);
		free(abs);
		return 0;
	}

	/* close current stream */
	stream_close(st);
	st = NULL;

	/* open new stream */
	int ret;
	stream_addr_str(addr, filename, 0);
	if ( (ret=stream_create(&st, addr, NULL, mpid, marker_comment ? marker->comment : comment)) != 0 ){
		fprintf(stderr, "%s: stream_create() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret));
		return 1;
	}

	char* abs = realpath(filename, NULL);
	fprintf(stderr, "\tfilename: `%s'\n", abs ? abs : filename);
	free(abs);

	return 0;
}

static int handle_marker(const struct cap_header* cp, stream_addr_t* addr, stream_t* st){
	struct marker mark;
	if ( !(marker && is_marker(cp, &mark, marker)) ){
		return 0;
	}

	/* show marker */
	marker_report(&mark);

	/* abort if output is pipe */
	if ( strcmp("/dev/stdout", addr->local_filename) == 0 ){
		return 1;
	}

	/* termination marker */
	if ( mark.flags & MARKER_TERMINATE ){
		if ( *st ){
			stream_addr_str(addr, "", STREAM_ADDR_LOCAL);
			stream_close(*st);
			*st = NULL;
		}
		fprintf(stderr, "\ttermination flag set, stopping capture until next marker arrives\n");
		return 0;
	}

	if ( open_next(addr, *st, &mark) != 0 ){
		return 1; /* error already shown */
	}

	return 0;
}

static int write_packet(struct cap_header* cp, stream_t st){
	if ( !st ) return 0;

	int ret;
	cp->caplen = cp->caplen < cp->len ? cp->caplen : cp->len; /* truncate */
	if ( (ret=stream_copy(st, cp)) != 0 ) {
		fprintf(stderr, "%s: stream_copy() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret) );
		return ret;
	}

	return 0;
}

static void set_destination(stream_addr_t* addr, const char* str){
	stream_addr_aton(addr, str, STREAM_ADDR_GUESS, 0);
	free(fmt_basename);
	fmt_basename = strdup(str);
	fmt_extension = fmt_basename;
	while ( *fmt_extension && *fmt_extension != '.' ){
		fmt_extension++;
	}
	if ( *fmt_extension ){
		*fmt_extension++ = 0;
	}
}

int main(int argc, char **argv){
	fprintf(stderr, "capdump-%s\n", caputils_version(NULL));
	int op, option_index = -1;

	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	char* iface = NULL;
	size_t buffer_size = 0;
	stream_addr_t output = STREAM_ADDR_INITIALIZER;
	unsigned int max_packets = 0;
	unsigned long written_packets = 0;

	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'o':
			set_destination(&output, optarg);
			break;

		case 'p':
			max_packets = atoi(optarg);
			break;

		case 'c':
			comment = optarg;
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

		case 'M': /* --marker-mode */
			marker_mode = parse_marker_mode(optarg);
			break;

		case 'C': /* --marker-comment */
			marker_comment = 1;
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
				fprintf(stderr, "flag --%s declared but not handled\n", longopts[option_index].name);
			} else {
				fprintf(stderr, "flag -%c declared but not handled\n", op);
			}
			abort();
		}
		option_index = -1;
	}

	stream_t src;
	stream_t dst;
	long ret;

	/* use stdout as default output if connected stdout is redirected */
	if ( !(stream_addr_is_set(&output) || isatty(STDOUT_FILENO)) ){
		stream_addr_str(&output, "/dev/stdout", 0);
	}

	/* if no output was given using -o or redirection grab the last positional argument */
	if ( !stream_addr_is_set(&output) ){
		if ( optind < argc ){
			set_destination(&output, argv[argc-1]);
			argc--;
		} else {
			show_usage();
			exit(0);
		}
	}

	/* Install signal handler so loop can be aborted. Handlers are installed
	 * before opening streams in case they block and SIGINT is passed to
	 * terminate blocking call. */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* open input stream (using a small buffer so pipes will fill faster) */
	if ( (ret=stream_from_getopt(&src, argv, optind, argc, iface, "-", program_name, buffer_size)) != 0 ) {
		return 1;
	}

	/* set hostname as mpid */
	gethostname(mpid, 8);

	/* open output stream */
	if ( (ret=stream_create(&dst, &output, NULL, mpid, comment)) != 0 ){
		fprintf(stderr, "stream_create() failed with code 0x%08lX: %s\n", ret, caputils_error_string(ret));
		return 1;
	}
	stream_stat = stream_get_stat(src);

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

		if ( handle_marker(cp, &output, &dst) != 0 ){
			break; /* error already shown */
		}

		if ( write_packet(cp, dst) != 0 ){
			break; /* error already shown */
		}

		written_packets++;
		if ( max_packets > 0 && stream_stat->read >= max_packets ){
				break;
		}
	}

	fprintf(stderr, "%s: There was a total of %'"PRIu64" packets recv.\n", program_name, stream_stat->recv);
	fprintf(stderr, "%s: There was a total of %'"PRIu64" packets read.\n", program_name, stream_stat->read);
	fprintf(stderr, "%s: There was a total of %'ld packets writen.\n", program_name, written_packets);

	stream_close(src);
	stream_close(dst);
	stream_addr_reset(&output);
	free(fmt_basename);

	return 0;
}
