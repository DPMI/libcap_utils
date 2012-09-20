#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/stream.h>
#include <caputils/filter.h>
#include <caputils/capture.h>
#include <caputils/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

static const char* program_name = NULL;
static const char* dst_filename = NULL;
static const char* src_filename = NULL;
static const char* rej_filename = NULL;
static int keep_running = 1;
static int invert = 0;
static int quiet = 0;

static const char* shortopts = "i:o:r:vqh";
static struct option longopts[] = {
	{"input",   required_argument, 0, 'i'},
	{"output",  required_argument, 0, 'o'},
	{"rejects", required_argument, 0, 'r'},
	{"invert",  no_argument,       0, 'v'},
	{"quiet",   no_argument,       0, 'q'},
	{"help",    no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(){
	printf("%s-"VERSION_FULL"\n", program_name);
	printf("(C) 2011 david.sveningsson@bth.se\n"
	       "Usage: %s [-i FILE] [-o FILE] [OPTIONS...]\n"
	       "  -i, --input=FILE            read from FILE [default stdin].\n"
	       "  -o, --output=FILE           write to FILE [default stdout].\n"
	       "  -r, --rejects=FILE          write packets not matching to FILE.\n"
	       "  -v, --invert                invert filter.\n"
	       "  -q, --quiet                 suppress output.\n"
	       "  -h, --help                  help (this text).\n"
	       "\n", program_name);
	filter_from_argv_usage();
}

void handle_sigint(int signum){
	if ( keep_running ){
		fprintf(stderr, "\r%s: got SIGINT, terminating.\n", program_name);
		keep_running = 0;
	} else {
		fprintf(stderr, "\r%s: got SIGINT again, aborting.\n", program_name);
		abort();
	}
}

int main(int argc, char* argv[]){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	struct filter filter;
	if ( filter_from_argv(&argc, argv, &filter) != 0 ){
		fprintf(stderr, "Failed to create filter, aborting.\n");
		exit(1); /* errors already displayed (on stderr) */
	}

	int index = 0;
	int op = 0;
	while ( (op=getopt_long(argc, argv, shortopts, longopts, &index)) != -1 ){
		switch (op){
		case 'o': /* --output */
			dst_filename = optarg;
			break;

		case 'i': /* --input */
			src_filename = optarg;
			break;

		case 'r': /* --rejects */
			rej_filename = optarg;
			break;

		case 'v': /* --invert */
			invert = 1;
			break;

		case 'q': /* --quiet */
			quiet = 1;
			break;

		case 'h': /* --help */
			show_usage();
			exit(0);
		}
	}

	int ret;
	stream_addr_t addr;
	stream_t src = NULL;
	stream_t dst = NULL;
	stream_t rej = NULL;

	/* ensure not reading/writing capfiles from terminal */
	if ( src_filename == NULL && isatty(STDIN_FILENO) ){
		fprintf(stderr, "Cannot read input from stdin when it is connected to a terminal.\n");
		fprintf(stderr, "Either specify another destination with --input, use redirection or pipe from another process.\n");
		exit(1);
	}
	if ( dst_filename == NULL && isatty(STDOUT_FILENO) ){
		fprintf(stderr, "Cannot output to stdout when it is connected to a terminal.\n");
		fprintf(stderr, "Either specify another destination with --output, use redirection or pipe to another process.\n");
		exit(1);
	}

	/* defaults */
	src_filename = src_filename ? src_filename : "/dev/stdin";
	dst_filename = dst_filename ? dst_filename : "/dev/stdout";

	/* open source */
	stream_addr_str(&addr, src_filename, 0);
	if ( (ret=stream_open(&src, &addr, NULL, 0)) != 0 ){
		fprintf(stderr, "%s: failed to open input `%s': %s\n", program_name, src_filename, caputils_error_string(ret));
		return 1;
	}

	/* open destination */
	stream_addr_str(&addr, dst_filename, 0);
	if ( (ret=stream_create(&dst, &addr, NULL, "CONV", "capfilter" VERSION " filtered stream")) != 0 ){
		fprintf(stderr, "%s: failed to open output `%s': %s\n", program_name, dst_filename, caputils_error_string(ret));
		return 1;
	}

	/* open rejects */
	if ( rej_filename ){
		stream_addr_str(&addr, rej_filename, 0);
		if ( (ret=stream_create(&rej, &addr, NULL, "CONV", "capfilter" VERSION " filtered stream")) != 0 ){
			fprintf(stderr, "%s: failed to open rejects `%s': %s\n", program_name, rej_filename, caputils_error_string(ret));
			return 1;
		}
	}

	/* handle signals */
	signal(SIGINT, handle_sigint);

	/* show filter */
	if ( !quiet ){
		filter_print(&filter, stderr, 0);
	}

	uint64_t matched = 0;
	const struct stream_stat* stats = stream_get_stat(src);
	while ( keep_running ){
		caphead_t cp;
		struct timeval tv = {1,0};
		switch ( (ret=stream_read(src, &cp, NULL, &tv)) ){
		case EAGAIN: /* timeout */
			continue;

		case 0: /* success */
			break;

		default: /* error */
			keep_running = 0;
			continue;
		}

		/* decide what to do with the packet */
		stream_t target = 0;
		const int match = filter_match(&filter, cp->payload, cp);
		const int post_match = invert ? (1-match) : match;
		if ( post_match ){
			target = dst;
			matched++;
		} else if ( rej ){
			target = rej;
		}

		/* copy packet */
		if ( target && (ret=stream_copy(target, cp)) != 0 ){
			fprintf(stderr, "%s: stream_copy() returned %d: %s\n", program_name, ret, caputils_error_string(ret));
			keep_running = 0;
		}
	}

	if ( !quiet ){
		fprintf(stderr, "%s: There was a total of %'"PRIu64" packets read.\n", program_name, stats->read);
		fprintf(stderr, "%s: There was a total of %'"PRIu64" packets matched.\n", program_name, matched);
	}

	filter_close(&filter);

	if ( ret != 0 && ret != -1 ){
		fprintf(stderr, "%s: stream_read() returned %d: %s\n", program_name, ret, caputils_error_string(ret));
		return 1;
	}

	return 0;
}
