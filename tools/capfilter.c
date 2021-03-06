/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/stream.h>
#include <caputils/filter.h>
#include <caputils/capture.h>
#include <caputils/utils.h>
#include <caputils/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

static inline int min(int a, int b){
	return a<b?a:b;
}

static const char* program_name = NULL;
static const char* dst_filename = NULL;
static const char* src_filename = NULL;
static const char* rej_filename = NULL;
static int keep_running = 1;
static int invert = 0;
static int quiet = 0;
static unsigned int max_read = 0;
static unsigned int max_matched = 0;

static const char* shortopts = "p:m:i:o:r:vqh";
static struct option longopts[] = {
	{"packets", required_argument, 0, 'p'},
	{"matched", required_argument, 0, 'm'},
	{"input",   required_argument, 0, 'i'},
	{"output",  required_argument, 0, 'o'},
	{"rejects", required_argument, 0, 'r'},
	{"invert",  no_argument,       0, 'v'},
	{"quiet",   no_argument,       0, 'q'},
	{"help",    no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(){
	printf("%s-%s\n", program_name, caputils_version(NULL));
	printf("(C) 2011 david.sveningsson@bth.se\n"
	       "Usage: %s [OPTIONS...] [SRC] [DST] \n"
	       "  -p, --packets=N             Stop after N read packets.\n"
	       "  -m, --matched=N             Stop after N matched packets.\n"
	       "  -i, --input=FILE            read from FILE [default stdin].\n"
	       "  -o, --output=FILE           write to FILE [default stdout].\n"
	       "  -r, --rejects=FILE          write packets not matching to FILE.\n"
	       "  -v, --invert                invert filter.\n"
	       "  -q, --quiet                 suppress output.\n"
	       "  -h, --help                  help (this text).\n"
	       "\n", program_name);
	filter_from_argv_usage();
}

static void handle_sigint(int signum){
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
		fprintf(stderr, "%s: Failed to create filter, aborting.\n", program_name);
		exit(1); /* errors already displayed (on stderr) */
	}

	int index = 0;
	int op = 0;
	while ( (op=getopt_long(argc, argv, shortopts, longopts, &index)) != -1 ){
		switch (op){
		case 'p': /* --packets */
			max_read = atoi(optarg);
			break;

		case 'm': /* --matched */
			max_matched = atoi(optarg);
			break;

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

	/* use positional arguments unless -i or -o has been specified (for
	 * compatibility with older versions) */
	if ( !(src_filename && dst_filename) ){
		const int nargs = argc-optind;
		switch ( nargs ){
		case 2:
			dst_filename = argv[optind+1];
		case 1:
			src_filename = argv[optind];
		case 0:
			break;
		}
	}

	int ret;
	stream_addr_t addr = STREAM_ADDR_INITIALIZER;
	stream_t src = NULL;
	stream_t dst = NULL;
	stream_t rej = NULL;

	/* ensure not reading/writing capfiles from terminal */
	if ( src_filename == NULL && isatty(STDIN_FILENO) ){
		fprintf(stderr, "%s: Cannot read input from stdin when it is connected to a terminal.\n", program_name);
		fprintf(stderr, "%s: Either specify another destination with --input, use redirection or pipe from another process.\n", program_name);
		exit(1);
	}
	if ( dst_filename == NULL && isatty(STDOUT_FILENO) ){
		fprintf(stderr, "%s: Cannot output to stdout when it is connected to a terminal.\n", program_name);
		fprintf(stderr, "%s: Either specify another destination with --output, use redirection or pipe to another process.\n", program_name);
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

		/* truncate if requested */
		if ( filter.caplen != (unsigned int)-1 ){
			cp->caplen = min(filter.caplen, cp->caplen);
		}

		/* copy packet */
		if ( target && (ret=stream_copy(target, cp)) != 0 ){
			fprintf(stderr, "%s: stream_copy() returned %d: %s\n", program_name, ret, caputils_error_string(ret));
			keep_running = 0;
		}

		if ( (max_read > 0 && stats->read >= max_read) || (max_matched > 0 && matched >= max_matched) ){
			/* Read enough pkts lets break. */
			break;
		}
	}

	if ( !quiet ){
		fprintf(stderr, "%s: There was a total of %'"PRIu64" packets read.\n", program_name, stats->read);
		fprintf(stderr, "%s: There was a total of %'"PRIu64" packets matched.\n", program_name, matched);
	}

	filter_close(&filter);
	stream_close(src);
	stream_close(dst);
	stream_close(rej);
	stream_addr_reset(&addr);

	if ( ret != 0 && ret != -1 ){
		fprintf(stderr, "%s: stream_read() returned %d: %s\n", program_name, ret, caputils_error_string(ret));
		return 1;
	}

	return 0;
}
