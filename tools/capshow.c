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
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils/stream.h"
#include "caputils/filter.h"
#include "caputils/utils.h"
#include "caputils/marker.h"
#include "caputils/log.h"
#include "caputils/packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

static int keep_running = 1;
static unsigned int flags = FORMAT_REL_TIMESTAMP;
static unsigned int max_packets = 0;
static unsigned int max_matched_packets = 0;
static const char* iface = NULL;
static struct timeval timeout = {1,0};
static const char* program_name = NULL;

void handle_sigint(int signum){
	if ( keep_running == 0 ){
		fprintf(stderr, "\rGot SIGINT again, terminating.\n");
		abort();
	}
	fprintf(stderr, "\rAborting capture.\n");
	keep_running = 0;
}

enum {
	ARGUMENT_VERSION = 256,
};

static const char* shortopts = "p:c:i:t:dDar1234xHh";
static struct option longopts[]= {
	{"packets",  required_argument, 0, 'p'},
	{"count",    required_argument, 0, 'c'},
	{"iface",    required_argument, 0, 'i'},
	{"timeout",  required_argument, 0, 't'},
	{"calender", no_argument,       0, 'd'},
	{"localtime",no_argument,       0, 'D'},
	{"absolute", no_argument,       0, 'a'},
	{"relative", no_argument,       0, 'r'},
	{"hexdump",  no_argument,       0, 'x'},
	{"headers",  no_argument,       0, 'H'},
	{"version",  no_argument,       0, ARGUMENT_VERSION},
	{"help",     no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(void){
	printf("%s-%s\n", program_name, caputils_version(NULL));
	printf("(C) 2004 Patrik Arlos <patrik.arlos@bth.se>\n");
	printf("(C) 2012 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] STREAM\n", program_name);
	printf("  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	       "                       on. For other streams it is ignored.\n"
	       "  -p, --packets=N      Stop after N read packets.\n"
	       "  -c, --count=N        Stop after N matched packets.\n"
	       "                       If both -p and -c is used, what ever happens first will stop.\n"
	       "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	       "      --version        Show program version and exit.\n"
	       "  -h, --help           This text.\n"
	       "\n"
	       "Formatting options:\n"
	       "  -1                   Show only DPMI information.\n"
	       "  -2                     .. include link layer.\n"
	       "  -3                     .. include transport layer.\n"
	       "  -4                     .. include application layer. [default]\n"
	       "  -H, --headers        Show layer headers.\n"
	       "  -x, --hexdump        Write full packet content as hexdump.\n"
	       "  -d, --calender       Show timestamps in human-readable format (UTC).\n"
	       "  -D, --localtime      Show timestamps in human-readable format (local time).\n"
	       "  -a, --absolute       Show absolute timestamps.\n"
	       "  -r, --relative       Show timestamps relative to first packet. [default]\n"
	       "\n");
	filter_from_argv_usage();
}

static void show_version(void){
	printf("%s-%s\n", program_name, caputils_version(NULL));
}

int main(int argc, char **argv){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	struct filter filter;
	if ( filter_from_argv(&argc, argv, &filter) != 0 ){
		return 0; /* error already shown */
	}

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case '1':
		case '2':
		case '3':
		case '4':
		{
			const unsigned int mask = (7<<FORMAT_LAYER_BIT);
			flags &= ~mask; /* reset all layer bits */
			flags |= (op-'0')<<FORMAT_LAYER_BIT;
			break;
		}

		case 'd': /* --calender */
			flags |= FORMAT_DATE_STR | FORMAT_DATE_UTC;
			break;

		case 'D': /* --localtime */
			flags |= FORMAT_DATE_STR | FORMAT_DATE_LOCALTIME;
			break;

		case 'a': /* --absolute */
			flags &= ~FORMAT_REL_TIMESTAMP;
			break;

		case 'r': /* --relative */
			flags |= FORMAT_REL_TIMESTAMP;
			break;

		case 'H': /* --headers */
			flags |= FORMAT_HEADER;
			break;

		case 'p': /* --packets */
			max_packets = atoi(optarg);
			break;

		case 'c': /* --packets */
			max_matched_packets = atoi(optarg);
			break;

		case 't': /* --timeout */
		{
			int tmp = atoi(optarg);
			timeout.tv_sec  = tmp / 1000;
			timeout.tv_usec = tmp % 1000 * 1000;
		}
		break;

		case 'x': /* --hexdump */
			flags |= FORMAT_HEXDUMP;
			break;

		case 'i': /* --iface */
			iface = optarg;
			break;

		case ARGUMENT_VERSION: /* --version */
			show_version();
			return 0;

		case 'h': /* --help */
			show_usage();
			return 0;

		default:
			fprintf (stderr, "%s: argument '-%c' declared but not handled\n", argv[0], op);
		}
	}

	int ret;

	/* Open stream(s) */
	struct stream* stream;
	if ( (ret=stream_from_getopt(&stream, argv, optind, argc, iface, "-", program_name, 0)) != 0 ) {
		return ret; /* Error already shown */
	}
	const stream_stat_t* stat = stream_get_stat(stream);
	stream_print_info(stream, stderr);

	
	/* handle C-c */
	signal(SIGINT, handle_sigint);

	/* setup formatter */
	struct format format;
	format_setup(&format, flags);

	uint64_t matched = 0;
	while ( keep_running ) {
		/* A short timeout is used to allow the application to "breathe", i.e
		 * terminate if SIGINT was received. */
		struct timeval tv = timeout;

		/* Read the next packet */
		cap_head* cp;
		ret = stream_read(stream, &cp, NULL, &tv);
		if ( ret == EAGAIN ){
			continue; /* timeout */
		} else if ( ret != 0 ){
			break; /* shutdown or error */
		}

		/* identify connection even if filter doesn't match so id will be
		 * deterministic when changing the filter */
		connection_id(cp);

		if ( filter_match(&filter, cp->payload, cp) ){
			format_pkg(stdout, &format, cp);
			matched++;
		} else {
			format_ignore(stdout, &format, cp);
		}

		if ( max_packets > 0 && stat->matched >= max_packets) {
			/* Read enough pkts lets break. */
			break;
		}
		if ( max_matched_packets > 0 && matched >= max_matched_packets) {
			/* Read enough pkts lets break. */
			break;
		}
	}

	/* if ret == -1 the stream was closed properly (e.g EOF or TCP shutdown)
	 * In addition EINTR should not give any errors because it is implied when the
	 * user presses C-c */
	if ( ret > 0 && ret != EINTR ){
		fprintf(stderr, "stream_read() returned 0x%08X: %s\n", ret, caputils_error_string(ret));
	}

	/* Write stats */
	fprintf(stderr, "%"PRIu64" packets read.\n", stat->read);
	fprintf(stderr, "%"PRIu64" packets matched filter.\n", matched);

	/* Release resources */
	stream_close(stream);
	filter_close(&filter);

	return 0;
}
