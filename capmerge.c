#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/caputils.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

static const char* program_name;

static const char* shortopts = "o:c:sVh";
static struct option longopts[] = {
	{"output",     required_argument, 0, 'o'},
	{"comment",    required_argument, 0, 'c'},
	{"sort",       no_argument,       0, 's'},
	{"help",       no_argument,       0, 'h'},
	{0,0,0,0},
};

static void show_usage(){
	printf("usage: %s [OPTIONS..] -o OUTPUT FILES..\n"
	       "\n"
	       "  -o, --output=FILE    Write merged file to FILE.\n"
	       "  -c, --comment=STRING Set stream comment.\n"
	       "  -s, --sort           Sort packets based on timestamp.\n"
	       "  -h, --help           This text.\n",
	       program_name);
}

static size_t min(size_t a, size_t b){
	return (a<b)?a:b;
}

int main(int argc, char* argv[]){
	fprintf(stderr, "capmerge-" VERSION_FULL "\n");

	const char* comment = "capmerge-" VERSION " stream";
	stream_addr_t output;
	stream_addr_aton(&output, "/dev/stdout", STREAM_ADDR_CAPFILE, STREAM_ADDR_LOCAL);

	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'o': /* --output */
			stream_addr_aton(&output, optarg, STREAM_ADDR_CAPFILE, STREAM_ADDR_LOCAL);
			break;

		case 'c': /* --comment */
			comment = optarg;
			break;

		case 'h': /* --help */
			show_usage();
			exit(0);

		default:
			fprintf(stderr, "%s: argument '-%c' declared but not handled.\n", program_name, op);
			abort();
		}
	}

	int ret;

	/* cannot output to stdout if it is a terminal */
	if ( stream_addr_type(&output) == STREAM_ADDR_CAPFILE &&
	     strcmp("/dev/stdout", output.local_filename) == 0 &&
	     isatty(STDOUT_FILENO) ){
		fprintf(stderr, "%s: Cannot output to stdout when is is connected to a terminal.\n", program_name);
		fprintf(stderr, "%s: Either specify another destination with --output, use redirection or pipe to another process.\n", program_name);
		return 1;
	}

	/* open output stream */
	stream_t dst;
	if ( (ret=stream_create(&dst, &output, NULL, "CONV", comment)) != 0 ){
		fprintf(stderr, "stream_create() failed with code 0x%08X: %s\n", ret, caputils_error_string(ret));
		return 1;
	}

	/* open input streams */
	const size_t files = argc - optind;
	stream_t st[files];
	for ( unsigned int i = optind, n = 0; i < argc; i++, n++ ){
		stream_addr_t addr;
		stream_addr_str(&addr, argv[i], 0);

		int ret;
		if ( (ret=stream_open(&st[n], &addr, NULL, 0)) != 0 ){
			fprintf(stderr, "%s: stream_open(..) returned %d: %s\n", program_name, ret, caputils_error_string(ret));
			exit(1);
		}
	}

	/* read packets */
	int streams = files;
	while ( streams > 0 ){
		struct cap_header* pkt[streams];

		/* take a peek at all open streams */
		for ( int i = 0; i < streams; i++ ){
			int ret;
			switch ( (ret=stream_peek(st[i], &pkt[i], NULL)) ){
			case 0:
				break;

			case EAGAIN:
				pkt[i] = NULL;
				break;

			default:
				pkt[i] = NULL;
				stream_close(st[i]);
				st[i] = st[streams-1];
				streams--;
				if ( ret != -1 ){
					fprintf(stderr, "%s: stream_peek(..) returned %d: %s\n", program_name, ret, caputils_error_string(ret));
				}
			}
		}

		/* find newest packet */
		int oldest = -1;
		timepico cur = {-1, -1};
		for ( int i = 0; i < streams; i++ ){
			if ( pkt[i] && timecmp(&pkt[i]->ts, &cur) < 0 ){
				oldest = i;
				cur = pkt[i]->ts;
			}
		}

		/* no packet was found */
		if ( oldest < 0 ){
			continue;
		}

		struct cap_header* cp;
		stream_read(st[oldest], &cp, NULL, NULL);

		if ( (ret=stream_write(dst, cp, sizeof(struct cap_header) + min(cp->caplen, cp->len))) != 0 ){
			fprintf(stderr, "%s: stream_write(..) returned %d: %s\n", program_name, ret, caputils_error_string(ret));
			stream_close(dst);
			exit(1);
		}
	}

	for ( unsigned int i = 0; i < streams; i++ ){
		stream_close(st[i]);
	}
	stream_close(dst);

	return 0;
}
