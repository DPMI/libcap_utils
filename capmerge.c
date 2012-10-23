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
static FILE* sort = NULL;
static int quiet = 0;

static const char* shortopts = "o:c:sqh";
static struct option longopts[] = {
	{"output",     required_argument, 0, 'o'},
	{"comment",    required_argument, 0, 'c'},
	{"sort",       no_argument,       0, 's'},
	{"quiet",      no_argument,       0, 'q'},
	{"help",       no_argument,       0, 'h'},
	{0,0,0,0},
};

static void show_usage(){
	printf("capmerge-" VERSION_FULL "\n");
	printf("usage: %s [OPTIONS..] -o OUTPUT FILES..\n"
	       "\n"
	       "  -o, --output=FILE    Write merged file to FILE.\n"
	       "  -c, --comment=STRING Set stream comment.\n"
	       "  -s, --sort           Sort out-of-order packets based on timestamp.\n"
	       "  -q, --quiet          Quiet output (no progressbar)\n"
	       "  -h, --help           This text.\n",
	       program_name);
}

static size_t min(size_t a, size_t b){
	return (a<b)?a:b;
}

int main(int argc, char* argv[]){
	const char* comment = "capmerge-" VERSION " stream";
	char* sort_buffer = NULL;
	size_t sort_size = 0;
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

		case 's': /* --sort */
			sort = open_memstream(&sort_buffer, &sort_size);
			break;

		case 'q': /* --quiet */
			quiet = 1;
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
		fprintf(stderr, "%s: Cannot output to stdout when it is connected to a terminal.\n", program_name);
		fprintf(stderr, "%s: Either specify another destination with --output, use redirection or pipe to another process.\n", program_name);
		return 1;
	}

	/* open output stream */
	stream_t dst;
	stream_addr_t real_addr = output;
	if ( sort ) stream_addr_fp(&real_addr, sort, STREAM_ADDR_FCLOSE);
	if ( (ret=stream_create(&dst, &real_addr, NULL, "CONV", comment)) != 0 ){
		fprintf(stderr, "stream_create() failed with code 0x%08X: %s\n", ret, caputils_error_string(ret));
		return 1;
	}

	/* open input streams */
	const size_t files = argc - optind;
	stream_t st[files];
	for ( int i = optind, n = 0; i < argc; i++, n++ ){
		stream_addr_t addr;
		stream_addr_str(&addr, argv[i], 0);

		int ret;
		if ( (ret=stream_open(&st[n], &addr, NULL, 0)) != 0 ){
			fprintf(stderr, "%s: when opening `%s':\n", program_name, argv[i]);
			fprintf(stderr, "%s:   stream_open(..) returned %d: %s\n", program_name, ret, caputils_error_string(ret));
			exit(1);
		}
	}

	/* read packets */
	unsigned int streams = files;
	unsigned long packets = 0;
	while ( streams > 0 ){
		struct cap_header* pkt[streams];

		/* take a peek at all open streams */
		for ( unsigned int i = 0; i < streams; i++ ){
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
		for ( unsigned int i = 0; i < streams; i++ ){
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

		packets++;
		cp->caplen = min(cp->caplen, cp->len); /* truncate when caplen > len */
		if ( (ret=stream_write(dst, cp, sizeof(struct cap_header) + cp->caplen)) != 0 ){
			fprintf(stderr, "%s: stream_write(..) returned %d: %s\n", program_name, ret, caputils_error_string(ret));
			stream_close(dst);
			exit(1);
		}
	}

	for ( unsigned int i = 0; i < streams; i++ ){
		stream_close(st[i]);
	}
	stream_close(dst);

	if ( sort ){
		if ( !quiet ){
			fprintf(stderr, "%s starting sort of %zd bytes\n", program_name, sort_size);
		}

		if ( (ret=stream_create(&dst, &output, NULL, "CONV", comment)) != 0 ){
			fprintf(stderr, "stream_create() failed with code 0x%08X: %s\n", ret, caputils_error_string(ret));
			return 1;
		}

		struct file_header_t* fh = (struct file_header_t*)sort_buffer;
		const char* begin = sort_buffer + fh->header_offset + fh->comment_size;
		const char* end = sort_buffer + sort_size;

		unsigned long int written = 0;
		do {
			const struct cap_header* pkt = NULL;
			timepico cur = {-1, -1};

			/* find "smallest" packet, i.e. packet will smallest timestamp */
			const char* ptr = begin;
			while ( ptr < end ){
				const struct cap_header* cp = (const struct cap_header*)ptr;
				if ( cp->len > 0 && timecmp(&cur, &cp->ts) > 0 ){
					pkt = cp;
					cur = cp->ts;
				}

				ptr += cp->caplen + sizeof(struct cap_header);
			}

			/* stop if there is no more packets */
			if ( !pkt ) break;

			/* copy */
			written++;
			stream_copy(dst, pkt);

			/* move forward */
			const struct cap_header* cp = (const struct cap_header*)begin;
			begin += cp->caplen + sizeof(struct cap_header);

			if ( !quiet && (written % 250 == 0) ){
				fprintf(stderr, "\r%lu / %lu (%p - %p)", written, packets, begin, end);
				fflush(stderr);
			}
		} while ( 1 );

		if ( !quiet ){
			fprintf(stderr, "\r%lu / %lu (%p - %p)\n", written, packets, begin, end);
			fflush(stderr);
		}
		stream_close(dst);
		free(sort_buffer);
	}

	return 0;
}
