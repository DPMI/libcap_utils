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
static const char* program_name = NULL;
static const char* dst_filename = "/dev/stdout";
static const char* src_filename = "/dev/stdin";
static const char* rej_filename = NULL;
static int keep_running = 1;

static const char* shortopts = "i:o:r:h";
static struct option longopts[] = {
	{"input",   required_argument, 0, 'i'},
	{"output",  required_argument, 0, 'o'},
	{"rejects", required_argument, 0, 'r'},
	{"help",    no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(){
	printf("%s-"VERSION"\n", program_name);
	printf("(C) 2011 david.sveningsson@bth.se\n"
	       "Usage: %s [-i FILE] [-o FILE] [OPTIONS...]\n"
	       "  -i, --input=FILE            read from FILE [default stdin].\n"
	       "  -o, --output=FILE           write to FILE [default stdout].\n"
	       "  -r, --rejects=FILE          write packets not matching to FILE.\n"
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
    case 'o':
      dst_filename = optarg;
      break;

    case 'i':
      src_filename = optarg;
      break;

    case 'r':
	    rej_filename = optarg;
	    break;

    case 'h':
	    show_usage();
      exit(0);
      break;
    }
  }

  int ret;
  stream_addr_t addr;
  stream_t src;
  stream_t dst;
  stream_t rej;

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
  filter_print(&filter, stdout, 0);

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
	  if ( filter_match(&filter, cp->payload, cp) ){
		  target = dst;
	  } else if ( rej ){
		  target = rej;
	  }

	  /* copy packet */
	  if ( (ret=stream_copy(target, cp)) != 0 ){
		  fprintf(stderr, "%s: stream_copy() returned %d: %s\n", program_name, ret, caputils_error_string(ret));
		  keep_running = 0;
	  }
  }

  filter_close(&filter);

  if ( ret != 0 && ret != -1 ){
	  fprintf(stderr, "%s: stream_read() returned %d: %s\n", program_name, ret, caputils_error_string(ret));
	  return 1;
  }

  return 0;
}
