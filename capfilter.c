#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

static char* dst_filename = NULL;
static char* src_filename = NULL;

int main(int argc, char* argv[]){
  static struct option options[] = {
    {"input",  1, 0, 'i'},
    {"output", 1, 0, 'o'},
    {"help",   0, 0, 'h'},
    {0, 0, 0, 0}
  };

  struct filter filter;
  if ( filter_from_argv(&argc, argv, &filter) != 0 ){
    fprintf(stderr, "Failed to create filter, aborting.\n");
    exit(1); /* errors already displayed (on stderr) */
  }

  int index = 0;
  int op = 0;
  while ( (op=getopt_long(argc, argv, "i:o:h", options, &index)) != -1 ){
    switch (op){
    case 'o':
      dst_filename = optarg;
      break;

    case 'i':
      src_filename = optarg;
      break;

    case 'h':
      printf("capfilter-" VERSION "\n");
      printf("(C) 2011 david.sveningsson@bth.se\n"),
      printf("Usage: %s [-i FILE] [-o FILE] [OPTIONS...]\n", argv[0]);
      printf("  -i, --input                 read from FILE.\n");
      printf("  -o, --output                write to FILE.\n");
      printf("  -h, --help                  help (this text).\n");
      printf("\n");
      filter_from_argv_usage();
      exit(0);
      break;
    }
  }

  printf("in: %s out: %s\n", src_filename, dst_filename);
  filter_print(&filter, stdout, 0);

  filter_close(&filter);

  return 0;
}
