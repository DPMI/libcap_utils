#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>

static const char* program_name = NULL;
static struct option long_options[]= {
  {"output",  required_argument, 0, 'o'},
  {"packets", required_argument, 0, 'p'},
  {"iface",   required_argument, 0, 'i'},
  {"comment", required_argument, 0, 'c'},
  {"help",    no_argument,       0, 'h'},
  {0, 0, 0, 0} /* sentinel */
};

static void show_usage(){
  printf("capdump-" VERSION "\n");
  printf("(C) 2011 David Sveningsson <david.sveningsson@bth.se>\n");
  printf("Usage: %s [OPTIONS] STREAM\n", program_name);
  printf("  -o, --output=FILE    Save output in capfile. [default=stdout]\n"
	 "  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	 "                       on. For other streams it is ignored.\n"
	 "  -p, --packets=INT    Stop capture after INT packages.\n"
	 "  -c, --comment        Set stream comment.\n"	 
	 "  -h, --help           This text.\n");
  printf("\n");
  printf("Streams can be specified in the following formats:\n");
  printf("  - NN:NN:NN:NN:NN:NN  Listen to ethernet multicast stream.\n"
	 "  - tcp://IP[:PORT]    Listen to TCP unicast.\n"
	 "  - udp://IP[:PORT]    Listen to UDP broadcast.\n"
	 "  - FILENAME           Open capfile for reading.\n");
}

int main(int argc, char **argv){
  extern int optind, opterr, optopt;
  int op, option_index = -1;
  program_name = strrchr(argv[0], '/') + 1;

  char* comment = "capdump-" VERSION " stream";
  char* iface = NULL;
  destination_t input;
  destination_t output;
  destination_aton(&output, "/dev/stdout", DEST_CAPFILE, DEST_LOCAL);

  long max_packets = -1;

  while ( (op = getopt_long(argc, argv, "ho:p:c:i:", long_options, &option_index)) != -1 ){
    switch (op){
    case 0:   /* long opt */
    case '?': /* unknown opt */
      break;

    case 'o':
      destination_aton(&output, optarg, 0, DEST_GUESS);
      break;

    case 'p':
      max_packets = atoi(optarg);
      break;

    case 'c':
      comment = optarg;
      break;

    case 'i':
      iface = optarg;
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

  struct stream* src;
  struct stream* dst;
  int ret;

  /* parse stream address */
  if ( (ret=destination_aton(&input, argv[optind], DEST_NONE, DEST_GUESS)) != 0 ){
    fprintf(stderr, "Failed to parse stream address: %s\n", caputils_error_string(ret));
    return 1;
  }

  /* ensure iface has been configured for ethernet streams */
  if ( input.type == DEST_ETHERNET && !iface ){
    fprintf(stderr, "Ethernet streams require --iface\n");
    return 1;
  }

  /* open input stream */
  static char* type[4] = {"file", "ethernet", "udp", "tcp"};
  fprintf(stderr, "Opening %s stream: %s\n", type[input.type], destination_ntoa(&input));
  if ( (ret=openstream(&src, &input, iface, 0)) != 0 ) {
    fprintf(stderr, "openstream() failed with code 0x%08X: %s\n", ret, caputils_error_string(ret));
    return 1;
  }

  /* open output stream */
  if ( (ret=createstream(&dst, &output, NULL, stream_get_mampid(src), comment)) != 0 ){
    fprintf(stderr, "createstream() failed with code 0x%08X: %s\n", ret, caputils_error_string(ret));
    return 1;
  }

  struct file_version version;
  stream_get_version(src, &version);

//output fileheader
  fprintf(stderr, "ver: %d.%d id: %s \n comments: %s\n",
	  version.major, 
	  version.minor, 
	  stream_get_mampid(src), 
	  stream_get_comment(src));

  cap_head* cp;
  size_t len = sizeof(struct cap_header);

  long matches = 0;
  while ( 1 ){
    long ret = stream_read(src, &cp, NULL);
    if ( ret == EAGAIN ){
      continue;
    } else if ( ret != 0 ){
      break;
    }

    matches++;
    if( !(stream_write(dst, (char*)cp, cp->caplen + len)) ) {
      fprintf(stderr, "Problems writing data to file!");
    }

    if ( matches >= max_packets ){
      break;
    }
  }

  closestream(src);
  closestream(dst);

  fprintf(stderr, "There was a total of %ld pkts that matched the filter.\n", matches);
  return 0;
}
