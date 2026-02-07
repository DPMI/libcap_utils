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
#include <config.h>
#endif

#include <caputils/caputils.h>
#include <caputils/capture.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>

/* pcap stores error descriptions in this buffer */
static char errorBuffer[PCAP_ERRBUF_SIZE] = {0,};
static const char* program_name = NULL;

static int run = 1;
static int quiet = 0;
static size_t caplen = UINT16_MAX - sizeof(cap_head);

static const char* shortopts = "c:o:m:i:l:qh";
static struct option longopts[] = {
	{"comments",  required_argument, 0, 'c'},
	{"output",    required_argument, 0, 'o'},
	{"mpid",      required_argument, 0, 'm'},
	{"interface", required_argument, 0, 'i'},
	{"CI",        required_argument, 0, 'i'},
	{"caplen",    required_argument, 0, 'l'},
	{"quiet",     no_argument,       0, 'q'},
	{"help",      no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(){
	printf("%s (caputils-%s)\n", program_name, caputils_version(NULL));
	printf("(c) 2004-2011 Patrik Arlos, David Sveningsson\n\n");
	printf("Capture packets using libpcap (or convert existing pcap-file) to a caputils stream.\n");
	printf("Converted data can be piped or stored to a file.\n\n");
	printf("Usage: pcap2cap [OPTION] -i INTERFACE [-o FILENAME]\n");
	printf("  or   pcap2cap [OPTION] [-o FILENAME] FILENAME\n");
	printf("\n");
	printf("  -m, --mpid=STRING          Set MP id, max 199 char. [default: hostname]\n");
	printf("  -c, --comment=STRING       Add comment to header [default: none]\n");
	printf("  -o, --output=FILENAME      Destination filename.\n");
	printf("  -i, --interface=INTERFACE  Capture Interface. If no input file is specified a\n"
	       "                             pcap live capture will run on the specified\n"
	       "                             interface. (use \"any\" to capture on all\n"
	       "                             interfaces).\n"
	       "      --CI=INTERFACE         Alias for --iface\n");
	printf("      --caplen=INT           Set caplen. Default %zd bytes.\n", caplen);
	printf("  -q, --quiet                Silent output, only errors is printed.\n");
	printf("  -h, --help                 Show this help.\n");
}

static int inline min(int a, int b){
	return (a < b) ? a : b;
}

static void sighandler(int signum){
	fprintf(stderr, "\r%s: Caught SIGINT, aborting...\n", program_name);
  run = 0;
}

static struct pcap* open_src_live(const char* iface){
	return pcap_open_live(iface, BUFSIZ, 1, 1000, errorBuffer);
}

static struct pcap* open_src_filename(const char* filename){
	return pcap_open_offline(filename, errorBuffer);
}

static struct pcap* open_src(int argc, char* argv[], struct cap_header* cp){
	const int tty = isatty(STDIN_FILENO);
	const int live = strcmp(cp->nic, "CONV") != 0;

	struct pcap* pcap;
	switch ( argc - optind ){ /* number of targets */
	case 0:
		if ( !tty ){ /* tcpdump piped */
			pcap = open_src_filename("/dev/stdin");
		} else if ( live ){ /* live capture */
			pcap = open_src_live(cp->nic);
		} else {
			fprintf(stderr, "%s: Must specify either an interface (-i, --interface) for live capture or a pcap-file.\n", program_name);
			return NULL;
		}
    break;

  case 1:
	  pcap = open_src_filename(argv[optind]);
    break;

  default:
	  fprintf(stderr, "%s: Must specify at most one pcap-file.\n", program_name);
    return NULL;
  }

  if ( errorBuffer[0] != 0 ){
	  /* may include non-fatal warnings */
    fprintf(stderr, "%s: %s\n", program_name, errorBuffer);
  }

  return pcap;
}

static stream_t open_dst(stream_addr_t* addr, const caphead_t cp, const char* comment){
	/* default to stdout */
	if( !stream_addr_is_set(addr) ){
		if ( isatty(STDOUT_FILENO) ){
			fprintf(stderr, "%s: Cannot output to a terminal, either specify a file using `-o FILENAME' or\n"
			        "          redirect output.\n", program_name);
			return NULL;
		}

		/* stdout is not a terminal so user probably want to use redirection */
		stream_addr_str(addr, "/dev/stdout", 0);
	}

	if ( !quiet ){
		fprintf(stderr, "%s: Opening file stream: %s\n", program_name, stream_addr_ntoa(addr));
	}

	int ret;
	stream_t st = NULL;
	if ( (ret=stream_create(&st, addr, cp->nic, cp->mampid, comment)) != 0 ){
		fprintf(stderr, "%s: stream_create failed with code %d: %s.\n", program_name, ret, caputils_error_string(ret));
		return NULL;
	}

	return st;
}

int main (int argc, char **argv){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

  /* setup capture header */
  struct cap_header cp;
  strncpy(cp.nic, "CONV", CAPHEAD_NICLEN);
  gethostname(cp.mampid, 8);

  /* defaults */
  char* comments = strdup("converted from pcap with pcap2cap-" CAPUTILS_VERSION);
  stream_addr_t dst = STREAM_ADDR_INITIALIZER;

  int op;
  int option_index;
  while ( (op = getopt_long  (argc, argv, shortopts, longopts, &option_index)) != -1 ){
    switch (op){
    case 'c':
      comments = strdup(optarg);
      break;

    case 'm':
//      strncpy(cp.mampid, optarg, 8);
      memset(cp.mampid, 0, sizeof cp.mampid);
      memcpy(cp.mampid, optarg, strnlen(optarg, sizeof cp.mampid - 1));

      break;

    case 'i': /* --iface */
      strncpy(cp.nic, optarg, CAPHEAD_NICLEN);
      cp.nic[CAPHEAD_NICLEN-1] = 0; /* force null-terminator */
      break;

    case 'l':
      caplen = atoi(optarg);
      break;

    case 'o':
      stream_addr_str(&dst, optarg, 0);
      break;

    case 'q': /* --quiet */
	    quiet = 1;
	    break;

    case 'h':
	    show_usage();
      return 0;
      break;
    default:
      printf ("?? getopt returned character code 0%o ??\n", op);
    }
  }

  /* open input/output */
  pcap_t* pcap = open_src(argc, argv, &cp);
  stream_t st = open_dst(&dst, &cp, comments);
  if ( !(pcap && st) ){
	  return 1; /* error already shown */
  }

  /* comment is no longer needed */
  free(comments);
  comments = NULL;

  /* setup signal handler so it can handle ctrl-c etc with proper closing of streams */
  signal(SIGINT, sighandler);

  const u_char* packet;
  struct pcap_pkthdr pcapHeader;
  unsigned long long pktCount = 0;
  while ( (packet=pcap_next(pcap, &pcapHeader)) && run ){
    cp.ts.tv_sec  = pcapHeader.ts.tv_sec;  /* Copy and convert the timestamp provided by PCAP, assumes _usec. If nsec will be present adjust! */
    cp.ts.tv_psec = pcapHeader.ts.tv_usec * 1e6;
    cp.len = pcapHeader.len; /* The Wire-lenght of the frame */
    cp.caplen = min(pcapHeader.caplen, caplen);

    // Let the user know that we are alive, good when processing large files.
    if ( !quiet && pktCount++ % 1000 == 0 ) {
      fprintf(stderr, ".");
      fflush(stderr);
    }

    // Save a copy of the frame to the new file.
    int ret;
    if ( (ret=stream_write_separate(st, &cp, packet, cp.caplen)) != 0 ) {
	    fprintf(stderr, "stream_write(..) returned %d: %s\n", ret, caputils_error_string(ret));
    }
  }

  /* Release resources */
  stream_close(st);
  stream_addr_reset(&dst);
  pcap_close(pcap);

  if ( !quiet ){
	  fprintf(stderr, "\n%s: There was a total of %lld packets converted.\n", program_name, pktCount);
  }

  return 0;
}
