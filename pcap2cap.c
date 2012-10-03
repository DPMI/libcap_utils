/**
 * Copyright (c) 2004-2011, Patrik Arlos, David Sveningsson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Blekinge Institute of Technology nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "caputils_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <net/if_arp.h>
#include <caputils/caputils.h>
#include <caputils/capture.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <assert.h>
#include <sys/ioctl.h>

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
	{"caplen",    required_argument, 0, 'l'},
	{"quiet",     no_argument,       0, 'q'},
	{"help",      no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(){
	printf("%s (caputils-" CAPUTILS_VERSION ")\n", program_name);
	printf("(c) 2004-2011 Patrik Arlos, David Sveningsson\n\n");
	printf("Capture packets using libpcap (or convert existing pcap-file) to a caputils stream.\n");
	printf("Converted data can be piped or stored to a file.\n\n");
	printf("Usage: pcap2cap [OPTION] -i INTERFACE [-o FILENAME]\n");
	printf("  or   pcap2cap [OPTION] [-o FILENAME] FILENAME\n");
	printf("\n");
	printf("  -m, --mpid=STRING          Set MP id, max 199 char. [default: hostname]\n");
	printf("  -c, --comment=STRING       Add comment to header [default: none]\n");
	printf("  -o, --output=FILENAME      Destination filename.\n");
	printf("  -i, --interface=INTERFACE  Capture on live interface. (use \"any\" to capture\n"
	       "                             on all interfaces)\n");
	printf("      --caplen=INT           Set caplen. Default %zd bytes.\n", caplen);
	printf("  -q, --quiet                Silent output, only errors is printed.\n");
	printf("  -h, --help                 Show this help.\n");
}

static int inline min(int a, int b){
	return (a < b) ? a : b;
}

void sighandler(int signum){
  fprintf(stderr, "Caught SIGINT, aborting...\n");
  run = 0;
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
  strncpy(cp.nic, "CONV", 8);
  gethostname(cp.mampid, 8);

  /* defaults */
  char* comments = strdup("converted from pcap with pcap2cap-" CAPUTILS_VERSION);
  stream_addr_t dst;
  stream_addr_reset(&dst);

  int op;
  int option_index;
  while ( (op = getopt_long  (argc, argv, shortopts, longopts, &option_index)) != -1 ){
    switch (op){
    case 'c':
      comments = strdup(optarg);
      break;

    case 'm':
      strncpy(cp.mampid, optarg, 8);
      break;

    case 'i':
      strncpy(cp.nic, optarg, 8);
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

  /* default to stdout */
  if( !stream_addr_is_set(&dst) ){
    if ( isatty(STDOUT_FILENO) ){
      fprintf(stderr, "Cannot output to a terminal, either specify a file using `-o FILENAME' or\n"
	              "redirect output.\n");
      return 1;
    }

    /* stdout is not a terminal so user probably want to use redirection */
    stream_addr_str(&dst, "/dev/stdout", 0);
  }

  /* open input */
  pcap_t* pcap;
  switch ( argc - optind ){ /* number of targets */
  case 0:
    if ( !isatty(STDIN_FILENO) ){ /* tcpdump piped */
      pcap = pcap_open_offline("/dev/stdin", errorBuffer);
    } else if ( strcmp(cp.nic, "CONV") != 0 ){ /* live capture */
      pcap = pcap_open_live(cp.nic, BUFSIZ, 1, 1000, errorBuffer);
    } else {
      fprintf(stderr, "Must specify either an interface (-i, --interface) for live capture or a pcap-file.\n");
      return 1;
    }
    break;
  case 1:
    pcap = pcap_open_offline(argv[optind], errorBuffer);
    break;
  default:
    fprintf(stderr, "Must specify at most one pcap-file.\n");
    return 1;
  }

  /* Ensure handle is valid */
  if ( pcap == NULL ){
    fprintf(stderr, "%s: %s\n", argv[0], errorBuffer);
    return 1;
  }

  /* warning from pcap */
  if ( errorBuffer[0] != 0 ){
    fprintf(stderr, "%s: %s\n", argv[0], errorBuffer);
  }

  if ( !quiet ){
	  fprintf(stderr, "Opening file stream: %s\n", stream_addr_ntoa(&dst));
  }

  int ret;
  stream_t st = NULL;
  if ( (ret=stream_create(&st, &dst, cp.nic, cp.mampid, comments)) != 0 ){
    fprintf(stderr, "%s: stream_create failed with code %d: %s.\n", argv[0], ret, caputils_error_string(ret));
    return 1;
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
    cp.ts.tv_psec = pcapHeader.ts.tv_usec * PICODIVIDER;
    cp.len = pcapHeader.len; /* The Wire-lenght of the frame */
    cp.caplen = min(pcapHeader.caplen, caplen);

    // Let the user know that we are alive, good when processing large files.
    if( pktCount++ % 1000 == 0 ) {
      fprintf(stderr, ".");
      fflush(stderr);
    }

    // Save a copy of the frame to the new file.
    if ( (ret=stream_write_separate(st, &cp, packet, cp.caplen)) != 0 ) {
	    fprintf(stderr, "stream_write(..) returned %d: %s\n", ret, caputils_error_string(ret));
    }
  }

  /* Release resources */
  stream_close(st);
  pcap_close(pcap);

  if ( !quiet ){
	  fprintf(stderr, "\n%s: There was a total of %lld pkts that matched the filter.\n", program_name, pktCount);
  } else {
	  fprintf(stderr, "\n");
  }

  return 0;
}
