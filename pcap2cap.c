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
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <assert.h>
#include <sys/ioctl.h>

#define MIN(A,B) ((A) < (B) ? (A):(B))

/* Enough space to store the cap_head + a maximum data block from PCAP (9200byte for a Gigabit Ethernet Jumbo frame. */
#define dataLEN 10000

/* If larger data will be read by PCAP, dataLEN needs to change accordingly. */
static unsigned char raw_buffer[dataLEN]; /* Allocate the data space */

/* pcap stores error descriptions in this buffer */
static char errorBuffer[PCAP_ERRBUF_SIZE];
static const char* program_name = NULL;

static int run = 1;
static int quiet = 0;
static size_t caplen = dataLEN - sizeof(cap_head);

static const char* shortopts = "m:c:o:i:qh";
static struct option longopts[] = {
	{"comments",1, 0,'c'},
	{"output",1,0, 'o'},
	{"mpid", 1, 0, 'm'},
	{"interface",1,0, 'i'},
	{"help", 0, 0, 'h'},
	{"caplen", 1, 0, 'l'},
	{"quiet", no_argument, 0, 'q'},
	{0, 0, 0, 0}
};

static void show_usage(){
	printf("%s (caputils-" CAPUTILS_VERSION ")\n", program_name);
	printf("(c) 2004-2011 Patrik Arlos, David Sveningsson\n\n");
	printf("Capture packets using libpcap (or convert existing pcap-file) to a caputils stream.\n");
	printf("Converted data can be piped or stored to a file.\n\n");
	printf("Usage: pcap2cap [OPTION] -i INTERFACE [-o FILENAME]\n");
	printf("  or   pcap2cap [OPTION] [-o FILENAME] FILENAME\n");
	printf("\n");
	printf("  -m, --mpid=STRING          Set MP id, max 199 char. Default hostname.\n");
	printf("  -c, --comment=STRING       Add comment to header, dont forget \" \" around the\n"
	       "                             text. Not set by default.\n");
	printf("  -o, --output=FILENAME      Destination filename.\n");
	printf("  -i, --interface=INTERFACE  Capture on live interface. (use \"any\" to capture\n"
	       "                             on all interfaces) Default CONV.\n");
	printf("      --caplen=INT           Set caplen. Default %zd.\n", caplen);
	printf("  -q, --quiet                Silent output, only errors is printed.\n");
	printf("  -h, --help                 Show this help.\n");
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

  extern int optind, opterr, optopt;
  int op;

  int option_index;

  const u_char *packet; /* Packet read from PCAP */
  struct pcap_pkthdr pcapHeader; /* PCAPS packet header */

  stream_addr_t dst;
  stream_t dst_stream = NULL;
  stream_addr_reset(&dst);

  char* comments = strdup("(nil)");
  unsigned long long pktCount = 0;

  memset(raw_buffer, 0, dataLEN);
  memset(errorBuffer, 0, PCAP_ERRBUF_SIZE);

  /* setup pointers */
  cap_head *caphead = (cap_head*)raw_buffer;
  unsigned char* pkt_buffer = (unsigned char*)raw_buffer + sizeof(cap_head);

  /* default interface */
  strncpy(caphead->nic, "CONV", 8);
  gethostname(caphead->mampid, 8);

  while (1) {
    option_index = 0;

    op = getopt_long  (argc, argv, shortopts, longopts, &option_index);
    if (op == -1)
      break;

    switch (op){
    case 'c':
      comments = strdup(optarg);
      break;

    case 'm':
      strncpy(caphead->mampid, optarg, 8);
      break;

    case 'i':
      strncpy(caphead->nic, optarg, 8);
      break;

    case 'l':
      caplen = atoi(optarg);
      break;

    case 'o':
      stream_addr_aton(&dst, optarg, STREAM_ADDR_GUESS, 0);
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

  pcap_t *pcapHandle;

  /* open input */
  switch ( argc - optind ){ /* number of targets */
  case 0:
    if ( !isatty(STDIN_FILENO) ){ /* tcpdump piped */
      pcapHandle = pcap_open_offline("/dev/stdin", errorBuffer);
    } else if ( strcmp(caphead->nic, "CONV") != 0 ){ /* live capture */
      pcapHandle = pcap_open_live(caphead->nic, BUFSIZ, 1, 1000, errorBuffer);
    } else {
      fprintf(stderr, "Must specify either an interface (-i, --interface) for live capture or a pcap-file.\n");
      return 1;
    }
    break;
  case 1:
    pcapHandle = pcap_open_offline(argv[optind], errorBuffer);
    break;
  default:
    fprintf(stderr, "Must specify at most one pcap-file.\n");
    return 1;
  }

  /* Ensure handle is valid */
  if ( pcapHandle==NULL ){
    fprintf(stderr, "%s: %s\n", argv[0], errorBuffer);
    return 1;
  }

  /* warning from pcap */
  if ( errorBuffer[0] != 0 ){
    fprintf(stderr, "%s: %s\n", argv[0], errorBuffer);
  }

  if ( !quiet ){
	  static const char* type[4] = {"file", "ethernet", "udp", "tcp"};
	  fprintf(stderr, "Opening %s stream: %s\n", type[stream_addr_type(&dst)], stream_addr_ntoa(&dst));
  }

  long ret;
  if ( (ret=stream_create(&dst_stream, &dst, caphead->nic, caphead->mampid, comments)) != 0 ){
    fprintf(stderr, "%s: stream_create failed with code %ld: %s.\n", argv[0], ret, caputils_error_string(ret));
    return 1;
  }

  if ( stream_addr_type(&dst) != STREAM_ADDR_CAPFILE ){
	  fprintf(stderr, "%s: only capfiles are supported, you can use \"mp --local -i pcapIFACE\" if you want to stream over ethernet.\n", program_name);
	  return 1;
  }

  /* comment is no longer needed */
  free(comments);
  comments = NULL;

  /* setup signal handler so it can handle ctrl-c etc with proper closing of streams */
  signal(SIGINT, sighandler);

  while ( (packet=pcap_next(pcapHandle, &pcapHeader)) && run ){
    pktCount++;

    caphead->ts.tv_sec=pcapHeader.ts.tv_sec;  /* Copy and convert the timestamp provided by PCAP, assumes _usec. If nsec will be present adjust! */
    caphead->ts.tv_psec=pcapHeader.ts.tv_usec;
    caphead->ts.tv_psec*=1000;
    caphead->ts.tv_psec*=1000;
    caphead->len=pcapHeader.len; /* The Wire-lenght of the frame */

    const size_t data_len = MIN(pcapHeader.caplen, caplen);
    memcpy(pkt_buffer, packet, data_len);
    caphead->caplen = data_len;

    // Let the user know that we are alive, good when processing large files.
    if( pktCount % 1000 == 0 ) {
      fprintf(stderr, ".");
      fflush(stderr);
    }

    // Save a copy of the frame to the new file.
    if ( (ret=stream_write(dst_stream, raw_buffer, caphead->caplen + sizeof(cap_head))) != 0 ) {
	    fprintf(stderr, "stream_write returned %ld: %s\n", ret, caputils_error_string(ret));
    }
  }
  //End Packet processing

  /* Close pcap file */
  pcap_close(pcapHandle);

  /* close caputils stream */
  stream_close(dst_stream);

  if ( !quiet ){
	  fprintf(stderr, "\n%s: There was a total of %lld pkts that matched the filter.\n", program_name, pktCount);
  }

  return 0;
}
