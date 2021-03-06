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
#endif /*HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils/stream.h"
#include "caputils/filter.h"
#include "caputils/utils.h"
#include "caputils/marker.h"
#include "caputils/log.h"
#include "caputils/packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

static const char* program_name = NULL;
static size_t caplen = 9964;
static const char* outFilename = NULL;
static const char* iface = NULL;
static int linktype = DLT_EN10MB;
static int quiet = 0;
static int keep_running = 1;
static unsigned int max_packets = 0;
static struct timeval timeout = {1,0};


void handle_sigint(int signum){
	if ( keep_running == 0 ){
		fprintf(stderr, "\rGot SIGINT again, terminating.\n");
		abort();
	}
	fprintf(stderr, "\rAborting capture.\n");
	keep_running = 0;
}


int main (int argc, char **argv){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	extern int optind;
	int op;

	int option_index;
	long ret;

	struct filter filter;
	if ( filter_from_argv(&argc, argv, &filter) != 0 ){
		fprintf(stderr, "Failed to parse filter");
		return 1;
	}

	/* Parse Input Arguments */
	static struct option long_options[]= {
		{"output",1,0, 'o'},
		{"iface", required_argument, 0, 'i'},
		{"caplen", required_argument, 0, 'a'},
		{"linktype",1,0,'l'},
		{"packets",  required_argument, 0, 'p'},
		{"quiet", no_argument, 0, 'q'},
		{"help", 0, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ( (op = getopt_long(argc, argv, "i:l:o:p:qh", long_options, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'o':
			outFilename = optarg;
			break;

		case 'i':
			iface = optarg;
			break;

		case 'a': /* --caplen */
			caplen = atoi(optarg);
			break;

		case 'l':
			linktype = atoi(optarg);
			fprintf(stderr, "Linktype = %d ==> %s(%s)\n", linktype, pcap_datalink_val_to_name(linktype),
			        pcap_datalink_val_to_description(linktype));
			break;
			
			
		case 'p': /* --packets */
		        max_packets = atoi(optarg);
			break;
		  
		case 'q': /* --quiet */
		        quiet = 1;
			break;
		  
		case 'h':
			printf("%s (caputils-%s)\n", program_name, caputils_version(NULL));
			printf("(c) 2004-2016 Patrik Arlos, David Sveningsson\n\n");
			printf("Converts CAP files to PCAP files.\n");
			printf("Converted data is stored to a file(-o).\n\n");
			printf("Usage: %s [OPTION] -o FILENAME [INPUT]\n", program_name);
			printf("  -o, --output=FILENAME      Destination filename.\n"
			       "  -i, --iface=INTERFACE      Capture interface (used when converting live ethernet stream.\n");  
			printf("      --caplen=INT           Set caplen. Default %zd.\n", caplen);
			printf("  -l, --linktype=INTEGER     pcap linktype (see PCAP-LINKTYPE(7))\n");
			printf("  -p, --packets=N            Stop after N read packets.\n");
			printf("  -q, --quiet                Silent output, only errors is printed.\n");
			filter_from_argv_usage();
			return 0;

		default:
			fprintf (stderr, "?? getopt returned character code 0%o ??\n", op);
		}
	}

	stream_addr_t src = STREAM_ADDR_INITIALIZER;
	if ( argc-optind > 0 ){
		ret = stream_addr_aton(&src, argv[optind], STREAM_ADDR_GUESS, 0);
	} else if ( !isatty(STDIN_FILENO) ){
		ret = stream_addr_str(&src, "/dev/stdin", 0); /* stdin is pipe */
	} else {
		fprintf(stderr, "%s: must specify source address.\n", program_name);
		return 1;
	}

	if ( ret != 0 ){
		fprintf(stderr, "%s: Failed to parse source address: %s\n", program_name, strerror(ret));
		return 1;
	}

	/* Open stream(s) */
	struct stream* stream;
	if ( (ret=stream_from_getopt(&stream, argv, optind, argc, iface, "-", program_name, 0)) != 0 ) {
		return ret; /* Error already shown */
	}
	const stream_stat_t* stat = stream_get_stat(stream);
	stream_print_info(stream, stderr);


	pcap_t* pcapHandle = pcap_open_dead(linktype, caplen);
	pcap_dumper_t* pH = NULL;

	/* open output stream */
	if ( outFilename ){
		pH = pcap_dump_open(pcapHandle, outFilename);
	} else if ( !isatty(STDOUT_FILENO) ){
		pH = pcap_dump_open(pcapHandle, "/dev/stdout");
	} else {
		fprintf(stderr, "You need to specify a file reciving the converted data.\n");
		fprintf(stderr, "Terminating.\n");
		return 1;
	}

	if ( !pH ) {
		fprintf(stderr, "%s: Error opening pcap file %s.\n", program_name, outFilename);
		return 1;
	}

	if ( !quiet ){
		stream_print_info(stream, stderr);
	}

	/* handle C-c */
	signal(SIGINT, handle_sigint);

	cap_head* cp;
	struct pcap_pkthdr pcapHeader;
	long int packets = 0;

	while ( keep_running)
	  {
	    struct timeval tv = timeout;
	    
	    ret=stream_read(stream, &cp, &filter, &tv);
	    if ( ret == EAGAIN ) {
	      continue;
	    } else if ( ret != 0) {
	      break;
	    }
	    packets++;

	    pcapHeader.ts.tv_sec  = cp->ts.tv_sec;
	    pcapHeader.ts.tv_usec = cp->ts.tv_psec/1000000;
	    pcapHeader.len    = cp->len;
	    pcapHeader.caplen = cp->caplen;
	    
	    // Let the user know that we are alive, good when processing large files.
	    if ( !quiet && packets % 1000 == 0) {
	      fprintf(stderr, ".");
	      fflush(stderr);
	    }
	    
	    // Save a copy of the frame to the new file.
	    pcap_dump((u_char*)pH, &pcapHeader, (u_char*)cp->payload);
	    pcap_dump_flush(pH);

	    if ( max_packets > 0 && stat->matched >= max_packets) {
	      /* Read enough pkts lets break. */
	      break;
	    }
	    
	  }
	
	/* Close pcap file */
	pcap_dump_close(pH);
	
	/* close cap file */
	stream_close(stream);
	stream_addr_reset(&src);
	
	if ( !quiet ){
	  fprintf(stderr, "\nThere was a total of %ld pkts that matched the filter.\n", packets);
	}
	return 0;
}
