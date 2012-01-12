#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <net/if_arp.h>
#include <caputils/caputils.h>
#include <caputils/stream.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <string.h>

static const char* program_name = NULL;
static size_t caplen = 9964;
static const char* outFilename = NULL;
static const char* iface = NULL;
static int linktype = DLT_EN10MB;

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
	long ret;
		
	if ( argc < 2 ){
		fprintf(stderr, "Usage: %s -h or --help for help\n", program_name);
		return 1;
	}
	
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
		{"help", 0, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ( (op = getopt_long(argc, argv, "i:l:o:h", long_options, &option_index)) != -1 ){
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
			
		case 'h':
	    printf("%s (caputils-" CAPUTILS_VERSION ")\n", program_name);
      printf("(c) 2004-2011 Patrik Arlos, David Sveningsson\n\n");
			printf("Converts CAP files to PCAP files.\n");
			printf("Converted data is stored to a file(-o).\n\n");
			printf("Usage: %s [OPTION] -o FILENAME [INPUT]\n", program_name);
			printf("  -o, --output=FILENAME      Destination filename.\n");
			printf("  -i, --iface=INTERFACE      Capture interface (used when converting live ethernet stream.\n");
			printf("      --caplen=INT           Set caplen. Default %zd.\n", caplen);
			printf("  -l, --linktype=INTEGER     pcap linktype (see PCAP-LINKTYPE(7))\n");
			return 0;

		default:
			fprintf (stderr, "?? getopt returned character code 0%o ??\n", op);
		}
	}
	
	stream_addr_t src;
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

	/* open input stream */
	stream_t* st;
	static const char* type[4] = {"file", "ethernet", "udp", "tcp"};
	fprintf(stderr, "Opening %s stream: %s\n", type[stream_addr_type(&src)], stream_addr_ntoa(&src));
	if ( (ret=stream_open(&st, &src, iface, 0)) != 0 ) {
		fprintf(stderr, "stream_open() failed with code 0x%08lX: %s\n", ret, caputils_error_string(ret));
		return 1;
	}

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

	//output fileheader, simply so that the user gets some info on the version of the file thats beeing created.
	struct file_version version;
	const char* mampid = stream_get_mampid(st);
	const char* comment = stream_get_comment(st);
	stream_get_version(st, &version);
	
	fprintf(stderr, "%s: caputils %d.%d stream\n", stream_addr_ntoa(&src), version.major, version.minor);
	fprintf(stderr, "     mpid: %s\n", mampid != 0 ? mampid : "(unset)");
	fprintf(stderr, "  comment: %s\n", comment ? comment : "(unset)");
	
	struct cap_header* cp;
	struct pcap_pkthdr pcapHeader;
	long int packets = 0;
	while ( (ret=stream_read(st, &cp, &filter, NULL)) == 0 ){
		packets++;

		pcapHeader.ts.tv_sec  = cp->ts.tv_sec;
		pcapHeader.ts.tv_usec = cp->ts.tv_psec/1000000;
		pcapHeader.len    = cp->len;
		pcapHeader.caplen = cp->caplen;

		// Let the user know that we are alive, good when processing large files. 
		if ( packets % 1000 == 0) {
			fprintf(stderr, ".");
			fflush(stderr);
		}

		// Save a copy of the frame to the new file.
		pcap_dump((u_char*)pH, &pcapHeader, (u_char*)cp->payload);
		pcap_dump_flush(pH);
	}

	/* Close pcap file */
	pcap_dump_close(pH);

	/* close cap file */
	stream_close(st);

	fprintf(stderr, "\nThere was a total of %ld pkts that matched the filter.\n", packets);
	return 0;
}
