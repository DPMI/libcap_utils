#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "consumer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>

struct {
  int print_content;
  int cDate;
  unsigned long long max_pkts;
} args;

int clone_stream(struct stream* dst, struct stream* src, const struct filter* filter, unsigned long long* matches){
  cap_head* cp;
  size_t len = sizeof(struct cap_header);

  *matches = 0;
  while ( 1 ){
    long ret = stream_read(src, (char**)&cp, filter);
    if ( ret == EAGAIN ){
      continue;
    } else if ( ret != 0 ){
      break;
    }

    (*matches)++;
    if( !(stream_write(dst, (char*)cp, cp->caplen + len)) ) {
      fprintf(stderr, "Problems writing data to file!");
    }
  }

  return 0;
}

int display_stream(struct stream* src, const struct filter* filter, unsigned long long* matches){
  cap_head* cp;
  time_t time;
  long ret;

  *matches = 0;
  while ( 1 ) {
    ret = stream_read(src, (char**)&cp, filter);
    if ( ret == EAGAIN ){
      continue;
    } else if ( ret != 0 ){
      break;
    }

    if ( cp->caplen == 0 ){
      fprintf(stderr, "caplen is zero, will skip this packet but most likely the stream got out-of-sync and will crash later.\n");
      continue;
    }
    
    (*matches)++;
    time = (time_t)cp->ts.tv_sec;
    
    fprintf(stdout, "[%llu]:%.4s:%.8s:", *matches, cp->nic, cp->mampid);
    if( args.cDate == 0 ) {
      fprintf(stdout, "%u.", cp->ts.tv_sec);
    } else {
      static char timeStr[25];
      struct tm tm = *gmtime(&time);
      strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm);
      fprintf(stdout, "%s.", timeStr);
    }

    fprintf(stdout, "%012lu:LINK(%d):CAPLEN(%d):", cp->ts.tv_psec, cp->len, cp->caplen);

    struct frame_t frame;
    if ( classify_packet(cp, &frame) == 0 ){
      print_frame(stdout, &frame, args.print_content);
    } else {
      fprintf(stderr, "Got an unknown packet.\n");
      if(cp->len<60) {
	fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x [%04x]:", 
		frame.eth->h_source[0],frame.eth->h_source[1],frame.eth->h_source[2],frame.eth->h_source[3],frame.eth->h_source[4],frame.eth->h_source[5],
		frame.eth->h_dest[0],  frame.eth->h_dest[1],  frame.eth->h_dest[2],  frame.eth->h_dest[3],  frame.eth->h_dest[4],  frame.eth->h_dest[5], 
		ntohs(frame.eth->h_proto));
      }
      fprintf(stdout, "\n");
      continue;
    }

    if ( args.max_pkts > 0 && *matches + 1 > args.max_pkts) {
      /* Read enough pkts lets break. */
      printf("read enought packages\n");
      break;
    }
  }

  if ( ret == -1 ){ /* EOF, TCP shutdown, etc */
    fprintf(stderr, "Finished\n");
    return 0;
  } 

  fprintf(stderr, "readpost() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
  return 0;  
}

int main(int argc, char **argv){
  extern int optind, opterr, optopt;

  int option_index;
  static struct option long_options[]= {
    {"content",0,0,'c'},
    {"output",1,0, 'o'},
    {"pkts", 1, 0, 'p'},
    {"help", 0, 0, 'h'},
    {"if", 1,0,'i'},
    {"tcp", 1,0,'t'},
    {"udp", 1,0,'u'},
    {"port", 1,0, 'v'},
    {"calender",0,0,'d'},
    {0, 0, 0, 0}
  };
  
  /* defaults */
  args.print_content = 0;
  args.cDate = 0; /* Way to display date, cDate=0 => seconds since 1970. cDate=1 => calender date */  
  args.max_pkts = 0; /* 0: all */

  char* outFilename=0;
  int capOutfile=0;
  int portnumber=0;
  char* nic = NULL;
  int streamType = 0; // Default a file
  unsigned long long pktCount = 0;
  int ret = 0;

  struct filter myfilter;
  filter_from_argv(&argc, argv, &myfilter);
  struct stream* inStream;
  struct stream* outStream;
  
  if(argc<2){
    fprintf(stderr, "use %s -h or --help for help\n",argv[0]);
    exit(0);
  }
  
  while (1) {
    option_index = 0;
    
    int op = getopt_long  (argc, argv, "hp:o:cdi:tuv:",
		       long_options, &option_index);
    if (op == -1)
      break;

    switch (op){
    case 0: /* long opt */
      break;

      case 'd':
	fprintf(stderr, "Calender date\n");
	args.cDate=1;
	break;
      case 'p':
	fprintf(stderr, "No packets. Argument %s\n", optarg);
	args.max_pkts=atoi(optarg);
	break;
      case 'c':
	fprintf(stderr, "Content printing..\n");
	args.print_content=1;
	break;
      case 'i':
	fprintf(stderr, "Ethernet Argument %s\n", optarg);
	nic=strdup(optarg);
	streamType=1;
	break;
      case 'u':
	fprintf(stderr, "UDP \n");
	streamType=2;
	break;
      case 't':
	fprintf(stderr, "TCP \n");
	streamType=3;
	break;
      case 'v':
	fprintf(stderr, "port %d\n", atoi(optarg));
	portnumber=atoi(optarg);
	break;	
      case 'o':
	fprintf(stderr, "Output to file.\n");
	outFilename=strdup(optarg);
	capOutfile=1;              
	fprintf(stderr, "Output to data file %s\n",outFilename);
	break;	  
      case 'h':
	fprintf(stderr, "-------------------------------------------------------\n");
	fprintf(stderr, "Application Version " VERSION "\n");
	fprintf(stderr, "Application Options\n");
	fprintf(stderr, "-p or --pkts   <NO>     Number of pkts to show [default all]\n");
	fprintf(stderr, "-o or --output <name>   Store results to a CAP file. \n");
	fprintf(stderr, "-d or --calender        Display date/time in YYYY-MM-DD HH:MM:SS.xx.\n");
	fprintf(stderr, "-i or --if <NIC>        Listen to NIC for Ethernet multicast address,\n");
	fprintf(stderr, "                        identified by <INPUT> (01:00:00:00:00:01).\n");
	fprintf(stderr, "-t or --tcp             Listen to a TCP stream.\n");
	fprintf(stderr, "                        identified by <INPUT> (192.168.0.10). \n");
	fprintf(stderr, "-u or --udp             Listen to a UDP multicast address.\n");
	fprintf(stderr, "                        identified by <INPUT> (225.10.11.10).\n");
	fprintf(stderr, "-v or --port            TCP/UDP port to listen to. Default 0x0810.\n");
	fprintf(stderr, "<INPUT>                 If n,t or u hasn't been declared, this \n");
	fprintf(stderr, "                        is interpreted as a filename.\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s [filter options] [application options] <INPUT>\n", argv[0]);

	fprintf(stderr, "Sizeof(capture_header) = %zd bytes\n",sizeof(cap_head));
	exit(0);
	break;
      default:
	printf ("?? getopt returned character code 0%o ??\n", op);
    }
  }

  const char* filename = NULL;
  switch (argc - optind){
  case 0:
    switch ( streamType ){
    case 0:
      fprintf(stderr, "filename required\n");
      return 1;
    default:
      filename = "01:00:00:00:00:01";
    }
    break;
  default:
    filename = argv[optind];
  }

  printf("Opening stream %s\n", filename);
  destination_t src;
  destination_aton(&src, filename, streamType, DEST_LOCAL);

  if( (ret=openstream(&inStream, &src, nic, portnumber)) != 0 ) {
    fprintf(stderr, "openstream failed with code 0x%08X: %s\n", ret, caputils_error_string(ret));
    return 1;
  }

  if(capOutfile==1) {
    fprintf(stderr, "Creating FILE!\n.");
    destination_t dst;
    destination_aton(&dst, outFilename, DEST_CAPFILE, DEST_LOCAL);
    createstream(&outStream, &dst, NULL, stream_get_mampid(inStream), stream_get_comment(inStream));
    fprintf(stderr, "OK.\n");
  }

  struct file_version version;
  stream_get_version(inStream, &version);

//output fileheader
  fprintf(stderr, "ver: %d.%d id: %s \n comments: %s\n",
	  version.major, 
	  version.minor, 
	  stream_get_mampid(inStream), 
	  stream_get_comment(inStream));

  fprintf(stderr, "myFilter.index = %u \n", myfilter.index);
  fprintf(stderr, "----------------------------\n");

  if ( capOutfile == 1 ){
    ret = clone_stream(outStream, inStream, &myfilter, &pktCount);
  } else {
    ret = display_stream(inStream, &myfilter, &pktCount);
  }
  
  closestream(inStream);

  if(capOutfile==1) {
    closestream(outStream);
  }

  filter_close(&myfilter);

  fprintf(stderr, "There was a total of %lld pkts that matched the filter.\n", pktCount);
  return 0;
}
