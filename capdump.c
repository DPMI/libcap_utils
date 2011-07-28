#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/stream.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>

int clone_stream(struct stream* dst, struct stream* src, unsigned long long* matches){
  cap_head* cp;
  size_t len = sizeof(struct cap_header);

  *matches = 0;
  while ( 1 ){
    long ret = stream_read(src, &cp, NULL);
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

static struct option long_options[]= {
  {"output",  1, 0, 'o'},
  {"packets", 1, 0, 'p'},
  {"help", 0, 0, 'h'},
  {0, 0, 0, 0}
};

int main(int argc, char **argv){
  extern int optind, opterr, optopt;

  int option_index;

  char* outFilename=0;
  struct stream* src;
  struct stream* dst;
  
  if ( argc < 2 ){
    show_usage();
    exit(0);
  }
  
  while ( (op = getopt_long(argc, argv, "ho:p:", long_options, &option_index)) != -1 )
    switch (op){
    case 0: /* long opt */
      break;
      
    case 'h':
      show_usage();
      exit(0);
      break;
      
    default:
      printf ("?? getopt returned character code 0%o ??\n", op);
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

  fprintf(stderr, "There was a total of %lld pkts that matched the filter.\n", pktCount);
  return 0;
}
