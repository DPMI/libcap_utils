#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include <getopt.h>
#include <string.h>
#include <errno.h>

static int packet_flag = 0;

void show_usage(){
  printf("capinfo  caputils-" CAPUTILS_VERSION "\n");
  printf("(c) 2011 David Sveningsson\n\n");
  printf("Open a capstream and show information about it.\n");
  printf("Usage: capinfo [OPTIONS] FILENAME..\n\n");
  printf("      --packets              Show how many packets it contain.\n");
  printf("  -h, --help                 Show this help.\n");
}

int show_info(const char* filename){
  struct stream st;

  int ret = openstream(&st, filename, 0, NULL, 0);
  if ( ret != 1 ){
    fprintf(stderr, "%s: %s\n", filename, caputils_error_string(errno));
    return ret;
  }

  printf("%s: caputils %d.%d stream\n", filename, st.FH.version.major, st.FH.version.minor);
  printf("     mpid: %s\n", st.FH.mpid[0] != 0 ? st.FH.mpid : "(unset)");
  printf("  comment: %s\n", st.comment ? st.comment : "(unset)");

  if ( packet_flag ){
    
  }

  closestream(&st);
  
  return 0;
}

int main(int argc, char* argv[]){
  /* no arguments */
  if ( argc == 1 ){
    show_usage();
    return 0;
  }

  /* parse arguments */
  while (1){
    static struct option long_options[] = {
      {"packets", 0, &packet_flag,   1},
      {"help",    0,            0, 'h'}
    };

    int option_index = 0;
    
    int c = getopt_long(argc, argv, "h", long_options, &option_index);

    if ( c == -1 ){
      break;
    }

    switch (c){
    case 'h':
      show_usage();
      return 0;
    }
  }

  /* no targets */
  if ( optind == argc ){
    show_usage();
    return 0;
  }

  /* visit all targets */
  while ( optind < argc ){
    show_info(argv[optind++]);
    if ( optind < argc ){
      putchar('\n');
    }
  }

  return 0;
}
