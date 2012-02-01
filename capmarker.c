#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/marker.h"
#include "caputils_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

enum app_mode {
	MODE_START,
	MODE_NEXT,
	MODE_STOP,
};

static enum app_mode mode = MODE_START;
static int keep_running = 1;
static const char* path = NULL;
static struct marker marker = {
	.magic = MARKER_MAGIC,
	.version = 1,
	.flags = 0,
	.reserved = 0,
	.exp_id = 0,
	.run_id = 0,
	.key_id = 0,
	.seq_num = 0,
	.starttime = 0,
	.stoptime = 0,
};

static const char* program_name = NULL;
static struct option long_options[]= {
	{"experiment", required_argument, 0, 'e'},
	{"run",        required_argument, 0, 'r'},
	{"key",        required_argument, 0, 'l'},
	{"sequence",   required_argument, 0, 's'},
	{"help",       no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void sigint_handler(int signum){
	if ( keep_running == 0 ){
		fprintf(stderr, "\rGot SIGINT again, terminating.\n");
		abort();
	}
	fprintf(stderr, "\rAborting.\n");
	keep_running = 0;
}

static void sigusr1_handler(int signum){
	/* do nothing */
}

static void sigusr2_handler(int signum){
	keep_running = 0;
}

/**
 * @note Returns static memory
 */
static const char* expand_home(const char* str){
	static char buf[1024];
	struct passwd* result = getpwuid(getuid());
	snprintf(buf, 1024, "%s/%s", result->pw_dir, str);
	return buf;
}

static int start_daemon(){
	int pid;
	struct stat st;

	/* ensure daemon isn't running */
	if ( stat(path, &st) == 0 ){
		fprintf(stderr, "%s: `%s' already exists, is the program already running?\n", program_name, path);
		return 1;
	} else if ( errno != ENOENT ){
		fprintf(stderr, "%s: failed to stat `%s', check permissions\n", program_name, path);
		return 1;
	}

	/* open socket */
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( sd == -1 ){
		fprintf(stderr, "%s: failed to open socket: %s\n", program_name, strerror(errno));
		return 1;
	}

  /* setup broadcast */
  int broadcast = 1;
  if( setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(int)) == -1 ){
	  fprintf(stderr, "%s: SO_BROADCAST failed: %s\n", program_name, strerror(errno));
	  return 1;
  }

	/* setup source address */
  static struct sockaddr_in src_addr;
  memset(&src_addr, 0, sizeof(struct sockaddr_in));
	src_addr.sin_family = AF_INET;
	src_addr.sin_port = (in_port_t)htons(MARKERPORT);
	src_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* setup destination address */
	static struct sockaddr_in dst_addr;
  memset(&dst_addr, 0, sizeof(struct sockaddr_in));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = (in_port_t)htons(MARKERPORT);
	dst_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	if ( bind(sd, &src_addr, sizeof(struct sockaddr_in)) == -1 ){
		fprintf(stderr, "%s: failed to bind socket: %s\n", program_name, strerror(errno));
		return 1;
	}
	
	if ( (pid=fork()) == 0 ){
		signal(SIGINT, sigint_handler);
		signal(SIGUSR1, sigusr1_handler);
		signal(SIGUSR2, sigusr2_handler);

		marker.starttime = htobe64(time(NULL));
		while ( keep_running){
			/* wait for signal */
			pause();

			/* send marker */
			if ( sendto(sd, &marker, sizeof(struct marker), 0, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr_in)) == -1 ){
				fprintf(stderr, "%s: sendto failed: %s\n", program_name, strerror(errno));
			}

			/* update fields */
			marker.seq_num += htonl(1);
			marker.starttime = marker.stoptime;
			marker.stoptime = htobe64(time(NULL));
		}

		unlink(path);
	} else {
		FILE* fp = fopen(path, "w");
		if ( !fp ){
			fprintf(stderr, "%s: could not write to `%s': %s\n", program_name, path, strerror(errno));
			kill(pid, SIGUSR2); /* terminate child */
			return 1;
		}
		fprintf(fp, "%d\n", pid);
	}
	return 0;
}

static void show_usage(void){
	printf("capmarker-" VERSION "\n");
	printf("(C) 2012 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] -e EXP -r RUN [-k KEY] [-s SEQ]\n"
	       "       %s next\n"
	       "       %s stop\n", program_name, program_name, program_name);
	printf("  -e, --experiment=ID  Current experiment ID.\n"
	       "  -r, --run=ID         Current run ID.\n"
	       "  -k, --key=INT        Domain information. [default: 0]\n"
	       "  -s, --sequence       Sequence start number. [default: 0].\n"
	       "  -h, --help           This text.\n");
}

int main(int argc, char **argv){
  /* extract program name from path. e.g. /path/to/MArCd -> MArCd */
  const char* separator = strrchr(argv[0], '/');
  if ( separator ){
    program_name = separator + 1;
  } else {
    program_name = argv[0];
  }

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, "e:r:k:s:h", long_options, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'e':
			marker.exp_id = atoi(optarg);
			if ( marker.exp_id == 0 ){
				fprintf(stderr, "%s: Experiment ID must be greater than 0.\n", program_name);
				return 1;
			}
			break;

		case 'r':
			marker.run_id = atoi(optarg);
			if ( marker.run_id == 0 ){
				fprintf(stderr, "%s: Run ID must be greater than 0.\n", program_name);
				return 1;
			}
			break;

		case 'k':
			marker.key_id = atoi(optarg);
			break;

		case 's':
			marker.seq_num = atoi(optarg);
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

	/* network order */
	marker.magic = htonl(marker.magic);
	marker.reserved = htons(marker.reserved);
	marker.exp_id = htonl(marker.exp_id);
	marker.run_id = htonl(marker.run_id);
	marker.key_id = htonl(marker.key_id);
	marker.seq_num = htonl(marker.seq_num);

	switch (argc-optind){
	case 0:
		mode = MODE_START;
		break;
	case 1:
		if ( strcasecmp(argv[optind], "next") == 0 ){
			mode = MODE_NEXT;
		} else if ( strcasecmp(argv[optind], "stop") == 0 ){
			mode = MODE_STOP;
		} else {
			fprintf(stderr, "%s: Invalid mode \"%s\"\n", program_name, argv[optind]);
			return 1;
		}
		break;
	default:
		fprintf(stderr, "%s: only one mode may be specified.\n", program_name);
		return 1;
	}

	if ( mode == MODE_START && (marker.exp_id == 0 || marker.run_id == 0) ){
		fprintf(stderr, "%s: must specify both experiment and run id.\n", program_name);
		return 1;
	}

	path = expand_home(".capmarker.pid");

	/* fork */
	if ( mode == MODE_START) {
		return start_daemon();
	}

	/* read child pid */
	int pid;
	FILE* fp = fopen(path, "r");
	if ( !fp ){
		fprintf(stderr, "%s: could not read `%s', check that the application is running and check permissions\n", program_name, path);
		return 1;
	}
	fscanf(fp, "%d\n", &pid);

	switch ( mode ){
	case MODE_START:
		break;
	case MODE_NEXT:
		kill(pid, SIGUSR1);
		break;
	case MODE_STOP:
		kill(pid, SIGUSR2);
		break;
	} 

	return 0;
}
