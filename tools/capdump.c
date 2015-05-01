/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2015 (see AUTHORS)
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
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include <caputils/marker.h>
#include <caputils/picotime.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <libgen.h> /* for dirname */
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/udp.h>
#include <inttypes.h>
#include "be64toh.h" /* for compability */
#include <time.h>
#include <pthread.h>

enum MarkerMode {
	MARKER_INCREMENT,
	MARKER_OVERWRITE,
	MARKER_APPEND,
};

#define BUFSIZE 1500

static const size_t PROGRESS_REPORT_DELAY = 60;  /* seconds between progress reports */
static const size_t IRQ_DELAY = 1;               /* seconds between IRQs reports */
static int signal_count=0;                       /* counter of ALARMS, used to trigger progress_report while at the same time handling terminate markers */
static int marker_quit=0;                        /* If set to one, the program will exit (gracefully) after receving a terminate marker */
static int marker_terminate=0;                   /* Increments once for each received terminate marker */
static int marker_terminate_TO=0;                /* Increments once for each received SIGALMR, after a terminate marker been detected */
static int src_stream_count=0;                   /* The number of source streams present, set after src has been created.*/
static const int TERMINATE_DELAY = 3;            /* The number of seconds between receiving the first terminate marker, and the actual stop. */
                                                 /* Should be large enough to handle many streams, they may be a second later (mp timeout) */
                                                 /* but small to avoid unneeded delays. */

static int keep_running = 1;
static int marker = 0;
static int marker_comment = 0;
static const char* marker_format = "%f-%x-%03s.%e";
static enum MarkerMode marker_mode = MARKER_INCREMENT;
static char* fmt_basename = NULL;  /* used by generate_filename */
static char* fmt_extension = NULL; /* used by generate_filename */
static const char* program_name = NULL;
static const char* comment = "capdump-" VERSION " stream";
static const struct stream_stat* stream_stat = NULL;
static char mpid[8];
static int progress = -1;          /* if >0 progress reports is written to this file descriptor */
static uint32_t marker_key = 0;    /* Key to look for, 0 means disabled */

/* Added to act as a marker recipient */
static int use_listen = 0;
static int sockfd = 0;             /* Socket for the UDP server */
static int portno = 4000;          /* Port number for UDP server */
struct sockaddr_in clientaddr;     /* client addr */

static const char* shortopts = "o:p:i:c:b:m:K:LP:f:M:C:s::h";
static struct option longopts[]= {
	{"output",         required_argument, 0, 'o'},
	{"packets",        required_argument, 0, 'p'},
	{"iface",          required_argument, 0, 'i'},
	{"comment",        required_argument, 0, 'c'},
	{"bufsize",        required_argument, 0, 'b'},
	{"marker",         required_argument, 0, 'm'},
	{"key",            optional_argument, 0, 'K'},
	{"listen",         optional_argument, 0, 'L'},
	{"port",           optional_argument, 0, 'P'},
	{"marker-format",  required_argument, 0, 'f'},
	{"marker-mode",    required_argument, 0, 'M'},
	{"marker-comment", required_argument, 0, 'C'},
	{"marker-quit",    no_argument, 0, 'Q'},
	{"progress",       optional_argument, 0, 's'},
	{"help",           no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

struct packet {
	struct cap_header cap;
	struct ethhdr eth_inner;
	struct iphdr ip_inner;
	struct udphdr udp_inner;
	struct marker mark_inner;
} __attribute__((packed));

stream_t dst;
stream_addr_t output = STREAM_ADDR_INITIALIZER;

static void show_usage(void){
	printf("(C) 2011-2014 David Sveningsson <david.sveningsson@bth.se>, Patrik Arlos <patrik.arlos@bth.se> \n"
	       "Usage: %s [OPTIONS] [INPUT..] [OUTPUT]\n"
	       "  -o, --output=FILE    Save output in capfile. [default=stdout]\n"
	       "  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	       "                       on. For other streams it is ignored.\n"
	       "  -p, --packets=INT    Stop capture after INT packages.\n"
	       "  -c, --comment        Set stream comment.\n"
	       "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	       "  -b, --bufsize=BYTES  Use BYTES buffer size [default depends on driver].\n"
	       "  -m, --marker=PORT    Split streams based on marker packet. See capdump(1) for\n"
	       "                       further description of this feature.\n"
	       "  -K, --key=KEY        If markers are used, and the key is set, the marker must contain\n"
	       "                       this key as to be considered as a marker. If key is not set, normal\n"
	       "                       behaviour is applied.\n"
	       "  -L, --listen         If applied, we will accept capmarker messages via UDP and TCP.\n"
	       "                       Will be treated the same as a mp marker.\n"
	       "  -P, --port           UDP port to listen to [default: 4000].\n"
	       "  -f, --marker-format  Renaming format for marker.\n"
	       "      --marker-mode    What to do when identical filename is generated. Valid\n"
	       "                       modes are [I]crement (default), [O]verwrite and [A]ppend.\n"
	       "      --marker-comment Use marker comment as the stream comment.\n"
	       "      --marker-quit    Terminate application after receving a End/Terminate marker.\n"
	       "      --progress[=FD]  Write progress report to FD every 60 seconds.\n"
	       "  -h, --help           This text.\n"
	       "\n"
	       "Streams can be specified in the following formats:\n"
	       "  - NN:NN:NN:NN:NN:NN  Listen to ethernet multicast stream.\n"
	       "  - tcp://IP[:PORT]    Listen to TCP unicast.\n"
	       "  - udp://IP[:PORT]    Listen to UDP broadcast.\n"
	       "  - FILENAME           Open capfile for reading.\n",
	       program_name);
}

static void sig_handler(int signum){
	static const char* names[] = {"SIGINT", "SIGTERM", "unknown signal"};
	const char* name;
	switch ( signum ){
	case SIGINT: name = names[0]; break;
	case SIGTERM: name = names[1]; break;
	default: name = names[2];
	}

	static char timestr[64];
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

	if ( keep_running == 0 ){
		fprintf(stderr, "\r%s: [%s] Got %s again, aborting.\n", program_name, timestr, name);
		abort();
	}
	fprintf(stderr, "\r%s: [%s] Got %s, terminating gracefully.\n", program_name, timestr, name);
	keep_running = 0;
}

static void my_signalhandler(int signum){
	/* Handle SIGALRM callbacks, first check if its progress report time, then check if we are */
	/* terminating something, and at the end should we leave. */

	if(progress>0){
		if( (signal_count+1) == PROGRESS_REPORT_DELAY){
			static char buf[1024];
			static char timestr[64];
			time_t t = time(NULL);
			struct tm tm = *localtime(&t);
			strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

			static uint64_t last = 0;
			const uint64_t delta = stream_stat->read - last;
			last = stream_stat->read;
			const uint64_t pps = delta / PROGRESS_REPORT_DELAY;
			const float rate = (float)(delta * 8 / PROGRESS_REPORT_DELAY / 1024 / 1024);

			ssize_t bytes = snprintf(buf, 1024, "%s: [%s] progress report: %'"PRIu64" packets read (%"PRIu64" new, %"PRIu64"pkt/s, avg bitrate %.1fMpbs).\n", program_name, timestr, stream_stat->read, delta, pps, rate);
			if ( write(progress, buf, bytes) == -1 ){
				fprintf(stderr, "progress report failed: %s\n", strerror(errno));
			}
			signal_count=0;
		} else {
			signal_count++;
		}
	}

	/* Handle termination */
	if( marker_terminate ) {
		if( (marker_terminate>=src_stream_count) || (marker_terminate_TO>=src_stream_count) ){
			/* We should terminate something */

			if ( dst ){
				stream_addr_str(&output, "", STREAM_ADDR_LOCAL);
				stream_close(dst);
				dst = NULL;
			}
			if(marker_quit){
				keep_running=0;
				fprintf(stderr,"\tReached terminate condition, quitting.\n");
			} else {
				marker_terminate=0;
				marker_terminate_TO=0;
				fprintf(stderr, "\tReached terminate condition, will not save until next marker arrives.\n");
			}
			return;
		} else {
			/* We are here as we gotten a SIGALRM, and a marker was received at some stage. */
			/* The marker_terminate is incr. in the handle_marker, here we incr. the timeout counter. */
			marker_terminate_TO++;
		}
	}
}

static const char* marker_flags(const struct marker* marker){
	static char buf[12];
	static char flag[8] = {'T', 0, };
	if ( marker->flags == 0 ){
		return "(not set)";
	}

	char* dst = buf;
	*dst++ = '[';
	for ( int i = 0; i < 8; i++ ){
		if ( marker->flags & (1<<i) ){
			*dst++ = flag[i];
		}
	}
	*dst++ = ']';
	return buf;
}

static void error(char *msg) {
	perror(msg);
	exit(1);
}

static void marker_report(const struct marker* marker){
	static char timestr[64];
	static char timestamp[200];
	static struct tm tm;

	/* timestamp for log */
	time_t t = time(NULL);
	tm = *localtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

	/* timestamp from marker */
	tm = *localtime((const time_t*)&marker->timestamp);
	strftime(timestamp, 200, "%a, %d %b %Y %T %z", &tm);

	fprintf(stderr, "%s: [%s] marker v%d found\n", program_name, timestr, marker->version);
	fprintf(stderr, "\tdata: exp=%d run=%d key=%d seq=%d\n", marker->exp_id, marker->run_id, marker->key_id, marker->seq_num);
	fprintf(stderr, "\tflags: %s [0x%02x]\n", marker_flags(marker), marker->flags);
	fprintf(stderr, "\ttimestamp: %s\n", timestamp);
}

static enum MarkerMode parse_marker_mode(const char* str){
	const char ch = tolower(str[0]);
	switch ( ch ){
	case 'i': return MARKER_INCREMENT;
	case 'o': return MARKER_OVERWRITE;
	case 'a': return MARKER_APPEND;
	default: 	return MARKER_INCREMENT;
	}
}

static const char* generate_filename(const char* fmt, const struct marker* marker){
	static char buffer[1024];
	char* dst = buffer;
	const char* src = fmt;

	while ( *src ){
		const char ch = *src;

		switch ( ch ){
		case '%':
		{
			char w[4] = {0,};
			int n = 0;
			while ( isdigit(*(++src)) ) {
				if ( n == 4 ){ fprintf(stderr, "field width specifier to great"); abort(); }
				w[n++] = *src;
			}

			const int zeropad = w[0] == '0';
			const int width = atoi(w);
			const char specifier = *src++;

			switch ( specifier ){
			case 'e': /* extension */
				dst += sprintf(dst, "%s", fmt_extension);
				break;

			case 'f': /* filename */
				dst += sprintf(dst, "%s", fmt_basename);
				break;

			case 's': /* sequence number */
				dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->seq_num);
				break;

			case 'k': /* key */
				dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->key_id);
				break;

			case 'r': /* run id */
				dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->run_id);
				break;

			case 'x': /* experiment id */
				dst += sprintf(dst, zeropad ? "%0*d" : "%*d", width, marker->exp_id);
				break;

			default:
				fprintf(stderr, "unknown specifier `%c'\n", specifier);
				abort();
			}
			break;
		}

		default:
			*dst++ = ch;
			src++;
		}
	}
	*dst = 0;

	if ( marker_mode == MARKER_INCREMENT ){
		/* try if the file exists already and append a suffix if it does */
		static unsigned int suffix = 1;

		do {
			/* test if filename already exists */
			struct stat st;
			if ( stat(buffer, &st) == -1 ){
				if ( errno == ENOENT ){
					break; /* exit loop and return filename */
				} else {
					fprintf(stderr, "%s: stat() returned %d: %s\n", program_name, errno, strerror(errno));
				}
				break;
			}

			/* increment suffix and retry */
			const size_t left = sizeof(buffer) - (dst - buffer);
			snprintf(dst, left, ".%d", suffix++);
		} while (1);
	}

	return buffer;
}

static int open_next(stream_addr_t* addr, stream_t* st, const struct marker* marker){
	/* generate next filename */
	const char* filename = generate_filename(marker_format, marker);

	/* test if user want to append to existing stream */
	if ( marker_mode == MARKER_APPEND && strcmp(filename, addr->local_filename) == 0){
		char* abs = realpath(filename, NULL);
		fprintf(stderr, "\tfilename: `%s' (appending)\n", abs ? abs : filename);
		free(abs);
		stream_flush(*st);
		return 0;
	}

	/* close current stream */
	stream_close(*st);
	*st = NULL;

	/* open new stream */
	int ret;
	stream_addr_reset(addr);
	stream_addr_str(addr, filename, STREAM_ADDR_DUPLICATE);
	if ( (ret=stream_create(st, addr, NULL, mpid, marker_comment ? marker->comment : comment)) != 0 ){
		fprintf(stderr, "%s: stream_create() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret));
		return 1;
	}

	char* abs = realpath(filename, NULL);
	fprintf(stderr, "\tfilename: `%s'\n", abs ? abs : filename);
	free(abs);

	return 0;
}

/**
 * Validate selected key versus key present in marker.
 * @return 1 if key is valid.
 */
static int validate_key(const struct marker* marker){
	if ( ! (marker_key && (marker->key_id == marker_key)) ){
		fprintf(stderr, "%s: Found marker, mismatch on key: looking for %ld, got %ld.\n ", program_name, (unsigned long)marker_key, (unsigned long)marker->key_id);
		return 0;
	}
	return 1;
}

static int handle_marker(const struct marker* mark, stream_addr_t* addr, stream_t* st){
	/* validate key */
	if ( !validate_key(mark) ){
		return 0;
	}

	/* show marker */
	marker_report(mark);

	/* abort if output is pipe */
	if ( strcmp("/dev/stdout", addr->local_filename) == 0 ){
		return 1;
	}

	/* termination marker */
	if ( mark->flags & MARKER_TERMINATE ){
		marker_terminate++;
		return 0;
	}

	if ( open_next(addr, st, mark) != 0 ){
		return 1; /* error already shown */
	}

	return 0;
}

static int handle_marker_caphead(const struct cap_header* cp, stream_addr_t* addr, stream_t* st){
	struct marker mark;
	if ( !(marker && is_marker(cp, &mark, marker)) ){
		return 0;
	}
	return handle_marker(&mark, addr, st);
}

static int handle_marker_server(void* payload, stream_addr_t* addr, stream_t* st){
	struct marker mark;
	if ( !(marker && is_marker_udp(payload, &mark, marker)) ){
		return 0;
	}
	return handle_marker(&mark, addr, st);
}

static int write_packet(struct cap_header* cp, stream_t st){
	if ( !st ) return 0;

	int ret;
	cp->caplen = cp->caplen < cp->len ? cp->caplen : cp->len; /* truncate */
	if ( (ret=stream_copy(st, cp)) != 0 ) {
		fprintf(stderr, "%s: stream_copy() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret) );
		return ret;
	}

	return 0;
}

static void set_destination(stream_addr_t* addr, const char* str){
	stream_addr_reset(addr);
	stream_addr_aton(addr, str, STREAM_ADDR_GUESS, 0);
	free(fmt_basename);
	fmt_basename = strdup(str);
	fmt_extension = fmt_basename;
	while ( *fmt_extension && *fmt_extension != '.' ){
		fmt_extension++;
	}
	if ( *fmt_extension ){
		*fmt_extension++ = 0;
	}
}

static void *tcprelay(void *arg){
	fprintf(stderr,"TCP thread awaken.\n");
	int tcpmainsocket;
	int tcpchildsocket;
	struct sockaddr_in clientaddr; /* client addr */
	struct sockaddr_in serveraddr; /* client addr */
	static char buf[BUFSIZE]; /* message buf */

	tcpmainsocket = socket(PF_INET, SOCK_STREAM, 0);
	if ( tcpmainsocket < 0 ){
		error("socket");
	}

	int optval = 1;
	setsockopt(tcpmainsocket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	/*--- bind port/address to socket ---*/
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(portno);
	serveraddr.sin_addr.s_addr = INADDR_ANY;                   /* any interface */
	if ( bind(tcpmainsocket, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) != 0 ){
		error("bind");
	}
	/*--- make into listener with 10 slots ---*/
	if ( listen(tcpmainsocket, 10) != 0 ){
		error("listen");
	}

	int packet_size=sizeof(struct cap_header) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof( struct marker);
	struct packet* packet=(struct packet*)malloc(sizeof(struct packet));

	/* caphead */
	packet->cap.len = packet_size-sizeof(struct cap_header);
	packet->cap.caplen = packet_size-sizeof(struct cap_header);
	/*ethernet*/
	packet->eth_inner.h_proto = htons(ETHERTYPE_IP);
	//memcpy(&packet->eth_inner.h_source, &hwaddr, ETH_ALEN);
	//memcpy(&packet->eth_inner.h_dest, &addr.ether_addr, ETH_ALEN);
	strncpy(packet->cap.nic, "c0", 2);
	strncpy(packet->cap.mampid, "control", 8);
	/* The following IP&UDP packet is just a place holder, it's configured just to trick libcap_utils to think that its a marker */
	/* ip */
	packet->ip_inner.protocol=IPPROTO_UDP;
	packet->ip_inner.saddr= inet_addr("127.0.0.1");
	packet->ip_inner.daddr= inet_addr("127.0.0.1");
	packet->ip_inner.ihl=5;
	packet->ip_inner.version=4;
	packet->ip_inner.tot_len=sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct marker);
	packet->ip_inner.id=htonl(12345);
	/* udp */
	packet->udp_inner.dest=htons(portno);
	packet->udp_inner.source=htons(MARKERPORT);
	packet->udp_inner.len=sizeof(struct udphdr)+sizeof(struct marker);
	/* Make sure that the marker comment is empty. */
	memset(packet->mark_inner.comment,0,64);

	int sockread;

	/*--- begin waiting for connections ---*/
	while (keep_running){
		socklen_t clientlen = sizeof(clientaddr);

		fprintf(stderr,"Waiting for TCP input on %d.\n",portno);
		tcpchildsocket = accept(tcpmainsocket, (struct sockaddr *)&clientaddr, &clientlen);     /* accept connection */
		if (tcpchildsocket<0){
			error("Error on accept.\n");
		}
		fprintf(stderr,"Accepted tcp connection, read message.");
		/* There should be some bytes to read. */
		sockread=recvfrom(tcpchildsocket, buf, BUFSIZE,0, (struct sockaddr *) &clientaddr, &clientlen);
		if (sockread < 0) {
			error("Error in recvfrom .");
		}
		fprintf(stderr,"Received marker via server (TCP).\n");
		if ( handle_marker_server(&buf, &output, &dst) != 0 ){
			break; /* error already shown */
		}
		/* Use the 'dummy' packet */
		/* Give the packet a proper timestamp */
		packet->cap.ts = timepico_now();

		/* Copy the marker message that we got, relay it. */
		memcpy(&packet->mark_inner,&buf,sockread);

		if ( write_packet(&packet->cap, dst) != 0 ){
			break; /* error already shown */
		}
		fprintf(stderr,"Close connection.\n");
		close(tcpchildsocket);
	}

	close(tcpmainsocket);
	return NULL;
}

static void setup_udp(struct packet* packet){
	/* We will activate the udp marker receiver */
	/*
	 * socket: create the parent socket
	 */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	/* setsockopt: Handy debugging trick that lets
	 * us rerun the server immediately after we kill it;
	 * otherwise we have to wait about 20 secs.
	 * Eliminates "ERROR on binding: Address already in use" error.
	 */
	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
	           (const void *)&optval , sizeof(int));

	/*
	 * build the server's Internet address
	 */
	struct sockaddr_in serveraddr;
	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)portno);

	/*
	 * bind: associate the parent socket with a port
	 */
	if (bind(sockfd, (struct sockaddr *) &serveraddr,
	         sizeof(serveraddr)) < 0)
		error("ERROR on binding");

	/* Now setup the socket poll/select */
	int packet_size=sizeof(struct cap_header) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof( struct marker);

	/* caphead */
	packet->cap.len = packet_size-sizeof(struct cap_header);
	packet->cap.caplen = packet_size-sizeof(struct cap_header);
	/*ethernet*/
	packet->eth_inner.h_proto = htons(ETHERTYPE_IP);
	//memcpy(&packet->eth_inner.h_source, &hwaddr, ETH_ALEN);
	//memcpy(&packet->eth_inner.h_dest, &addr.ether_addr, ETH_ALEN);
	strncpy(packet->cap.nic, "c0", 2);
	strncpy(packet->cap.mampid, "control", 8);
	/* The following IP&UDP packet is just a place holder, it's configured just to trick libcap_utils to think that its a marker */
	/* ip */
	packet->ip_inner.protocol=IPPROTO_UDP;
	packet->ip_inner.saddr= inet_addr("127.0.0.1");
	packet->ip_inner.daddr= inet_addr("127.0.0.1");
	packet->ip_inner.ihl=5;
	packet->ip_inner.version=4;
	packet->ip_inner.tot_len=sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct marker);
	packet->ip_inner.id=htonl(12345);
	/* udp */
	packet->udp_inner.dest=htons(portno);
	packet->udp_inner.source=htons(MARKERPORT);
	packet->udp_inner.len=sizeof(struct udphdr)+sizeof(struct marker);
	/* Make sure that the marker comment is empty. */
	memset(packet->mark_inner.comment,0,64);

	/*
	 * main loop: wait for a datagram, then echo it
	 */
	fprintf(stderr," Waiting for markers on UDP port %d.\n",portno);
}

static int handle_udp(struct packet* packet){
	if ( sockfd == 0 ){
		return 0;
	}

	static char buf[BUFSIZE]; /* message buf */
	int bytes = 0;

	/* check if the udp socket received any data, require it to be the size of a marker message */
	if ( ioctl(sockfd, FIONREAD, &bytes) != 0) {
		fprintf(stderr, "%s: ioctl(udp, FIONREAD, ..) failed: %s\n", program_name, strerror(errno));
	}
	if ( bytes < (int)sizeof(struct marker) ) {
		return 0;
	}

	/* There should be some bytes to read. */
	socklen_t clientlen = sizeof(clientaddr);
	bytes = recvfrom(sockfd, buf, BUFSIZE,0, (struct sockaddr *) &clientaddr, &clientlen);
	if (bytes < 0) {
		error("Error in recvfrom .");
	}
	fprintf(stderr,"Received marker via server.\n");
	if ( handle_marker_server(&buf, &output, &dst) != 0 ){
		return 1;
	}

	/* Use the 'dummy' packet */
	/* Give the packet a proper timestamp */
	packet->cap.ts = timepico_now();

	/* Copy the marker message that we got, relay it. */
	memcpy(&packet->mark_inner,&buf, bytes);

	if ( write_packet(&packet->cap, dst) != 0 ){
		return 1;
	}

	return 0;
}

int main(int argc, char **argv){
	fprintf(stderr, "capdump-%s\n", caputils_version(NULL));

	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	char* iface = NULL;
	size_t buffer_size = 0;
	unsigned int max_packets = 0;
	unsigned long written_packets = 0;
	pthread_t child;
	struct packet* udp_dummy = (struct packet*)malloc(sizeof(struct packet));

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'o':
			set_destination(&output, optarg);
			break;

		case 'p':
			max_packets = atoi(optarg);
			break;

		case 'c':
			comment = optarg;
			break;

		case 'b': /* --bufsize */
			buffer_size = atoi(optarg);
			break;

		case 'i':
			iface = optarg;
			break;

		case 'm': /* --marker */
			marker = atoi(optarg);
			break;

		case 'f': /* --marker-format */
			marker_format = optarg;
			break;

		case 'M': /* --marker-mode */
			marker_mode = parse_marker_mode(optarg);
			break;

		case 'K': /* --marker-key */
			marker_key = atoi(optarg);
			break;

		case 'P': /* set port */
			portno=atoi(optarg);
			break;

		case 'L': /* --listen */
			use_listen = 1;
			break;

		case 'C': /* --marker-comment */
			marker_comment = 1;
			break;

		case 'Q': /* --marker-quit */
			marker_quit=1;
			break;

		case 's': /* --progress */
			progress = STDERR_FILENO;
			if ( optarg ){
				progress = atoi(optarg);
				int fd = dup(progress);
				if (fd < 0) {
					fprintf(stderr, "%s: invalid progress file descriptor: %s\n", program_name, strerror(errno));
					return 1;
				}
				close(fd);
				break;
			}
			break;

		case 'h':
			show_usage();
			exit(0);
			break;

		default:
			if ( option_index >= 0 ){
				fprintf(stderr, "flag --%s declared but not handled\n", longopts[option_index].name);
			} else {
				fprintf(stderr, "flag -%c declared but not handled\n", op);
			}
			abort();
		}
		option_index = -1;
	}

	stream_t src;

	long ret;

	/* use stdout as default output if connected stdout is redirected */
	if ( !(stream_addr_is_set(&output) || isatty(STDOUT_FILENO)) ){
		stream_addr_str(&output, "/dev/stdout", 0);
	}

	/* if no output was given using -o or redirection grab the last positional argument */
	if ( !stream_addr_is_set(&output) ){
		if ( optind < argc ){
			set_destination(&output, argv[argc-1]);
			argc--;
		} else {
			show_usage();
			exit(0);
		}
	}

	/* Install signal handler so loop can be aborted. Handlers are installed
	 * before opening streams in case they block and SIGINT is passed to
	 * terminate blocking call. */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* open input stream (using a small buffer so pipes will fill faster) */
	if ( (ret=stream_from_getopt(&src, argv, optind, argc, iface, "-", program_name, buffer_size)) != 0 ) {
		return 1;
	}

	/* set hostname as mpid */
	gethostname(mpid, 8);

	/* open output stream */
	if ( (ret=stream_create(&dst, &output, NULL, mpid, comment)) != 0 ){
		fprintf(stderr, "stream_create() failed with code 0x%08lX: %s\n", ret, caputils_error_string(ret));
		return 1;
	}
	stream_stat = stream_get_stat(src);
	src_stream_count = stream_num_address(src);

	/* progress report */
	struct itimerval tv = {
		{IRQ_DELAY, 0},
		{IRQ_DELAY, 0},
	};
	setitimer(ITIMER_REAL, &tv, NULL);
	signal(SIGALRM, my_signalhandler);

	/* key validation */
	if (marker_key){
		fprintf(stderr, "%s: Looking for %ld as key.\n", program_name, (unsigned long)marker_key);
	}

	/* Quit / Continue */
	if ( marker_quit ){
		fprintf(stderr,"%s: Will quit upon receving termination marker.\n", program_name);
	} else {
		fprintf(stderr,"%s: Will continue after receving termination marker.\n", program_name);
	}

	/* setup listen server */
	if ( use_listen ){
		setup_udp(udp_dummy);
		pthread_create(&child,0,tcprelay,0);
		pthread_detach(child);
	}

	while( keep_running ){
		if ( handle_udp(udp_dummy) != 0 ) break;

		/* Read the next packet */
		cap_head* cp;
		ret = stream_read(src, &cp, NULL, NULL);
		if ( ret == EAGAIN ){ /* a timeout occured */
			continue;
		} else if ( ret == EINTR && keep_running != 0 ){ /* don't abort unless signal caused a halt */
			continue;
		} else if ( ret > 0 ){ /* either an error or proper shutdown */
			fprintf(stderr, "%s: stream_read() returned 0x%08lX: %s\n", program_name, ret, caputils_error_string(ret));
			break;
		} else if ( ret == -1 ){
			break;
		} else if ( ret != 0 ){
			abort();
		}

		if ( handle_marker_caphead(cp, &output, &dst) != 0 ){
			break; /* error already shown */
		}

		if ( write_packet(cp, dst) != 0 ){
			break; /* error already shown */
		}

		written_packets++;
		if ( max_packets > 0 && stream_stat->read >= max_packets ){
			break;
		}
	}

	fprintf(stderr, "%s: There was a total of %'"PRIu64" packets recv.\n", program_name, stream_stat->recv);
	fprintf(stderr, "%s: There was a total of %'"PRIu64" packets read.\n", program_name, stream_stat->read);
	fprintf(stderr, "%s: There was a total of %'ld packets writen.\n", program_name, written_packets);

	close(sockfd);

	stream_close(src);
	stream_close(dst);
	stream_addr_reset(&output);
	free(fmt_basename);
	free(udp_dummy);

	return 0;
}
