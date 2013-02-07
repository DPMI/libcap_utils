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
#endif /* HAVE_CONFIG_H */

#include "caputils/marc.h"
#include "caputils/version.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h> /* required for offsetof */
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>

#define DEFAULT_CLIENT_PORT 2000
#define DEFAULT_RELAY_PORT 1500
#define DEFAULT_MARCD_PORT 1600

/* might be a portability problem, add ifdefs for GCC if this fails */
#define UNUSED __attribute__((unused))

enum context_type {
	CONTEXT_SERVER,
	CONTEXT_CLIENT,
};

struct marc_context {
	char ip[INET_ADDRSTRLEN];
	int port;
	char* iface;
	struct ether_addr hwaddr;
	enum context_type type;
	int sd;
	enum MPEvent (*compat)(enum MPEvent);
};
typedef struct marc_context context_t;

struct client {
	struct marc_context context;
	struct sockaddr_in client_addr;
	struct sockaddr_in relay_addr;
	struct sockaddr_in server_addr;
	version_t server_version;
};
typedef struct client client_t;

struct server {
	struct marc_context context;
	struct sockaddr_in addr;
	version_t server_version;
};
typedef struct server server_t;

/* Structure used to communicate to the MA relayer */
struct MAINFO {
	int version;
	char address[16];
	int port;
	char database[64];
	char user[64];
	char password[64];
	int portUDP;
};

/**
 * wrapper around perror. saves and returns errno after calling perror.
 */
static int perror2(const char* s){
	int save = errno;
	perror(s);
	return save;
}

static marc_output_handler_t out_func = fprintf;
static marc_output_handlerv_t out_funcv = vfprintf;
static FILE* dst_error = NULL;
static FILE* dst_verbose = NULL;

void mampid_set(mampid_t dst, const char* src){
	/* no garbage in field, mostly for viewing hexdumps of traffic */
	memset(dst, 0, 16);

	/* if no src is provided, it is considered a reset */
	if ( src ){
		strncpy(dst, src, 16);
	}
}

const char* mampid_get(const mampid_t src){
	static char buf[17];

	if ( src[0] != 0 ){
		sprintf(buf, "%.16s", src);
		return buf;
	} else {
		return "(nil)";
	}
}

int marc_set_output_handler(marc_output_handler_t func, marc_output_handlerv_t vfunc, FILE* errors, FILE* verbose){
	out_func = func;
	out_funcv = vfunc;
	dst_error = errors;
	dst_verbose = verbose;
	return 0;
}

int marc_init_client(marc_context_t* ctxptr, const char* iface, struct marc_client_info* info){
	assert(ctxptr);
	assert(iface);
	assert(info);

	if ( !dst_error ){
		dst_error = stderr;
		dst_verbose = stderr;
	}

	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, iface, IFNAMSIZ);

	/* open UDP socket */
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if( sd < 0) {
		return perror2("socket");
	}

	/* query mac address on iface */
	struct ether_addr hwaddr;
	if ( ioctl(sd, SIOCGIFHWADDR, &ifreq) == -1) {
		return perror2("ioctl SIOCGIFHWADDR");
	}
	memcpy(hwaddr.ether_addr_octet, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

	/* query ip address on iface */
	if( ioctl(sd, SIOCGIFADDR, &ifreq) == -1 ) {
		return perror2("ioctl SIOCGIFADDR");
	}

	/* check if a address was found */
	if( ifreq.ifr_addr.sa_family != AF_INET) {
		return perror2("ifr_addr.sa_family");
	}

	/* setup broadcast */
	int broadcast = 1;
	if( setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(int)) == -1 ){
		return perror2("setsockopt SO_BROADCAST");
	}

	/* create addr structs */
	struct sockaddr_in client_addr;
	struct sockaddr_in relay_addr;
	struct sockaddr_in server_addr;
	memset(&client_addr, 0, sizeof(struct sockaddr_in));
	memset(&relay_addr,  0, sizeof(struct sockaddr_in));
	memset(&server_addr, 0, sizeof(struct sockaddr_in));

	/* setup client addr */
	info->client_port = info->client_port == 0 ? DEFAULT_CLIENT_PORT : info->client_port;
	memcpy(&client_addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
	if ( info->client_ip && inet_aton(info->client_ip, (struct in_addr*)&client_addr) == 0){
		return perror2("inet_aton");
	}
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(info->client_port);

	/* setup relay addr */
	relay_addr.sin_family = AF_INET;
	relay_addr.sin_port   = htons(DEFAULT_RELAY_PORT);
	relay_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	/* bind socket to client addr */
	if( bind(sd, (struct sockaddr*)&client_addr, sizeof(struct sockaddr_in)) == -1){
		return perror2("bind");
	}

	/* send initialization request to relay */
	{
		struct MAINFO mainfo;
		memset(&mainfo, 0, sizeof(struct MAINFO));
		mainfo.version = htons(3);
		mainfo.port = client_addr.sin_port;
		sprintf(mainfo.address, "%s", inet_ntoa(client_addr.sin_addr));

		if ( sendto(sd, &mainfo, sizeof(struct MAINFO), 0, (struct sockaddr*)&relay_addr, sizeof(struct sockaddr_in)) == -1 ){
			return perror2("sendto");
		}
	}

	/* await relay reply */
	struct MAINFO reply;
	int n = 1;
	static const int max_retries = 6; /* try at most n times */
	static const int timeout_factor = 8; /* for each retry, wait n*x sec */
	while ( n < max_retries ){
		struct timeval timeout = { n * timeout_factor, 0 };
		out_func(dst_verbose, "Sending init request to MArelayD (try: %d timeout: %d)\n", n, timeout.tv_sec);
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(sd, &fds);

		switch ( select(sd+1, &fds, NULL, NULL, &timeout) ){
		case -1:
			if ( errno == EINTR ){ /* dont want to show perror for this */
				return errno;
			}
			return perror2("select");
		case 0:
			out_func(dst_verbose, "Request timed out.\n");
			n++;
			continue;
		default:
			break;
		}

		if ( recvfrom(sd, &reply, sizeof(struct MAINFO), 0, NULL, NULL) == -1 ){
			return perror2("recvfrom");
		}

		break;
	}

	if ( n < max_retries ){
		out_func(dst_verbose, "Got MArelayD reply (v%d): MArCd: udp://%s:%d\n", reply.version, reply.address, reply.portUDP);
	} else {
		out_func(dst_error, "Gave up trying to contact MArelayD after %d tries.\n", n-1);
		return ECANCELED;
	}

	if ( ntohs(reply.version) == 1 ){
		out_func(dst_error, "MA version 1 (mysql) is unsupported\n");
		return ECONNREFUSED;
	}

	/* Reusing socket, just disable broadcast. */
	broadcast = 0;
	if( setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == -1 ){
		return perror2("setsockopt SO_BROADCAST 0");
	}

	/* setup server addr */
	server_addr.sin_family = AF_INET;
	server_addr.sin_port   = htons(reply.portUDP);
	inet_aton(reply.address, (struct in_addr*)&server_addr.sin_addr.s_addr);

	/* allocate context */
	client_t* client = malloc(sizeof(struct client));
	if ( !client ){
		return perror2("malloc");
	}
	marc_context_t ctx = &client->context;

	/* fill context */
	info->client_ip = inet_ntop(AF_INET, &client_addr.sin_addr, ctx->ip, INET_ADDRSTRLEN);
	ctx->port = info->client_port;
	ctx->iface = strdup(iface);
	ctx->type = CONTEXT_CLIENT;
	ctx->sd = sd;
	ctx->compat = NULL;
	memcpy(&ctx->hwaddr, &hwaddr, sizeof(struct ether_addr));
	memcpy(&client->client_addr, &client_addr, sizeof(struct sockaddr_in));
	memcpy(&client->relay_addr,  &relay_addr,  sizeof(struct sockaddr_in));
	memcpy(&client->server_addr, &server_addr, sizeof(struct sockaddr_in));

	*ctxptr = ctx;

	return marc_client_init_request(ctx, info);
}

int marc_client_init_request(marc_context_t ctx, struct marc_client_info* info){
	MPMessage msg;
	memset(&msg, 0, sizeof(MPMessage));

	struct MPinitialization* init = (struct MPinitialization*)&msg;
	struct client* client = (struct client*)ctx;

	msg.type = MP_CONTROL_INIT_EVENT;

	memcpy(&init->hwaddr, &ctx->hwaddr, sizeof(struct ether_addr));
	gethostname(init->hostname, 200);
	memcpy(init->ipaddress, &client->client_addr.sin_addr.s_addr, sizeof(struct in_addr));
	init->port = client->client_addr.sin_port;
	init->maxFilters = htons(info->max_filters);
	init->noCI = htons(info->noCI);
	init->ma_mtu = htons(info->ma_mtu);
	init->version.protocol.major = htons(CAPUTILS_VERSION_MAJOR);
	init->version.protocol.minor = htons(CAPUTILS_VERSION_MINOR);

	/* extended version */
	init->version.caputils = info->version.caputils;
	init->version.self = info->version.self;
	init->drivers = htonl(info->drivers);
	memcpy(init->CI, info->CI, sizeof(struct CIinitialization) * info->noCI);

	return marc_push_event(ctx, (MPMessage*)&msg, (struct sockaddr*)&client->server_addr);
}

int marc_init_server(marc_context_t* ctxptr, int port){
	assert(ctxptr);

	if ( !dst_error ){
		dst_error = stderr;
		dst_verbose = stderr;
	}

	/* socket creation. */
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( sd < 0 ) {
		return perror2("socket");
	}

	/* setup broadcast */
	int broadcast = 1;
	if( setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(int)) == -1 ){
		return perror2("setsockopt SO_BROADCAST");
	}

	const int server_port = port == 0 ? DEFAULT_MARCD_PORT : port;
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = 0;

	/* bind legacy server port */
	server_addr.sin_port = htons(server_port);
	out_func(dst_error, "Listens to %s:%d\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
	if ( bind(sd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0 ){
		return perror2("bind");
	}

	/* allocate context */
	server_t* server = malloc(sizeof(struct server));
	if ( !server ){
		return perror2("malloc");
	}
	marc_context_t ctx = &server->context;

	/* fill context */
	ctx->iface = NULL;
	ctx->type = CONTEXT_SERVER;
	ctx->sd = sd;
	ctx->compat = NULL;
	memset(&ctx->hwaddr, 0, sizeof(struct ether_addr));
	memcpy(&server->addr, &server_addr, sizeof(struct sockaddr_in));

	*ctxptr = ctx;


	return 0;
}

int marc_cleanup(marc_context_t ctx){
	free(ctx->iface);
	free(ctx);
	return 0;
}

static size_t event_size(MPMessage* event){
	assert(event);

	const enum MPEvent type = (enum MPEvent)event->type;
	switch ( type ){
	case MP_CONTROL_INIT_EVENT:
		return sizeof(struct MPinitialization) + ntohs(sizeof(struct CIinitialization) * ((struct MPinitialization*)event)->noCI);

	case MP_CONTROL_AUTHORIZE_EVENT:
		return sizeof(struct MPauth);

	case MP_STATUS_EVENT:
		return offsetof(struct MPstatusLegacy, CIstats) + strlen(((struct MPstatusLegacy*)event)->CIstats) + 1; /* +1 nullterminator */

	case MP_STATUS3_EVENT:
		return sizeof(struct MPstatusExtended) + sizeof(struct CIstats) * ((struct MPstatusExtended*)event)->noCI;

	case MP_FILTER_EVENT:
		return sizeof(struct MPFilter);

	case MP_FILTER_REQUEST_EVENT:
		return sizeof(struct MPFilterID);

	case MP_FILTER_INVALID_ID:
		return sizeof(uint32_t); /* only type is sent */

	case MP_CONTROL_TERMINATE_EVENT:
	case MP_CONTROL_STOP_EVENT:
	case MP_CONTROL_START_EVENT:
	case MP_CONTROL_DISTRESS:
	case MP_CONTROL_PING_EVENT:
		return sizeof(uint32_t) + sizeof(mampid_t); /* only type and MAMPid is sent */

	default:
		assert(0 && "sizeof for unknown type");
		return sizeof(uint32_t);
	}
}

enum MPEvent legacy_compat(enum MPEvent event){
	switch ( event ){
		/* from client */
	case MP_CONTROL_INIT_EVENT:
		return MP_LEGACY_INIT_EVENT;

	case MP_STATUS_EVENT:
		return MP_LEGACY_STATUS_EVENT;

	case MP_FILTER_REQUEST_EVENT:
		return 3;

		/* from server */
	case MP_LEGACY_FILTER_ADD_EVENT:
		return MP_FILTER_EVENT;

	default:
		return event;
	}
}

int marc_push_event(marc_context_t ctx, MPMessage* event, struct sockaddr* dst){
	assert(ctx);
	assert(event);

	const size_t size = event_size(event);

	/* compatibility mode */
	if ( ctx->compat ){
		event->type = ctx->compat(event->type);
	}

	event->type = htonl(event->type);

	if ( !dst ){
		struct client* client = (struct client*)ctx;
		dst = (struct sockaddr*)&client->server_addr;
	}

	if ( sendto(ctx->sd, event, size, 0, dst, sizeof(struct sockaddr)) == -1 ){
		return perror2("sendto");
	}

	return 0;
}

int marc_poll_event(marc_context_t ctx, MPMessage* event, size_t* size, struct sockaddr* cfrom, socklen_t* addrlen, struct timeval* timeout){
	assert(ctx);
	assert(event);

	//static socklen_t addrlen = sizeof(struct sockaddr_in);
	struct client* client = (struct client*)ctx;

	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(ctx->sd, &fds);
	memset(event, 0, sizeof(MPMessage));

	switch ( select(ctx->sd+1, &fds, NULL, NULL, timeout) ){
	case -1:
		return errno;
	case 0:
		return EAGAIN;
	default:
		break;
	}

	ssize_t bytes;
	struct sockaddr_in from;
	socklen_t socklen = sizeof(struct sockaddr_in);
	if ( (bytes=recvfrom(ctx->sd, event, sizeof(MPMessage), 0, (struct sockaddr*)&from, &socklen)) <= 0 ){
		return errno;
	}

	/* copy address to caller */
	if ( cfrom ){
		memcpy(cfrom, &from, *addrlen);
		*addrlen = socklen;
	}

	event->type = ntohl(event->type);

	/* fill in version field for old MArCd versions */
	const int legacy_marc = ctx->type == CONTEXT_CLIENT && event->type == MP_LEGACY_AUTH_EVENT && (size_t)bytes < sizeof(struct MPauth);
	const int legacy_mp   = ctx->type == CONTEXT_SERVER && event->type == MP_LEGACY_INIT_EVENT && (size_t)bytes < sizeof(struct MPinitialization);
	if ( legacy_marc ){
		event->type = MP_CONTROL_AUTHORIZE_EVENT;
		event->auth.version.major = 0;
		event->auth.version.minor = 6;
		ctx->compat = legacy_compat;

		out_func(dst_error, "Activating MArCd compatibility mode (v0.6). Please update MArCd. This can also\n");
		out_func(dst_error, "happen if using a legacy version of the webgui to authorize, if so please\n");
		out_func(dst_error, "restart this measurement point.\n");
	} else if ( legacy_mp ){
		event->type = MP_CONTROL_INIT_EVENT;
		event->init.noCI = 0;
		event->init.version.protocol.major = htons(0);
		event->init.version.protocol.minor = htons(6);

		out_func(dst_error, "Activating MP compatibility mode (v0.6). Please update MP to a later version.\n");
	}

	/* intercept auth event to store version */
	if ( event->type == MP_CONTROL_AUTHORIZE_EVENT ){
		client->server_version = event->init.version.protocol;
	}

	/* intercept ping events, no need to bother client with this */
	int ret;
	if ( event->type == MP_CONTROL_PING_EVENT ){
		out_func(dst_verbose, "Got ping requst from %s:%d, sending pong.\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
		if ( (ret=marc_push_event(ctx, event, (struct sockaddr*)&from)) != 0 ){
			out_func(dst_error, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
		}
		return EAGAIN; /* slight abuse of EAGAIN but easiest way to have client retry */
	}

	/* legacy hack. php-gui sends a events without full payload */
	if ( bytes < 100 && event->type < 11 ){ /* keeping logic from MP (100 bytes is probably arbitrary)*/
		switch ( event->type ){
		case MP_CONTROL_AUTHORIZE_EVENT:
			break; /* already handled */

		case MP_LEGACY_FILTER_ADD_EVENT:
			event->type = MP_FILTER_REQUEST_EVENT;
			event->filter_id.id = htonl(atoi(event->payload));
			break;

		case MP_LEGACY_FILTER_DEL_EVENT:
			event->type = MP_FILTER_DEL_EVENT;
			event->filter_id.id = htonl(atoi(event->payload));
			break;

		case MP_LEGACY_FILTER_RELOAD_EVENT:
			event->type = MP_FILTER_RELOAD_EVENT;
			event->filter_id.id = htonl(-1);
			break;

		default:
			out_func(dst_error, "Got unhandled legacy PHP message of type %d. Here be dragons.\n", event->type);
		}
	} else if ( ctx->compat ){ /* compatibility mode */
		event->type = ctx->compat(event->type);
	}

	*size = bytes;
	return 0;
}

int marc_filter_request(marc_context_t ctx, const char* MAMPid, uint32_t filter_id){
	struct MPFilterID msg;
	msg.type = MP_FILTER_REQUEST_EVENT;
	msg.id = htonl(filter_id);
	mampid_set(msg.MAMPid, MAMPid);
	return marc_push_event(ctx, (MPMessage*)&msg, NULL);
}
