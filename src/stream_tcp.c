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

#include "caputils/caputils.h"
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int stream_tcp_init(struct stream* st, const char* address, int port){
	struct sockaddr_in sender, client;
	struct ifreq ifr;
	int listen_socket;

	assert(st);
	assert(address);

	/* open tcp socket */
	listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP); /** @todo Verify that IPPROTO_IP correct, was 0 before */
	if ( st->mySocket < 0 ){
		perror("socket open failed");
		return errno;
	}

	setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,(void*)1, sizeof(int));

	sender.sin_family = AF_INET;
	inet_aton(address, &sender.sin_addr);
	sender.sin_port = htons(port);

	if( bind (listen_socket, (struct sockaddr *) &sender, sizeof(sender)) < 0 ){
		perror("Cannot bind port number");
		return errno;
	}
	listen(listen_socket, 1);

	socklen_t len = sizeof(client);
	st->mySocket = accept(listen_socket, (struct sockaddr *)&client, &len);
	if( st->mySocket < 0 ){
		perror("Cannot accept new connection.");
		return errno;
	}

#ifdef DEBUG
	printf("TCP unicast\nIP.destination=%s port=%d\n", address,port);
	printf("Client: %s  %d\n",inet_ntoa(client.sin_addr), ntohs(client.sin_port));
#endif

	st->address = strdup(address);

	/* query interface index */
	if ( ioctl(st->mySocket, SIOCGIFINDEX, &ifr) == -1 ){
		perror("SIOCGIFINDEX error");
		return errno;
	}
	st->ifindex=ifr.ifr_ifindex;

	/* query default MTU */
	if(ioctl(st->mySocket,SIOCGIFMTU,&ifr) == -1 ) {
		perror("SIOCGIIFMTU");
		return errno;
	}
	st->if_mtu=ifr.ifr_mtu;

	return 0;
}
