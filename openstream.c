/***************************************************************************
                          openstream.c  -  description
                             -------------------
    begin                : Mon Feb 3 2003
    copyright            : (C) 2005 by Patrik Arlos
    email                : Patrik.Arlos@bth.se
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/***************************************************************************
 This function opens a large file (64bits) and reads the fileheader
 described in caputils/caputils.h. the file pointer the points to the first packet.
 Function returns 1 if success and 0 if open failed.
 ***************************************************************************/

/*
INPUT:
  struct stream *myStream; Pointer to a struct handling the stream. 
  char *address;           A pointer to a string identifying the address/file we try to open.
  int  protocol;           Transport mode, 
                           0 -- Local file
			   1 -- Ethernet multicast
			   2 -- UDP multi/uni-cast
			   3 -- TCP unicast ??
  char *nic;               A pointer to a string identifying the interface to listen to. (NULL if a file)
  int port;                Port to listen to, incase of UDP or TCP. Not used for ethernet.

OUTPUT:
  int 0 if fail
  int 1 if ok.
*/

#include "caputils/caputils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <features.h>

#include <signal.h>
#include <getopt.h>
#include <unistd.h>

//#include <netpacket/packet.h>
#include <linux/if_packet.h>
//#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

/**
 * Validates the file_header version against libcap_utils version. Prints
 * warning to stderr if version mismatch.
 * @return Non-zero if version is valid.
 */
int is_valid_version(struct file_header* fhptr){
  if( fhptr->version.major == VERSION_MAJOR && fhptr->version.minor == VERSION_MINOR ) {
    return 1;
  }

  fprintf(stderr,"Stream uses version %d.%d, this application uses ", fhptr->version.major, fhptr->version.minor);
  fprintf(stderr,"Libcap_utils version " VERSION "\n");
  fprintf(stderr,"Change libcap version or convert file.\n");
  return 0;
}

/**
 * Initialize variables for a stream.
 * @bug To retain compability with code, some variables which weren't
 *      initialized are left that way, at least until I proved and tested it
 *      does not break.
 * @return Non-zero on failure.
 */
static int stream_init(struct stream* st, int protocol, int port){
  st->type=protocol;
  st->myFile=0;
  st->mySocket=0;
  st->expSeqnr = 0;
  st->pktCount = 0;
  st->bufferSize=0;
  st->readPos=0;
  st->flushed = 0;
  st->address=0;
  st->filename=0;
  st->portnr=port;

  st->ifindex=0;
  /** st->if_mtu = 0; for backwards compability, @bug */
  st->comment=0;

  /* callbacks */
  st->fill_buffer = NULL;
  st->destroy = NULL;

  memset(st->buffer, 0, buffLen);

  /* initialize file_header */
  st->FH.comment_size=0;
  memset(st->FH.mpid, 0, 200); /* @bug what is 200? why is not [0] = 0 enought? */

  return 0;
}

int openstream(struct stream *myStream,char *address, int protocol, char *nic, int port){
  // Temporary buffer for holding ETHERNET/UDP packets, while filling buffer.
  char osrBuffer[buffLen] = {0,};
  int ret = 0;

  char *ether=osrBuffer;
  struct sendhead *sh=0;
  if(protocol==1)
    sh=(struct sendhead *)(ether+sizeof(struct ethhdr));
  if(protocol==2 || protocol==3) 
    sh=(struct sendhead *)(ether);

  int readBytes=0;

  /* Initialize the structure */
  if ( (ret=stream_init(myStream, protocol, port)) != 0 ){
    fprintf(stderr, "stream_init failed with code %d\n", ret);
    exit(1);
  }

#ifdef DEBUG
  printf("openstream() \n");
#endif
  switch(protocol){
    case PROTOCOL_TCP_UNICAST:
      ret = stream_tcp_init(myStream, address, port);
      break;

    case PROTOCOL_UDP_MULTICAST:
      ret = stream_udp_init(myStream, address, port);
      break;

    case PROTOCOL_ETHERNET_MULTICAST:
      ret = stream_ethernet_init(myStream, address);
      break;
    case PROTOCOL_LOCAL_FILE:
      ret = stream_file_init(myStream, address);
      break;

    default:
      fprintf(stderr, "Unhandled protocol %d\n", protocol);
      return 0;
  }

  /* initialize a file stream */
  if ( ret != 0 ){
    fprintf(stderr, "failed to initialize protocol. code %d:\n", ret);
    fprintf(stderr, "  protocol: %d\n", protocol);
    fprintf(stderr, "  message: %s\n", strerror(ret));
    return 0;
  }

  switch(myStream->type){
    case PROTOCOL_TCP_UNICAST:
      readBytes=recvfrom(myStream->mySocket, osrBuffer, sizeof(struct sendhead), 0, NULL, NULL);
      
      if(readBytes<0){
	perror("Cannot receive TCP data.");
	return(0);
      }
      if(readBytes==0){
	perror("Connection closed by client.");
	myStream->flushed=1;
	break;
      }
      myStream->FH.version.major=ntohs(sh->version.major);
      myStream->FH.version.minor=ntohs(sh->version.minor);
      if ( !is_valid_version(&myStream->FH) ){
	return EINVAL;
      }

#ifdef DEBUG
      printf("Read %d bytes, Got the sendhead.\n",readBytes);
#endif
      // Now we read some packets.
      while(myStream->bufferSize==0){ // This equals approx 1 packets each of 
	readBytes=recvfrom(myStream->mySocket, myStream->buffer, buffLen, 0, NULL, NULL);
	
	if(readBytes<0){
	  perror("Cannot receive TCP/UDP data.");
	  return(0);
	}
	if(readBytes==0){
	  perror("Connection closed by client.");
	  myStream->flushed=1;
	  break;
	}
#ifdef DEBUG
	printf("myStream->buffer = %p\n",myStream->buffer);
	printf("Packet contained %d bytes Buffer Size = %d / %d  \n",readBytes,myStream->bufferSize, buffLen);
#endif
	if(ntohs(sh->flush)==1){// This indicates a flush from the sender..
#ifdef DEBUG
	  printf("Sender terminated. \n");
#endif
	  myStream->flushed=1;
	  break;//Break the while loop.
	}
	myStream->bufferSize+=readBytes;
      }
      break;

    case PROTOCOL_UDP_MULTICAST:
      while(myStream->bufferSize==0){ // This equals approx 5 packets each of 
	readBytes=recvfrom(myStream->mySocket, osrBuffer, buffLen, 0, NULL, NULL);
	
	if(readBytes<0){
	  perror("Cannot receive TCP/UDP data.");
	  return(0);
	}
	if(readBytes==0){
	  perror("Connection closed by client.");
	  return(0);
	}
	myStream->pktCount+=ntohs(sh->nopkts);
	if(myStream->bufferSize<7410) {
	  myStream->expSeqnr=ntohl(sh->sequencenr)+1;
	  myStream->FH.version.major=ntohs(sh->version.major);
	  myStream->FH.version.minor=ntohs(sh->version.minor);
	  if ( !is_valid_version(&myStream->FH) ){
	    return EINVAL;
	  }
	} else {
	  if(myStream->expSeqnr!=ntohl(sh->sequencenr)){
	    fprintf(stderr,"Missmatch of sequence numbers. Expeced %ld got %d\n",myStream->expSeqnr, ntohl(sh->sequencenr));
	    myStream->expSeqnr=ntohl(sh->sequencenr);
	  } 
	  myStream->expSeqnr++;
	  if(myStream->expSeqnr>=0xFFFF){
	    myStream->expSeqnr=0;
	  }
	  
	}
	memcpy(myStream->buffer+myStream->bufferSize, osrBuffer+sizeof(struct sendhead), readBytes-sizeof(struct sendhead));
	myStream->bufferSize+=(readBytes-sizeof(struct sendhead));
#ifdef DEBUG
	printf("Packet contained %d bytes (Send %d, Cap %d) Buffer Size = %d / %d  Pkts %ld \n",readBytes, sizeof(struct sendhead),sizeof(struct cap_header),myStream->bufferSize, buffLen, myStream->pktCount);
	printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
#endif
	if(ntohs(sh->flush)==1){// This indicates a flush from the sender..
#ifdef DEBUG
	  printf("Sender terminated. \n");
#endif
	  myStream->flushed=1;
	  break;//Break the while loop.
	}
      }
     break;
    case PROTOCOL_ETHERNET_MULTICAST:
    case PROTOCOL_LOCAL_FILE:
      myStream->fill_buffer(myStream);
      break;
  }

  myStream->readPos=0;

#ifdef DEBUG
  printf("Read op filled: %p --- %04x --- %p \n", myStream->buffer, readBytes, myStream->buffer+readBytes);
#endif
  if(myStream->bufferSize<buffLen){
    switch(myStream->type){
      case 3:
      case 2:
      case 1:
	break;
      case 0:
      default:
	if(ferror(myStream->myFile)>0){
	  perror("Reading file.");
	  return(0); // Some error occured.
	}
    }
  }
  
  if(myStream->bufferSize==0) {
    switch(myStream->type){
      case 3:
      case 2:
      case 1:
	//perror("Connection closed. ");
	return(0);
	break;
      case 0:
      default:
	if(feof(myStream->myFile)){
	  //perror("EOF reached.");
	  return(0);// End-of-file reached.
	}
    }
  }
#ifdef DEBUG
  printf("OPENSTREAM Initial read complete.\n");  
#endif  


  return(1);
    
}
