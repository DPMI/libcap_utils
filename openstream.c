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
 described in cap_utils.h. the file pointer the points to the first packet.
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

#include "cap_utils.h"

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

/**
 * Validates the file_header version against libcap_utils version. Prints
 * warning to stderr if version mismatch.
 * @return Non-zero if version is valid.
 */
static int is_valid_version(struct file_header* fhptr){
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
  /** st->expSeqnr = 0; for backwards compability, @bug */
  /** st->pktCount = 0; for backwards compability, @bug */
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
  char osrBuffer[buffLen]; // Temporary buffer for holding ETHERNET/UDP packets, while filling buffer.
  int newsocket=0;
  struct ifreq ifr;
  int ifindex=0;
  int socket_descriptor=0;
  struct sockaddr_in sender,client;
  socklen_t cliLen;
  if(nic!=0) {
    strncpy(ifr.ifr_name, nic, IFNAMSIZ);
  }
  char *myaddress=0;
  int i=0;
  int ret = 0;

  char *ether=osrBuffer;
  struct ethhdr *eh=(struct ethhdr *)ether;
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
    case 3: // TCP unicast
      newsocket=socket(AF_INET,SOCK_STREAM,0);
      if(newsocket<0) {
	perror("Cannot open socket. ");
	return(0);
      }     
      setsockopt(newsocket,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int));
      sender.sin_family = AF_INET;
//      sender.sin_addr.s_addr = htonl(INADDR_ANY);
      inet_aton(address,&sender.sin_addr);
      sender.sin_port = htons(port);

      if( bind (newsocket, (struct sockaddr *) &sender,sizeof(sender))<0){
	perror("Cannot bind port number \n");
	return(0);
      }
      listen(newsocket, 1);
#ifdef deug
      printf("Listens to %s:%d\n",inet_ntoa(sender.sin_addr),ntohs(sender.sin_port));
#endif
      cliLen=sizeof(client);
      socket_descriptor= accept(newsocket, (struct sockaddr *)&client, &cliLen);
      if(socket_descriptor<0) {
	perror("Cannot accept new connection.");
	return(0);
      }
#ifdef DEBUG
      printf("TCP unicast\nIP.destination=%s port=%d\n", address,port);
      printf("Client: %s  %d\n",inet_ntoa(client.sin_addr), ntohs(client.sin_port));
#endif
      myStream->address=(char*)calloc(strlen(address)+1,1);
      strcpy(myStream->address,address);
      break;

    case 2: // UDP multi/unicast
      socket_descriptor=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
      if(socket_descriptor<0) {
	perror("Cannot open socket. ");
	return(0);
      }     
      setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int));
      setsockopt(socket_descriptor,SOL_SOCKET,SO_BROADCAST,(void*)1,sizeof(int));
      sender.sin_family = AF_INET;
      inet_aton(address,&sender.sin_addr);
      sender.sin_port = htons(port);
#ifdef DEBUG
      printf("Listens to %s:%d\n",inet_ntoa(sender.sin_addr),ntohs(sender.sin_port));
#endif
      if( bind (socket_descriptor, (struct sockaddr *) &sender,sizeof(sender))<0){
	perror("Cannot bind port number \n");
	return(0);
      }
#ifdef DEBUG
      printf("UDP Multi/uni-cast\nIP.destination=%s UDP.port=%d\n", address,port);
#endif
      myStream->address=(char*)calloc(strlen(address)+1,1);
      strcpy(myStream->address,address);
      if(ioctl(socket_descriptor, SIOCGIFINDEX, &ifr) == -1 ){
	perror("SIOCGIFINDEX error. ");
	return(0);
      }
      ifindex=ifr.ifr_ifindex;
      if(ioctl(socket_descriptor,SIOCGIFMTU,&ifr) == -1 ) {
	perror("SIOCGIIFMTU");
	exit(1);
      }
      myStream->if_mtu=ifr.ifr_mtu;

      break;

    case 1: // Ethernet multicast
      socket_descriptor=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//LLPROTO));
      if(socket_descriptor<0) {
	perror("Cannot open socket. ");
	return(0);
      }
      if(ioctl(socket_descriptor, SIOCGIFINDEX, &ifr) == -1 ){
	perror("SIOCGIFINDEX error. ");
	return(0);
      }
      ifindex=ifr.ifr_ifindex;
      if(ioctl(socket_descriptor,SIOCGIFMTU,&ifr) == -1 ) {
	perror("SIOCGIIFMTU");
	exit(1);
      }
      myStream->if_mtu=ifr.ifr_mtu;

      myaddress=(char*)calloc(strlen(address)+1,1);
      eth_aton(myaddress, address);
      struct packet_mreq mcast;
      mcast.mr_ifindex = ifindex;
      mcast.mr_type = PACKET_MR_MULTICAST;
      mcast.mr_alen = ETH_ALEN;
      memcpy(mcast.mr_address, myaddress, ETH_ALEN);
      if(setsockopt(socket_descriptor, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mcast,sizeof(mcast))==-1){
	perror("Adding multicast address failed..");
	free(myaddress);
	return(0);
      }
      struct sockaddr_ll sll;
      sll.sll_family=AF_PACKET;
      sll.sll_ifindex=ifindex;
      sll.sll_protocol=htons(ETH_P_ALL);//LLPROTO);
      sll.sll_pkttype=PACKET_MULTICAST;
      memcpy(sll.sll_addr,myaddress,ETH_ALEN);
      if (bind(socket_descriptor, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
	perror("Binding to interface.");
	free(myaddress);
	return(0);
      }
#ifdef DEBUG
      printf("Ethernet Multicast\nEthernet.type=%04X\nEthernet.dst=%02X:%02X:%02X:%02X:%02X:%02X\nInterface=%s (%d)\n", LLPROTO
	     ,mcast.mr_address[0], mcast.mr_address[1], mcast.mr_address[2]
	     ,mcast.mr_address[3], mcast.mr_address[4], mcast.mr_address[5]
	     ,nic, ifindex);
#endif
      myStream->address=(char*)calloc(strlen(myaddress),1);
      memcpy(myStream->address,myaddress,ETH_ALEN);
      myStream->FH.comment_size=0;
      myStream->comment=0;
      


      break;
    case 0:
    default:
      /* initialize a file stream */
      if ( (ret=stream_file_init(myStream, address)) != 0 ){
	fprintf(stderr, "stream_file_init failed with code %d: %s\n", ret, strerror(ret));
	return 0;
      }
      
      struct file_header *fhptr;
      fhptr=&(myStream->FH);
      i=fread(fhptr, 1, sizeof(struct file_header), myStream->myFile);
#ifdef DEBUG
      printf("Read File Header %d bytes <-> %d\n",i, sizeof(struct file_header));
#endif
      myStream->comment=(char*)calloc(fhptr->comment_size+1,1);
      i=fread(myStream->comment, 1, fhptr->comment_size, myStream->myFile);
#ifdef DEBUG
      printf("Read comment  %d bytes\nFile pointer peeks to %ld",i, ftell(myStream->myFile));
#endif

      if ( !is_valid_version(fhptr) ){ /* is_valid_version has side-effects */
	return(0);
      }

      myStream->filename = strdup(address);
      break;
  } 


  free(myaddress);
  myStream->mySocket=socket_descriptor;
  myStream->ifindex=ifindex;

#ifdef DEBUG
  printf("sizeof(cap_head) = %d\n",sizeof(cap_head));
  printf("sizeof(ethhead)  = %d\n",sizeof(struct ethhdr));
  printf("sizeof(sendhead) = %d\n",sizeof(struct sendhead));
  printf("OPENSTREAM.Initial read.\n");
#endif

  switch(myStream->type){
    case 3://TCP
      myStream->bufferSize=0;
      bzero(osrBuffer,buffLen);
      myStream->pktCount=0;
#ifdef DEBUG      
      printf("osrBuffer = %p, \n",&osrBuffer);
#endif
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
      myStream->pktCount=0;
      myStream->expSeqnr=0;
      myStream->FH.version.major=ntohs(sh->version.major);
      myStream->FH.version.minor=ntohs(sh->version.minor);
      if(myStream->FH.version.major != VERSION_MAJOR || myStream->FH.version.minor != VERSION_MINOR){
	fprintf(stderr,"Stream uses version %d.%d, this application uses version %d.%d.\n",myStream->FH.version.major, myStream->FH.version.minor, VERSION_MAJOR, VERSION_MAJOR);
	fprintf(stderr,"I will not process this stream, change the version on Libcap_utils.\n");
	return(0);
      }
#ifdef DEBUG
      printf("Read %d bytes, Got the sendhead.\n",readBytes);
#endif
      // Now we read some packets.
      bzero(osrBuffer,buffLen);
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
      myStream->readPos=0;
      break;

    case 2://UDP
      myStream->bufferSize=0;
      bzero(osrBuffer,buffLen);
      myStream->pktCount=0;
      
#ifdef DEBUG      
      printf("osrBuffer = %p, \n",&osrBuffer);
#endif
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
	  if(myStream->FH.version.major != VERSION_MAJOR || myStream->FH.version.minor != VERSION_MINOR){
	    fprintf(stderr,"Stream uses version %d.%d, this application uses version %d.%d.\n",myStream->FH.version.major, myStream->FH.version.minor, VERSION_MAJOR, VERSION_MAJOR);
	    fprintf(stderr,"I will not process this stream, change the version on Libcap_utils.\n");
	    return(0);
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
      myStream->readPos=0;

     break;
    case 1://ETHERNET
      myStream->bufferSize=0;
      bzero(osrBuffer,buffLen);
      myStream->pktCount=0;

#ifdef DEBUG      
      printf("osrBuffer = %p, \n",&osrBuffer);
#endif
      while(myStream->bufferSize==0){ // Read one chunk of data, mostly to determine sequence number and stream version. 
#ifdef DEBUG
	printf("ETH read from %d, to %p max %d bytes, from socket %p\n",myStream->mySocket, myStream->buffer, buffLen);
#endif
	readBytes=recvfrom(myStream->mySocket, osrBuffer, buffLen, 0, NULL, NULL);
#ifdef DEBUG
	printf("eth.type=%04x %02X:%02X:%02X:%02X:%02X:%02X --> %02X:%02X:%02X:%02X:%02X:%02X",ntohs(eh->h_proto),eh->h_source[0],eh->h_source[1],eh->h_source[2],eh->h_source[3],eh->h_source[4],eh->h_source[5],eh->h_dest[0],eh->h_dest[1],eh->h_dest[2],eh->h_dest[3],eh->h_dest[4],eh->h_dest[5]);
	printf("myStream->address = %02x:%02x:%02x:%02x:%02x:%02x \n",myStream->address[0],myStream->address[1],myStream->address[2],myStream->address[3],myStream->address[4],myStream->address[5]);
#endif
	
	if(readBytes<0){
	  perror("Cannot receive Ethernet data.");
	  return(0);
	}
	if(readBytes==0){
	  perror("Connection closed by client.");
	  return(0);
	}
	if(ntohs(eh->h_proto) == LLPROTO && memcmp((const void*)eh->h_dest,(const void*)myStream->address, ETH_ALEN)==0){
	  myStream->pktCount+=ntohs(sh->nopkts);
	  if(myStream->bufferSize==0) {
	    myStream->expSeqnr=ntohl(sh->sequencenr)+1;
	    myStream->FH.version.major=ntohs(sh->version.major);
	    myStream->FH.version.minor=ntohs(sh->version.minor);
	    if(myStream->FH.version.major != VERSION_MAJOR || myStream->FH.version.minor != VERSION_MINOR){
	      fprintf(stderr,"Stream uses version %d.%d, this application uses version %d.%d.\n",myStream->FH.version.major, myStream->FH.version.minor, VERSION_MAJOR, VERSION_MAJOR);
	      fprintf(stderr,"I will not process this stream, change the version on Libcap_utils.\n");
	      return(0);
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
	  memcpy(myStream->buffer+myStream->bufferSize, osrBuffer+sizeof(struct ethhdr)+sizeof(struct sendhead), readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
	  myStream->bufferSize+=(readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
#ifdef DEBUG
	  printf("Packet contained %d bytes (Eth %d, Send %d, Cap %d) Buffer Size = %d / %d  Pkts %ld \n",readBytes,sizeof(struct ethhdr), sizeof(struct sendhead),sizeof(struct cap_header),myStream->bufferSize, buffLen, myStream->pktCount);
#endif
	  if(ntohs(sh->flush)==1){// This indicates a flush from the sender..
	    printf("Sender terminated. \n");
	    myStream->flushed=1;
	    break;//Break the while loop.
	  }
	} else {
//	      printf("Not my address, %d bytes.\n", readBytes);
	}
      }
      myStream->readPos=0;

      break;
    case 0:
    default:
      myStream->fill_buffer(myStream);
      break;
  }
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
