/***************************************************************************
                          readpost.c  -  description
                             -------------------
    begin                : Mnn Aug 1 2004
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
 This function reads a captured packet from the file and stores it in data.
  The function returns 1 until the file ends and a 0 is returned.
 ***************************************************************************/
#include "caputils/caputils.h"
#include <string.h>
#include <arpa/inet.h>

int read_post(struct stream *myStream, char **data, struct filter *my_Filter){
  char rBuffer[buffLen]; // Temporary buffer for holding ETHERNET/UDP packets, while filling buffer.

  struct sockaddr from;
  struct cap_header *cp;


  int readBytes=0;
  int filterStatus=0;
  int skip_counter=-1;

  char *ether=rBuffer;
  struct ethhdr *eh=(struct ethhdr *)ether;
  struct sendhead *sh=0;
  if(myStream->type==1)
    sh=(struct sendhead *)(rBuffer+sizeof(struct ethhdr));
  if(myStream->type==2 || myStream->type==3)
    sh=(struct sendhead *)ether;
  
  readBytes=0;
  filterStatus=0;
  skip_counter=-1;


  do{
    skip_counter++;
    if(myStream->bufferSize==0){// Initial or last read?
      printf("Initial read.\n");

      if( myStream->flushed==1 ){
	printf("EOF stream reached.\n");
	return(0);
      }

      switch(myStream->type){
	case PROTOCOL_TCP_UNICAST://TCP
	  myStream->bufferSize=0;
	  bzero(rBuffer,buffLen);
	  myStream->pktCount=0;
	  
	  while(myStream->bufferSize<7410){ // This equals approx 5 packets each of 
//	    printf("ETH read from %d, to %p max %d bytes, from socket %p\n",myStream->mySocket, myStream->buffer, buffLen,&from);
	    readBytes=recvfrom(myStream->mySocket, myStream->buffer, buffLen, 0, &from, (socklen_t*)&from);

	    if(readBytes<0){
	      perror("Cannot receive Net stream data.");
	      return(0);
	    }
	    if(readBytes==0){
	      perror("Connection closed by client.");
	      myStream->flushed=1;
	      myStream->readPos=0;
	      break;
	    }

	    myStream->bufferSize+=readBytes;
//	    printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
//	      printf("sequenceNr = %04x\nmyStream->readPos=%d\n",ntohs(sh->sequencenr),myStream->readPos);
	    if(ntohs(sh->flush)==1){
	      printf("Indicataion of termination from sender.. %d/%d\n", readBytes, myStream->if_mtu);
	      myStream->flushed=1;
	      break;//Break the while loop.
	    }
	  }
	  myStream->readPos=0;
	  printf("Initial read complete.\n");

	  break;
	case PROTOCOL_UDP_MULTICAST://UDP
	  myStream->bufferSize=0;
	  bzero(rBuffer,buffLen);
	  myStream->pktCount=0;
	  
	  
	  while(myStream->bufferSize<7410){ // This equals approx 5 packets each of 
//	    printf("ETH read from %d, to %p max %d bytes, from socket %p\n",myStream->mySocket, myStream->buffer, buffLen,&from);
	    readBytes=recvfrom(myStream->mySocket, rBuffer, buffLen, 0, &from, (socklen_t*)&from);

	    if(readBytes<0){
	      perror("Cannot receive Net stream data.");
	      return(0);
	    }
	    if(readBytes==0){
	      perror("Connection closed by client.");
	      return(0);
	    }
	    myStream->pktCount+=ntohs(sh->nopkts);
	    if(myStream->bufferSize==0) {
	      myStream->expSeqnr=ntohl(sh->sequencenr)+1;
	      myStream->FH.version.minor=ntohs(sh->version.minor);
	      myStream->FH.version.major=ntohs(sh->version.major);
	    } else {
	      if(myStream->expSeqnr!=ntohl(sh->sequencenr)){
		printf("Missmatch of sequence numbers. Expeced %ld got %d\n",myStream->expSeqnr, ntohl(sh->sequencenr));
		myStream->expSeqnr=ntohl(sh->sequencenr);
	      } 
	      myStream->expSeqnr++;
	      if(myStream->expSeqnr>=0xFFFF){
		myStream->expSeqnr=0;
	      }
	      
	    }
	    memcpy(myStream->buffer+myStream->bufferSize, rBuffer+sizeof(struct sendhead), readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
	    myStream->bufferSize+=(readBytes-sizeof(struct sendhead));
//	    printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
//	      printf("sequenceNr = %04x\nmyStream->readPos=%d\n",ntohs(sh->sequencenr),myStream->readPos);
	    if(ntohs(sh->flush)==1){
	      printf("Indicataion of termination from sender.. %d/%d\n", readBytes, myStream->if_mtu);
	      myStream->flushed=1;
	      break;//Break the while loop.
	    }
	  }
	  myStream->readPos=0;
	  printf("Initial read complete.\n");
	  break;
	case PROTOCOL_ETHERNET_MULTICAST://ETHERNET
	case PROTOCOL_LOCAL_FILE:
	  if ( myStream->fill_buffer(myStream, buffLen) < 0 ){
	    fprintf(stderr, "Failed to read from stream: %s", strerror(errno));
	    return 0;
	  }
	  break;
      }
    } else {
      // We have some data in the buffer.
      cp=(struct cap_header*)(myStream->buffer+myStream->readPos);
//      printf("readPos = %d \t cp->nic: %s, cp->caplen: %d,  cp->len: %d\n", myStream->readPos, cp->nic, cp->caplen, cp->len);
      if( (cp->caplen+myStream->readPos+sizeof(struct cap_header))<=myStream->bufferSize ) {
	// And we can simply move the pointer forward.
	myStream->readPos+=(cp->caplen+sizeof(struct cap_header));
	cp=(struct cap_header*)(myStream->buffer+myStream->readPos);
//	printf("MtNPt. Next packet is  %d bytes long.\n", cp->caplen);
//	printf("bufferSize = %d, readPos = %d \n", myStream->bufferSize, myStream->readPos);
	if( (cp->caplen+myStream->readPos+sizeof(struct cap_header))>myStream->bufferSize) {
	  // If we read this packet we can potentially endup out side the buffer!!!
//	  printf("\nPacket incomplete.\t");
	  int amount=(myStream->bufferSize)-(myStream->readPos);
//	  printf("Moving %d bytes from %p -> %p \t", amount, myStream->buffer+myStream->readPos, myStream->buffer); 
	  memmove(myStream->buffer,myStream->buffer+myStream->readPos, amount);
	  bzero(myStream->buffer+amount,buffLen-amount);
	  switch(myStream->type){
	    case 3://TCP
	      if(myStream->flushed==1){
		printf("EOF stream reached.\n");
		return(0);
	      }
	      myStream->bufferSize=amount;
	      bzero(rBuffer,buffLen);
	      myStream->pktCount=0;
//	      printf("Normal read, data present %d\n",amount);
//	      printf("rBuffer = %p, from = %p \n",&rBuffer, &from);
	      while(myStream->bufferSize<7410){
		readBytes=recvfrom(myStream->mySocket, myStream->buffer+myStream->bufferSize, buffLen-myStream->bufferSize, 0,&from, (socklen_t*)&from);
		if(readBytes<0){
		  perror("Cannot receive tcp data.");
		  return(0);
		}
		if(readBytes==0){
		  perror("Connection closed by client.");
		  myStream->flushed=1;
		  myStream->readPos=0;
		  myStream->bufferSize+=(readBytes);
		  break;
		}

		myStream->bufferSize+=(readBytes);
//		printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
	      }
	      myStream->readPos=0;

	      break;
	    case 2://UDP
	      if(myStream->flushed==1){
		printf("EOF stream reached.\n");
		return(0);
	      }
	      myStream->bufferSize=amount;
	      bzero(rBuffer,buffLen);
	      myStream->pktCount=0;
	      printf("Normal read, data present %d\n",amount);
	      printf("rBuffer = %p, from = %p \n",&rBuffer, &from);
	      while(myStream->bufferSize<7410){
		readBytes=recvfrom(myStream->mySocket, rBuffer, buffLen, 0,&from, (socklen_t*)&from);
		if(readBytes<0){
		  perror("Cannot receive Ethernet data.");
		  return(0);
		}
		if(readBytes==0){
		  perror("Connection closed by client.");
		  return(0);
		}

		myStream->pktCount+=ntohs(sh->nopkts);
		if(myStream->expSeqnr!=ntohl(sh->sequencenr)){
		  printf("Missmatch of sequence numbers. Expeced %ld got %d\n",myStream->expSeqnr, ntohl(sh->sequencenr));
		  myStream->expSeqnr=ntohl(sh->sequencenr);
		}
		myStream->expSeqnr++;
		if(myStream->expSeqnr>=0xFFFF){
		  myStream->expSeqnr=0;
		}
		memcpy(myStream->buffer+myStream->bufferSize, rBuffer+sizeof(struct sendhead), readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
		myStream->bufferSize+=(readBytes-sizeof(struct sendhead));
//		printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
		if(ntohs(sh->flush)==1){
		  printf("Indicataion of termination from sender.. %d/%d\n", readBytes, myStream->if_mtu);
		  myStream->flushed=1;
		  break;//Break the while loop.
		}
	      }
	      myStream->readPos=0;

	      break;
	    case 1://ETHERNET
	      if(myStream->flushed==1){
		printf("EOF stream reached.\n");
		return(0);
	      }
	      myStream->bufferSize=amount;
	      myStream->pktCount=0;
	      bzero(rBuffer,buffLen);
//	      printf("Normal read, data present %d\n",amount);
//	      printf("rBuffer = %p, from = %p \n",&rBuffer, &from);
	      while(myStream->bufferSize<7410){
		readBytes=recvfrom(myStream->mySocket, rBuffer, buffLen, 0,NULL, NULL);
//		printf("eth.type=%04x %02X:%02X:%02X:%02X:%02X:%02X --> %02X:%02X:%02X:%02X:%02X:%02X",ntohs(eh->h_proto),eh->h_source[0],eh->h_source[1],eh->h_source[2],eh->h_source[3],eh->h_source[4],eh->h_source[5],eh->h_dest[0],eh->h_dest[1],eh->h_dest[2],eh->h_dest[3],eh->h_dest[4],eh->h_dest[5]);
//		printf("rBuffer = %p --> %d, from = %p eh = %p \n",&rBuffer, readBytes,&from,eh);
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
		  if(myStream->expSeqnr!=ntohl(sh->sequencenr)){
		    printf("Missmatch of sequence numbers. Expeced %ld got %d\n",myStream->expSeqnr, ntohl(sh->sequencenr));
		    myStream->expSeqnr=ntohl(sh->sequencenr);
		  }
		  myStream->expSeqnr++;
		  if(myStream->expSeqnr>=0xFFFF){
		    myStream->expSeqnr=0;
		  }
		  memcpy(myStream->buffer+myStream->bufferSize, rBuffer+sizeof(struct ethhdr)+sizeof(struct sendhead), readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
		  myStream->bufferSize+=(readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
//		  printf("Buffer Size = %d / %d Packet contained %d packets\n",myStream->bufferSize, buffLen,ntohs(sh->nopkts));
		  if(ntohs(sh->flush)==1){
		    printf("Indicataion of termination from sender.. %d/%d\n", readBytes, myStream->if_mtu);
		    myStream->flushed=1;
		    break;//Break the while loop.
		  }
		} else {
//		  printf("Not my address, %d bytes.\n", readBytes);
		}
	      }
	      myStream->readPos=0;
	      break;
	    case 0:
	    default:
	      readBytes=fread((myStream->buffer+amount), 1, buffLen-amount, myStream->myFile);
	      myStream->bufferSize=amount+readBytes;
	      myStream->readPos=0;
	      break;
	  }
//	  printf("Read op filled: %p --- %d(Max:%d) --- %p \n", myStream->buffer+amount, myStream->bufferSize, buffLen-amount, myStream->buffer+amount+readBytes);

	  if( myStream->bufferSize<(buffLen-amount)){
	    switch(myStream->type){
	      case 3:
	      case 2:
	      case 1:
		break;
	      case 0:
	      default:
		if(ferror(myStream->myFile)>0){
		  perror("ERROR:Reading file.\n");
		  return(0); // Some error occured.
		}
		break;
	    }
	  }
	  
	  if(myStream->bufferSize==0) {
	    switch(myStream->type){
	      case 3:
	      case 2:
	      case 1:
		break;
	      case 0:
	      default:
		if(feof(myStream->myFile)){
		  //printf("ERROR: 1EOF reached\n");
		  return(0);// End-of-file reached.
		}
		break;
	    }
	  }
	  myStream->readPos=0;	 
	}
      } else { 
	printf("\nInsufficient data\t");
	// We have data, but not enough. We need to move the existing data to the front and fill up with new.
	int amount=(myStream->bufferSize)-(myStream->readPos+sizeof(struct cap_header)+cp->caplen);
	// Move the data
	printf("No need to move data, since ETH/UDP are 'messages', containing complete packets. amount = %d\n", amount);
	bzero(myStream->buffer,buffLen);
	memmove(myStream->buffer,myStream->buffer+myStream->readPos, amount);
	switch(myStream->type){
	  case 3:
	      if(myStream->flushed==1){
		printf("EOF stream reached.\n");
		return(0);
	      }
	      myStream->bufferSize=amount;
	      bzero(rBuffer,buffLen);
	      myStream->pktCount=0;
//	      printf("Normal read, data present %d\n",amount);
//	      printf("rBuffer = %p, from = %p \n",&rBuffer, &from);
	      while(myStream->bufferSize<7410){
		readBytes=recvfrom(myStream->mySocket, 
				   myStream->buffer+myStream->bufferSize, 
				   buffLen-myStream->bufferSize, 0,&from, (socklen_t*)&from);
		if(readBytes<0){
		  perror("Cannot receive tcp data.");
		  return(0);
		}
		if(readBytes==0){
		  perror("Connection closed by client.");
		  myStream->flushed=1;
		  myStream->readPos=0;
		  myStream->bufferSize+=(readBytes);
		  break;
		}
		myStream->bufferSize+=(readBytes);
//		printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
	      }
	      myStream->readPos=0;

	    break;

	  case 2:
	    if(myStream->flushed==1){
	      printf("EOF stream reached.\n");
	      return(0);
	    }
	    myStream->bufferSize=amount;
	    myStream->pktCount=0;
	    amount=0;
	    printf("Secondary read, incomplete packet.\n");
	    while(myStream->bufferSize<7410){
	      readBytes=recvfrom(myStream->mySocket, rBuffer, buffLen, 0,&from, (socklen_t*)&from);
	      if(readBytes<0){
		perror("Cannot receive Ethernet data.");
		return(0);
	      }
	      if(readBytes==0){
		perror("Connection closed by client.");
		return(0);
	      }
	      myStream->pktCount+=ntohs(sh->nopkts);
	      if(myStream->expSeqnr!=ntohl(sh->sequencenr)){
		printf("Missmatch of sequence numbers. Expeced %ld got %d\n",myStream->expSeqnr, ntohl(sh->sequencenr));
		myStream->expSeqnr=ntohl(sh->sequencenr);
	      }
	      myStream->expSeqnr++;
	      if(myStream->expSeqnr>=0xFFFF){
		myStream->expSeqnr=0;
	      }
	      memcpy(myStream->buffer+myStream->bufferSize, rBuffer+sizeof(struct sendhead), readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
	      myStream->bufferSize+=(readBytes-sizeof(struct sendhead));
//	      printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
	      if(ntohs(sh->flush)==1){
		printf("Indicataion of termination from sender.. %d/%d\n", readBytes, myStream->if_mtu);
		myStream->flushed=1;
		break;//Break the while loop.
	      }
	    }
	    myStream->readPos=0;
	    break;
	  case 1:
	    if(myStream->flushed==1){
	      return(0);
	    }
	    myStream->bufferSize=amount;
	    myStream->pktCount=0;
	    amount=0;
//	    printf("Secondary read, incomplete packet.\n");
	    while(myStream->bufferSize<7410){
	      readBytes=recvfrom(myStream->mySocket, rBuffer, buffLen, 0,NULL, NULL);
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
		if(myStream->expSeqnr!=ntohl(sh->sequencenr)){
		  printf("Missmatch of sequence numbers. Expeced %ld got %d\n",myStream->expSeqnr, ntohl(sh->sequencenr));
		  myStream->expSeqnr=ntohl(sh->sequencenr);
		}
		myStream->expSeqnr++;
		if(myStream->expSeqnr>=0xFFFF){
		  myStream->expSeqnr=0;
		}
		memcpy(myStream->buffer+myStream->bufferSize, rBuffer+sizeof(struct ethhdr)+sizeof(struct sendhead), readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
		myStream->bufferSize+=(readBytes-sizeof(struct ethhdr)-sizeof(struct sendhead));
//		printf("Buffer Size = %d / %d \n",myStream->bufferSize, buffLen);
		if(ntohs(sh->flush)==1){
		  printf("Indicataion of termination from sender.. %d/%d\n", readBytes, myStream->if_mtu);
		  myStream->flushed=1;
		  break;//Break the while loop.
		}
	      } else {
//		printf("Not my address, %d bytes.\n", readBytes);
	      }
	    }
	    myStream->readPos=0;
	    break;
	  case 0:
	  default:	      
	    readBytes=fread((myStream->buffer+amount), 1, buffLen-amount, myStream->myFile);
	    myStream->bufferSize=amount+readBytes;
	    myStream->readPos=0;
	    break;
	}

//	printf("Read op filled: %p --- %d(Max:%d) --- %p \n", myStream->buffer+amount, myStream->bufferSize, buffLen-amount, myStream->buffer+amount+readBytes);
	if( (myStream->bufferSize)<buffLen){
	  switch(myStream->type){
	    case 3:
	    case 2:
	    case 1:
	      break;
	    case 0:
	    default:
	      if(ferror(myStream->myFile)>0){
		perror("ERROR:Reading file.\n");
		return(0); // Some error occured.
	      }
	      break;
	  }
	}
	
	if(myStream->bufferSize==0) {
	  switch(myStream->type){
	    case 3:
	    case 2:
	    case 1:
	      break;
	    case 0:
	    default:
	      if(feof(myStream->myFile)){
		//printf("ERROR: 1EOF reached\n");
		return(0);// End-of-file reached.
	      }
	      break;
	  }
	}
      }
    }
    *data=myStream->buffer+myStream->readPos;
    filterStatus=checkFilter((myStream->buffer+myStream->readPos),my_Filter);
//    printf("[%d]", skip_counter);
  }while(filterStatus==0);
//  printf("Skipped %d packets.\n",skip_counter);
  
  return(1);
}

