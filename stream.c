#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include "caputils_int.h"
#include "stream.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

int stream_alloc(struct stream** stptr, enum protocol_t protocol, size_t size){
  assert(stptr);

  /* the buffer is always placed after the struct */
  struct stream* st = (struct stream*)malloc(size + buffLen);
  *stptr = st;

  st->type = protocol;
  st->comment = NULL;
  st->buffer = (char*)st + size; /* calculate pointer to buffer */

  st->expSeqnr = 0;
  st->pktCount = 0;
  st->bufferSize=0;
  st->readPos=0;
  st->flushed = 0;

  /* callbacks */
  st->fill_buffer = NULL;
  st->destroy = NULL;

  memset(st->buffer, 0, buffLen);

  /* initialize file_header */
  st->FH.comment_size = 0;
  memset(st->FH.mpid, 0, 200); /* @bug what is 200? why is not [0] = 0 enought? */

  return 0;
}

void match_inc_seqnr(struct stream* restrict st, const struct sendhead* restrict sh){
    /* validate sequence number */
    if( st->expSeqnr != ntohl(sh->sequencenr) ){
      fprintf(stderr,"Missmatch of sequence numbers. Expeced %ld got %d\n", st->expSeqnr, ntohl(sh->sequencenr));
      st->expSeqnr = ntohl(sh->sequencenr); /* reset sequence number */
    }

    /* increment sequence number (next packet is expected to have +1) */
    st->expSeqnr++;

    /* wrap sequence number */
    if( st->expSeqnr>=0xFFFF ){
      st->expSeqnr=0;
    }
}

void stream_get_version(const struct stream* st, struct file_version* dst){
  dst->major = st->FH.version.major;
  dst->minor = st->FH.version.minor;
}

const char* stream_get_comment(const struct stream* st){
  return st->comment;
}

const char* stream_get_mampid(const struct stream* st){
  return st->FH.mpid;
}

/**
 * Validates the file_header version against libcap_utils version. Prints
 * warning to stderr if version mismatch.
 * @return Non-zero if version is valid.
 */
int is_valid_version(struct file_header_t* fhptr){
  if( fhptr->version.major <= VERSION_MAJOR && fhptr->version.minor <= VERSION_MINOR ) {
    return 1;
  }

  fprintf(stderr,"Stream uses version %d.%d, this application uses ", fhptr->version.major, fhptr->version.minor);
  fprintf(stderr,"Libcap_utils version " VERSION "\n");
  fprintf(stderr,"Change libcap version or convert file.\n");
  return 0;
}

long stream_open(struct stream** stptr, const destination_t* dest, const char* nic, int port){
  switch(dest->type){
    /* case PROTOCOL_TCP_UNICAST: */
    /*   return stream_tcp_init(myStream, address, port); */

    /* case PROTOCOL_UDP_MULTICAST: */
    /*   return stream_udp_init(myStream, address, port); */

    case PROTOCOL_ETHERNET_MULTICAST:
      return stream_ethernet_open(stptr, &dest->ether_addr, nic);

    case PROTOCOL_LOCAL_FILE:
      return stream_file_open(stptr, (dest->flags & DEST_LOCAL) ? dest->local_filename : dest->filename);

    default:
      fprintf(stderr, "Unhandled protocol %d\n", dest->type);
      return ERROR_NOT_IMPLEMENTED;
  }
}

long stream_create(struct stream** stptr, const destination_t* dest, const char* nic, const char* mpid, const char* comment){
  /* struct ifreq ifr; */
  /* int ifindex=0; */
  /* int socket_descriptor=0; */
  /* int ret; */
  /* struct sockaddr_in destination; */
  /* struct ether_addr ethernet_address; */

  switch ( dest->type ){
  case PROTOCOL_ETHERNET_MULTICAST:
    return stream_ethernet_create(stptr, &dest->ether_addr, nic, mpid, comment);

  case PROTOCOL_LOCAL_FILE:
    return stream_file_create(stptr, NULL, (dest->flags & DEST_LOCAL) ? dest->local_filename : dest->filename, mpid, comment);

  default:
    return ERROR_NOT_IMPLEMENTED;
  }


  /* switch(protocol){ */
  /*   case 3: // TCP unicast */
  /*     socket_descriptor=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); */
  /*     if(socket_descriptor<0) { */
  /* 	perror("Cannot open socket. "); */
  /* 	return(0); */
  /*     }      */
  /*     setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int)); */
  /*     destination.sin_family = AF_INET; */
  /*     destination.sin_port = htons(LISTENPORT); */
  /*     inet_aton(address,&destination.sin_addr); */
  /*     if(connect(socket_descriptor,(struct sockaddr*)&(destination),sizeof(destination))!=0){ */
  /* 	perror("Cannot connect TCP socket."); */
  /* 	return(0); */
  /*     } */
  /*     printf("Connected."); */
  /*     address=(char*)calloc(strlen(address)+1,1); */
  /*     strcpy(st->address,address);  */

  /*     break; */

  /*   case 2: // UDP multi/unicast */
  /*     socket_descriptor=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); */
  /*     if(socket_descriptor<0) { */
  /* 	perror("Cannot open socket. "); */
  /* 	return(0); */
  /*     }      */
  /*     setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int)); */
  /*     setsockopt(socket_descriptor,SOL_SOCKET,SO_BROADCAST,(void*)1,sizeof(int)); */
  /*     destination.sin_family = AF_INET; */
  /*     inet_aton(address,&destination.sin_addr); */
  /*     destination.sin_port = htons(LISTENPORT); */
  /*     if(connect(socket_descriptor,(struct sockaddr*)&destination,sizeof(destination))!=0){ */
  /* 	perror("Cannot connect UDP socket."); */
  /* 	return(0); */
  /*     } */
  /*     address=(char*)calloc(strlen(address)+1,1); */
  /*     strcpy(st->address,address); */
  /*     break; */

  /*   case 1: // Ethernet multicast */
  /*   case 0: */
  /*   default: */
  /* }  */

  /* //  st->mySocket=socket_descriptor; */
  /* //  st->ifindex=ifindex; */
  
  /* return(1);   */
}

long stream_close(struct stream* st){
  return st->destroy ? st->destroy(st) : 0;

  /* ret */
  /* errno=0; */
  /* switch(myStream->type){ */
  /*   case 3://TCP */
  /*   case 2://UDP */
  /*   case 1://Ethernet */
  /*     if(close(myStream->mySocket)==-1){ */
  /* 	perror("Close failed."); */
  /* 	return(0); */
  /*     } */
  /*     break; */
  /*   case 0: */
  /*   default: */
  /*     if(fclose(myStream->myFile)==EOF){ */
  /* 	perror("Close failed."); */
  /* 	return(0); */
  /*     } */
  /*     break; */
  /* } */

  /* free(myStream->address); */
  /* free(myStream->comment); */
  /* free(myStream->filename); */

  /* return(1); */
}
