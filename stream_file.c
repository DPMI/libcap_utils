#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "caputils/caputils.h"

/**
 * Fill buffer.
 * @return Number of bytes read, or <0 on errors.
 */
static int stream_file_fillbuffer(struct stream* st){
  assert(st);
  assert(st->myFile);

  int readBytes = fread(st->buffer, 1, buffLen, st->myFile);

  if ( readBytes > 0 ){
    st->bufferSize = readBytes;
    st->readPos = 0;
  }

  return readBytes;
}

/**
 * Initialize file stream.
 * @return Non-zero on error (see errno(3) for descriptions).
 */
int stream_file_init(struct stream* st, const char* filename){
  assert(st);

  /* validate that filename is set */
  if ( !filename ){
    return ENOENT;
  }

  /* try to open the file */
  st->myFile = fopen(filename, "rb");
  if( !st->myFile ){
    perror("open input failed");
    return errno;
  }

  struct file_header* fhptr = &(st->FH);
  int i;

  i = fread(fhptr, 1, sizeof(struct file_header), st->myFile);
  st->comment = (char*)malloc(fhptr->comment_size+1);
  i = fread(st->comment, 1, fhptr->comment_size, st->myFile);

  if ( !is_valid_version(fhptr) ){ /* is_valid_version has side-effects */
    return EINVAL;
  }

  /** @bug I think this memory leaks */
  st->filename = strdup(filename);
  
  /* add callbacks */
  st->fill_buffer = stream_file_fillbuffer;
  st->destroy = NULL;

  return 0;
}
