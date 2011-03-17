#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include "cap_utils.h"

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
  
  /* add callbacks */
  st->fill_buffer = stream_file_fillbuffer;
  st->destroy = NULL;

  return 0;
}
