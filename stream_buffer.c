#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_buffer.h"
#include "stream.h"

size_t stream_frame_buffer_size(size_t num_frames, size_t mtu){
	return num_frames * mtu + sizeof(char*) * num_frames;
}

void stream_frame_init(struct stream_frame_buffer* fb, char* src, size_t num_frames, size_t mtu){
  const size_t frame_offset = sizeof(char*) * num_frames;

  fb->frame = (char**)src;
  fb->num_frames = num_frames;
  fb->num_packets = 0;

  /* setup buffer pointers (see brief overview at struct declaration) */
  fb->read_ptr = NULL;
  for ( unsigned int i = 0; i < num_frames; i++ ){
	  fb->frame[i] = src + frame_offset + i * mtu;
  }

}

struct cap_header* stream_frame_buffer_read(stream_t st, struct stream_frame_buffer* fb){
	/* find next packet */
	struct cap_header* cp = (struct cap_header*)(fb->read_ptr);
	const size_t packet_size = sizeof(struct cap_header) + cp->caplen;
	fb->num_packets--;
	fb->read_ptr += packet_size;

	/* move to next frame if needed */
	if ( fb->num_packets == 0 ){
		st->readPos = (st->readPos+1) % fb->num_frames;
		if ( st->readPos == st->writePos ){
			fb->read_ptr = NULL;
		} else {
			char* frame = fb->frame[st->readPos];
			struct sendhead* sh = (struct sendhead*)(frame + fb->header_offset);
			fb->read_ptr = frame + fb->header_offset + sizeof(struct sendhead);
			fb->num_packets = ntohl(sh->nopkts);
		}
	}

	return cp;
}
