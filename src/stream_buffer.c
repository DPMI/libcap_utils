#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_buffer.h"
#include "stream.h"
#include "caputils/filter.h"
#include <errno.h>

size_t stream_frame_buffer_size(size_t num_frames, size_t mtu){
	return num_frames * mtu + sizeof(char*) * num_frames;
}

void stream_frame_init(struct stream_frame_buffer* fb, read_frame_callback cb, char* src, size_t num_frames, size_t mtu){
	const size_t frame_offset = sizeof(char*) * num_frames;

	fb->read_frame = cb;
	fb->frame = (char**)src;
	fb->num_frames = num_frames;
	fb->num_packets = 0;
	fb->header_offset = 0;

	/* setup buffer pointers (see brief overview at struct declaration) */
	fb->read_ptr = NULL;
	for ( unsigned int i = 0; i < num_frames; i++ ){
		fb->frame[i] = src + frame_offset + i * mtu;
	}
}

static int read_frame(stream_t st, struct stream_frame_buffer* fb, struct timeval* timeout){
	if ( !fb->read_frame(st, fb->frame[st->writePos], timeout) ){
		return 0;
	}

	/* increment write position */
	st->writePos = (st->writePos+1) % fb->num_frames;
	return 1;
}

int stream_frame_buffer_read(stream_t st, struct stream_frame_buffer* fb, struct cap_header** header, struct filter* filter, struct timeval* timeout){
	/* I heard ext is a pretty cool guy, uses goto and doesn't afraid of anything */
	retry:

	/* empty buffer */
	if ( !fb->read_ptr ){
		if ( !read_frame(st, fb, timeout) ){
			return EAGAIN;
		}

		char* frame = fb->frame[st->readPos];
		struct sendhead* sh = (struct sendhead*)(frame + fb->header_offset);
		fb->read_ptr = frame + fb->header_offset + sizeof(struct sendhead);
		fb->num_packets = ntohl(sh->nopkts);
	}

	/* always read if there is space available */
	if ( st->writePos != st->readPos ){
		struct timeval tv = {0,0}; /* dont read with a timeout as we don't want to introduce delays here */
		read_frame(st, fb, &tv);
	}

	/* no packets available */
	if ( fb->num_packets == 0 ){
		fprintf(stderr, "stream_frame_buffer_read: st->num_packets is 0 but st->read_ptr is set\n");
		abort();
	}

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

	/* set next packet and advance the read pointer */
	*header = cp;
	st->stat.read++;
	st->stat.buffer_usage = 0;

	if ( filter && !filter_match(filter, cp->payload, cp) ){
		goto retry;
	}

	st->stat.matched++;
	return 0;
}
