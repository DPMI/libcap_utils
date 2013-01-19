#ifndef STREAM_BUFFER_H
#define STREAM_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include "caputils/stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Stream frame buffer.
 * A specialized layout of the buffer memory is split into N regions each
 * storing one measurement frame (of MTU size). It keeps track of which regions
 * is free and which it is currently reading from and where within a frame it
 * is. Empty regions is filled as soon as possible.
 *
 * Memory layout:
 *                              +----------+
 *                              | Pointers |
 * +---------+------------------+----------+
 * | Headers |            Frame 1          |
 * +---------+-----------------------------+
 * ' Headers |              ...            '
 * +---------+-----------------------------+
 * | Headers |            Frame N          |
 * +---------+-----------------------------+
 * (headers is the ethernet- and send-header from MP)
 *
 * Usage:
 *  - Include "struct stream_frame_buffer" in your structure.
 *  - At the bottom add "char* frame[0]" which refers to the pointers at the
 *    beginning of the layout.
 *  - `stream_frame_buffer_init(..)`.
 *  - Use a custom `read_callback` which calls `stream_frame_buffer_read`.
 */

typedef int (*read_frame_callback)(stream_t st, char* dst, struct timeval* timeout);

struct stream_frame_buffer {
	read_frame_callback read_frame;  /* Read next frame */
	size_t num_frames;               /* How many frames that buffer can hold */
	size_t num_packets;              /* How many packets is left in current frame */
	size_t header_offset;            /* How many bytes of headers to skip to get to sendheader */
	char* read_ptr;                  /* Where inside a frame it currently is or NULL if a frame hasn't been processed yet */
	char** frame;                    /* Pointer to first frame */
};

/**
 * Calculate the buffer size required for holding N frames.
 * Pass this size to stream_alloc().
 */
size_t stream_frame_buffer_size(size_t num_frames, size_t mtu);

/**
 * Initialize buffer frame structure.
 * @param src Pointer to the start of the stream buffer.
 */
void stream_frame_init(struct stream_frame_buffer* buf, read_frame_callback cb, char* src, size_t num_frames, size_t mtu);

/**
 * Read the next packet from the buffer.
 */
int stream_frame_buffer_read(stream_t st, struct stream_frame_buffer* fb, struct cap_header** cp, struct filter* filter, struct timeval* timeout);

#ifdef __cplusplus
}
#endif

#endif /* STREAM_BUFFER_H */
