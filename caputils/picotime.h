#ifndef CAPUTILS_PICOTIME_H
#define CAPUTILS_PICOTIME_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#define PICODIVIDER 1e12

#ifdef __cplusplus
extern "C" {
#endif

// Time struct for precision down to picoseconds
struct picotime {
    uint32_t tv_sec;
    uint64_t tv_psec;
} __attribute__((packed));

typedef struct picotime timepico;

//converts struct timeval to struct timepico (ms->ps)
timepico timeval_to_timepico(struct timeval);

//converts struct timespec to struct timepico (us->ps)
timepico timespec_to_timepico(struct timespec);

/**
 * Set timepico from string.
 * Return 0 on success.
 */
int timepico_from_string(timepico* dst, const char* str);

/**
 * Convert timepico to string (using strftime), psec ignored
 * @return dst or NULL if it fails.
 */
const char* timepico_to_string(const timepico* src, char* dst, size_t bytes, const char* fmt);

//compares two struct timepico (ts1<ts2=-1, ts1>ts2=1, ts1==ts2=0)
int timecmp(const timepico *ts1, const timepico *ts2);

/**
 * Calculate a - b.
 */
timepico timepico_sub(timepico a, timepico b);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_PICOTIME_H */
