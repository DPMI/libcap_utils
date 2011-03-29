#ifndef CAPUTILS_PICOTIME_H
#define CAPUTILS_PICOTIME_H

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

//compares two struct timepico (ts1<ts2=-1, ts1>ts2=1, ts1==ts2=0)
int timecmp(const timepico *ts1, const timepico *ts2);

#endif /* CAPUTILS_PICOTIME_H */
