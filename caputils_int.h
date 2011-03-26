#ifndef CAPUTILS_INT_H
#define CAPUTILS_INT_H

/**
 * Check if a frame matches filter.
 * @return Non-zero if frame matches filter.
 */
int checkFilter(const char* pkt, const struct filter* filter);

#endif /* CAPUTILS_INT_H */
