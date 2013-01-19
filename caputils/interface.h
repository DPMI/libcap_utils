#ifndef INTERFACE_H
#define INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <net/if.h>
#include <net/ethernet.h>

struct iface {
	char if_name[IFNAMSIZ];             /* interface name (e.g. "eth0") */
	struct ether_addr if_hwaddr;        /* interface hardware adress */
	unsigned int if_index;              /* interface index */
	unsigned int if_mtu;                /* interface MTU */
	int if_up;                          /* non-zero if interface is up */
	int if_loopback;                    /* non-zero if interface is a loopback device */
	int if_multicast;                   /* non-zero if interface supports multicasting */
};

/**
 * Get properties for an interface.
 * @param name Interface name, e.g. "eth0"
 * @param iface Pointer to a iface structure which will be filled with data.
 * @return 0 on success or errno on failure.
 */
int iface_get(const char* name, struct iface* iface);

#ifdef __cplusplus
}
#endif

#endif /* INTERFACE_H */
