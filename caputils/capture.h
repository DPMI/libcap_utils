#ifndef CAPUTILS_CAPTURE_H
#define CAPUTILS_CAPTURE_H

#include <caputils/picotime.h>
#include <caputils/file.h>

#include <stdint.h>
#include <netinet/if_ether.h>

struct ether_vlan_header{
  uint8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
  uint8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
  uint16_t vlan_proto;             /* vlan is present if feild begins with 0x8100 */
  uint16_t vlan_tci;               /* vlan is present if feild begins with 0x8100 */
  uint16_t h_proto;                /* Ethernet payload protocol */
};

// Capture Header. This header is attached to each packet that we keep, i.e. it matched a filter.
//
//
struct cap_header {
  char nic[8];                          // Identifies the CI where the frame was caught
  char mampid[8];                       // Identifies the MP where the frame was caught,
  timepico ts;                          // Identifies when the frame was caught
  uint32_t len;                         // Identifies the lenght of the frame
  uint32_t caplen;                      // Identifies how much of the frame that we find here

  /* convenience accessor (since array size is 0 it won't affect sizeof) */
  union {
    char payload[0];
    struct ethhdr ethhdr[0];
    struct ether_vlan_header ethvlanhdr[0];
  };
};
typedef struct cap_header cap_head;
typedef struct cap_header* caphead_t;

// Send Structure, used infront of each send data packet. The sequence number is indicates the number
// of sent data packets. I.e. after a send packet this value is increased by one.
struct sendhead {
  uint32_t sequencenr;                  // Sequence number.
  uint32_t nopkts;                      // How many packets are here.
  uint32_t flush;                       // Indicate that this is the last packet.
  struct file_version version;          // What version of the file format is used for storing mp_pkts.
};

#endif /* CAPUTILS_CAPTURE_H */
