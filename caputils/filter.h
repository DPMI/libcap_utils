#ifndef CAPUTILS_FILTER_H
#define CAPUTILS_FILTER_H

//Filter struct are base on binary indexing in filter.index
//Ex. to filter on source and destination adresses the index would look like:
// 1000 0000 0000 0000 0000 0000 0011 1100
// and the fields src_mask, dst_mask, src_ip and dst_ip contains the information
struct filter{
  uint32_t index;			//{2^31}
  
  timepico starttime;			//{4096}    st
  timepico endtime;			//{2048}    et
  char mampid[8];                       //{1024]    mpid
  char nic[8];        			//{512}     if
  uint16_t vlan;                       //{256}     eth.vlan
  uint16_t eth_type;  			//{128}     eth.type
  struct ether_addr eth_src;             //{64}      eth.src
  struct ether_addr eth_dst;             //{32}      eth.dst
  uint8_t ip_proto;  			//{16}      ip.proto
  char ip_src[16];    			//{8}       ip.src
  char ip_dst[16];    			//{4}       ip.dst
  uint16_t tp_sport; 			//{2}       tp.port
  uint16_t tp_dport; 			//{1}       tp.port
  
  uint16_t vlan_mask;                  //
  uint16_t eth_type_mask;              //
  struct ether_addr eth_src_mask;        //
  struct ether_addr eth_dst_mask;        //
  char ip_src_mask[16];			//
  char ip_dst_mask[16];			//
  uint16_t tp_sport_mask;              //
  uint16_t tp_dport_mask;              //
};

struct filter* createfilter(int argc, char** argv);
int closefilter(struct filter* filter);


#endif /* CAPUTILS_FILTER_H */
