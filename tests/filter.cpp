#include "test.hpp"

#include <caputils/filter.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" {
int filter_vlan_tci(const struct filter* filter, const struct ether_vlan_header* vlan);
int filter_h_proto(const struct filter* filter, uint16_t h_proto);
int filter_eth_src(const struct filter* filter, const struct ethhdr* ether);
int filter_eth_dst(const struct filter* filter, const struct ethhdr* ether);
int filter_ip_proto(const struct filter* filter, const struct ip* ip);
int filter_ip_src(const struct filter* filter, const struct ip* ip);
int filter_ip_dst(const struct filter* filter, const struct ip* ip);
int filter_src_port(const struct filter* filter, uint16_t port);
int filter_dst_port(const struct filter* filter, uint16_t port);
int filter_port(const struct filter* filter, uint16_t src, uint16_t dst);
int filter_mampid(const struct filter* filter, char mampid[]);
int filter_start_time(const struct filter* filter, const timepico* time);
int filter_end_time(const struct filter* filter, const timepico* time);
int filter_frame_dt(const struct filter* filter, const timepico time);
}

class Test: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Test);
	CPPUNIT_TEST(test_tp_dport);
	CPPUNIT_TEST(test_tp_sport);
  CPPUNIT_TEST_SUITE_END();

	void test_tp_dport(){
		struct filter filter;
		filter_dst_port_set(&filter, 0x007b, 0x00ff);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff == 0x007b", 1, filter_dst_port(&filter, 0x007b));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff != 0x007c", 0, filter_dst_port(&filter, 0x007c));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff == 0x017b", 1, filter_dst_port(&filter, 0x017b));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff != 0x017c", 0, filter_dst_port(&filter, 0x017c));

		filter_dst_port_set(&filter, 0x027b, 0x00ff);	/* filter should mask input as well */
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x027b/0x00ff == 0x007b", 1, filter_dst_port(&filter, 0x007b));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x027b/0x00ff != 0x007c", 0, filter_dst_port(&filter, 0x007c));
	}

	void test_tp_sport(){
		struct filter filter;
		filter_src_port_set(&filter, 0x007b, 0x00ff);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff == 0x007b", 1, filter_src_port(&filter, 0x007b));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff != 0x007c", 0, filter_src_port(&filter, 0x007c));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff == 0x017b", 1, filter_src_port(&filter, 0x017b));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x007b/0x00ff != 0x017c", 0, filter_src_port(&filter, 0x017c));

		filter_src_port_set(&filter, 0x027b, 0x00ff);	/* filter should mask input as well */
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x027b/0x00ff == 0x007b", 1, filter_src_port(&filter, 0x007b));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("0x027b/0x00ff != 0x007c", 0, filter_src_port(&filter, 0x007c));
	}

};

CPPUNIT_TEST_SUITE_REGISTRATION(Test);
