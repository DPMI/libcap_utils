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
int filter_mampid(const struct filter* filter, const char mampid[]);
int filter_start_time(const struct filter* filter, const timepico* time);
int filter_end_time(const struct filter* filter, const timepico* time);
int filter_frame_dt(const struct filter* filter, const timepico time);
}

class Test: public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(Test);
	CPPUNIT_TEST(test_eth_type);
	CPPUNIT_TEST(test_eth_src);
	CPPUNIT_TEST(test_eth_dst);
	CPPUNIT_TEST(test_ip_proto);
	CPPUNIT_TEST(test_ip_src);
	CPPUNIT_TEST(test_ip_dst);
	CPPUNIT_TEST(test_tp_dport);
	CPPUNIT_TEST(test_tp_sport);
	CPPUNIT_TEST(test_tp_port);
	CPPUNIT_TEST(test_mampid);
	CPPUNIT_TEST(test_start_time);
	CPPUNIT_TEST(test_end_time);
	CPPUNIT_TEST(test_frame_dt);
	CPPUNIT_TEST_SUITE_END();

	void test_eth_type(){
		struct filter filter;
		filter_eth_type_set(&filter, "ip");
		CPPUNIT_ASSERT_MESSAGE("[1] ip == ip",   filter_h_proto(&filter, ETHERTYPE_IP));
		CPPUNIT_ASSERT_MESSAGE("[1] ip != arp", !filter_h_proto(&filter, ETHERTYPE_ARP));
	}

	void test_eth_src(){
		static const char addr1[] = {1,0,0,0,0,1};
		static const char addr2[] = {1,0,0,0,0,2};
		static const char addr3[] = {1,0,0,0,1,1};
		struct filter filter;
		struct ethhdr eth;

		filter_eth_src_set(&filter, "01:00:00:00:00:01");
		memcpy(eth.h_source, addr1, sizeof(addr1)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 01::01 == 01::01", 1, filter_eth_src(&filter, &eth));
		memcpy(eth.h_source, addr2, sizeof(addr2)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 01::01 != 01::02", 0, filter_eth_src(&filter, &eth));

		filter_eth_src_set(&filter, "01:00:00:00:00:01/ff:ff:ff:ff:ff:00");
		memcpy(eth.h_source, addr1, sizeof(addr3)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 01::01/ff::00 == 01::00:01", 1, filter_eth_src(&filter, &eth));
		memcpy(eth.h_source, addr3, sizeof(addr3)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[4] 01::01/ff::00 != 01::01:01", 0, filter_eth_src(&filter, &eth));
	}

	void test_eth_dst(){
		static const char addr1[] = {1,0,0,0,0,1};
		static const char addr2[] = {1,0,0,0,0,2};
		static const char addr3[] = {1,0,0,0,1,1};
		struct filter filter;
		struct ethhdr eth;

		filter_eth_dst_set(&filter, "01:00:00:00:00:01");
		memcpy(eth.h_dest, addr1, sizeof(addr1)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 01::01 == 01::01", 1, filter_eth_dst(&filter, &eth));
		memcpy(eth.h_dest, addr2, sizeof(addr2)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 01::01 != 01::02", 0, filter_eth_dst(&filter, &eth));

		filter_eth_dst_set(&filter, "01:00:00:00:00:01/ff:ff:ff:ff:ff:00");
		memcpy(eth.h_dest, addr1, sizeof(addr3)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 01::01/ff::00 == 01::00:01", 1, filter_eth_dst(&filter, &eth));
		memcpy(eth.h_dest, addr3, sizeof(addr3)); CPPUNIT_ASSERT_EQUAL_MESSAGE("[4] 01::01/ff::00 != 01::01:01", 0, filter_eth_dst(&filter, &eth));
	}

	void test_ip_proto(){
		struct filter filter;
		struct ip ip;
		filter_ip_proto_aton(&filter, "tcp");
		ip.ip_p = 6; CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 6 == tcp", 1, filter_ip_proto(&filter, &ip));
		ip.ip_p = 7; CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 7 != tcp", 0, filter_ip_proto(&filter, &ip));
		filter_ip_proto_aton(&filter, "6");
		ip.ip_p = 6; CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 6 == 6", 1, filter_ip_proto(&filter, &ip));
		ip.ip_p = 7; CPPUNIT_ASSERT_EQUAL_MESSAGE("[4] 7 != 6", 0, filter_ip_proto(&filter, &ip));
	}

	void test_ip_src(){
		struct filter filter;
		struct ip ip;

		filter_src_ip_aton(&filter, "10.1.2.0/24");
		ip.ip_src.s_addr = inet_addr("10.1.2.3"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 10.1.2.0/24 == 10.1.2.3", 1, filter_ip_src(&filter, &ip));
		ip.ip_src.s_addr = inet_addr("10.1.2.4"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 10.1.2.0/24 == 10.1.2.4", 1, filter_ip_src(&filter, &ip));
		ip.ip_src.s_addr = inet_addr("10.1.3.3"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 10.1.2.0/24 == 10.1.3.3", 0, filter_ip_src(&filter, &ip));
		ip.ip_src.s_addr = inet_addr("10.1.3.4"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[4] 10.1.2.0/24 == 10.1.3.4", 0, filter_ip_src(&filter, &ip));

		filter_src_ip_aton(&filter, "10.1.2.3/24"); /* filter should mask input as well */
		ip.ip_src.s_addr = inet_addr("10.1.2.5"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[5] 10.1.2.3/24 == 10.1.2.5", 1, filter_ip_src(&filter, &ip));
	}

	void test_ip_dst(){
		struct filter filter;
		struct ip ip;

		filter_dst_ip_aton(&filter, "10.1.2.0/24");
		ip.ip_dst.s_addr = inet_addr("10.1.2.3"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 10.1.2.0/24 == 10.1.2.3", 1, filter_ip_dst(&filter, &ip));
		ip.ip_dst.s_addr = inet_addr("10.1.2.4"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 10.1.2.0/24 == 10.1.2.4", 1, filter_ip_dst(&filter, &ip));
		ip.ip_dst.s_addr = inet_addr("10.1.3.3"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 10.1.2.0/24 == 10.1.3.3", 0, filter_ip_dst(&filter, &ip));
		ip.ip_dst.s_addr = inet_addr("10.1.3.4"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[4] 10.1.2.0/24 == 10.1.3.4", 0, filter_ip_dst(&filter, &ip));

		filter_dst_ip_aton(&filter, "10.1.2.3/24"); /* filter should mask input as well */
		ip.ip_dst.s_addr = inet_addr("10.1.2.5"); CPPUNIT_ASSERT_EQUAL_MESSAGE("[5] 10.1.2.3/24 == 10.1.2.5", 1, filter_ip_dst(&filter, &ip));
	}

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

	void test_tp_port(){
		struct filter filter;
		for ( int i = 0; i < 2; i++ ){
			filter_tp_port_set(&filter, 0x007b, 0x00ff);
			CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 0x007b/0x00ff == 0x007b", 1, filter_port(&filter, 0x007b*i, 0x007b*(1-i)));
			CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 0x007b/0x00ff != 0x007c", 0, filter_port(&filter, 0x007c*i, 0x007c*(1-i)));
			CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 0x007b/0x00ff == 0x017b", 1, filter_port(&filter, 0x017b*i, 0x017b*(1-i)));
			CPPUNIT_ASSERT_EQUAL_MESSAGE("[4] 0x007b/0x00ff != 0x017c", 0, filter_port(&filter, 0x017c*i, 0x017c*(1-i)));

			filter_src_port_set(&filter, 0x027b, 0x00ff);	/* filter should mask input as well */
			CPPUNIT_ASSERT_EQUAL_MESSAGE("[5] 0x027b/0x00ff == 0x007b", 1, filter_port(&filter, 0x007b*i, 0x007b*(1-i)));
			CPPUNIT_ASSERT_EQUAL_MESSAGE("[6] 0x027b/0x00ff != 0x007c", 0, filter_port(&filter, 0x007c*i, 0x007c*(1-i)));
		}
	}

	void test_mampid(){
		struct filter filter;

		/* simple cases */
		filter_mampid_set(&filter, "foo");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] foo == foo", 1, filter_mampid(&filter, "foo"));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] bar != foo", 0, filter_mampid(&filter, "bar"));

		/* too long */
		filter_mampid_set(&filter, "foobarbaz");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] foobarbaz == foobarbazspam", 1, filter_mampid(&filter, "foobarbazspam"));
	}

	void test_start_time(){
		struct filter filter;
		timepico ts;

		timepico_from_string(&ts, "1.5");
		filter_starttime_set(&filter, ts);

		timepico_from_string(&ts, "1.5");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 1.5 >= 1.5", 1, filter_start_time(&filter, &ts));

		timepico_from_string(&ts, "1.6");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 1.6 >= 1.5", 1, filter_start_time(&filter, &ts));

		timepico_from_string(&ts, "1.4");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 1.4 >= 1.5", 0, filter_start_time(&filter, &ts));
	}

	void test_end_time(){
		struct filter filter;
		timepico ts;

		timepico_from_string(&ts, "1.5");
		filter_endtime_set(&filter, ts);

		timepico_from_string(&ts, "1.5");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] 1.5 < 1.5", 0, filter_end_time(&filter, &ts));

		timepico_from_string(&ts, "1.6");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] 1.6 < 1.5", 0, filter_end_time(&filter, &ts));

		timepico_from_string(&ts, "1.4");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] 1.4 < 1.5", 1, filter_end_time(&filter, &ts));
	}

	void test_frame_dt(){
		struct filter filter;
		filter.frame_last_ts.tv_sec = 0;
		filter.frame_last_ts.tv_psec = 0;
		timepico ts;

		timepico_from_string(&ts, "0.2");
		filter_frame_dt_set(&filter, ts);

		timepico_from_string(&ts, "0.1");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[1] dt >= 0.1 ", 1, filter_frame_dt(&filter, ts));

		timepico_from_string(&ts, "0.2");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[2] dt >= 0.2 ", 1, filter_frame_dt(&filter, ts));

		timepico_from_string(&ts, "0.3");
		CPPUNIT_ASSERT_EQUAL_MESSAGE("[3] dt >= 0.3 ", 0, filter_frame_dt(&filter, ts));
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(Test);
