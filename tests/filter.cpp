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
	CPPUNIT_TEST(test_tp_dport);
	CPPUNIT_TEST(test_tp_sport);
	CPPUNIT_TEST(test_tp_port);
	CPPUNIT_TEST(test_mampid);
	CPPUNIT_TEST(test_start_time);
	CPPUNIT_TEST(test_end_time);
	CPPUNIT_TEST(test_frame_dt);
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
