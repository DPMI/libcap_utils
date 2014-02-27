#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/filter.h>
#include <caputils/utils.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <list>

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

/* hack: all strings in here will be released before program terminates. getopt
 * look as the previous arg so they cannot be released in tearDown but they
 * should be released at some point to valgrind won't whine about it. (helps
 * when debugging actual memory-related errors in the code) */
static std::list<char*> strings;

extern "C" const char* hexdump_address_r(const struct ether_addr* address, char* buf);
void check_eth_addr(const struct ether_addr& a, const struct ether_addr& b, CppUnit::SourceLine sourceLine){
	for ( int i = 0; i < ETH_ALEN; i++ ){
		if ( a.ether_addr_octet[i] != b.ether_addr_octet[i] ){
			char expected[24], actual[24];
			CppUnit::Asserter::failNotEqual(hexdump_address_r(&a, expected), hexdump_address_r(&b, actual), sourceLine);
		}
	}
}

/**
 * Succeeds if ret=0 and argc == expected.
 *
 * @param ret return code from filter_from_argv.
 * @param expected arguments left after parsing.
 * @param actual arguments left after parsing.
 */
void check_success(int ret, int expected, int actual, CppUnit::SourceLine sourceLine){
	if ( ret != 0 ){
		CppUnit::Asserter::failNotEqual("(no error)", strerror(ret), sourceLine, "function did not return successfully");
		return;
	}
	CppUnit::assertEquals(expected, actual, sourceLine, "did not consume enough arguments");
}

/**
 * Same as check_success but ret!=0
 */
void check_failure(int ret, int expected, int actual, CppUnit::SourceLine sourceLine){
	if ( ret == 0 ){
		CppUnit::Asserter::failNotEqual("(no error)", strerror(ret), sourceLine, "function unexpectedly returned successfully");
		return;
	}
	CppUnit::assertEquals(expected, actual, sourceLine, "did not consume enough arguments");
}

void check_inet_addr(in_addr expected, in_addr actual, CppUnit::SourceLine sourceLine){
	if ( expected.s_addr != actual.s_addr ){
		char _expected[64];
		char _actual[64];
		strcpy(_expected, inet_ntoa(expected));
		strcpy(_actual, inet_ntoa(actual));
		CppUnit::Asserter::failNotEqual(_expected, _actual, sourceLine);
	}
}

#define CPPUNIT_ASSERT_ETH_ADDR(expected, actual) check_eth_addr(expected, actual, CPPUNIT_SOURCELINE())
#define CPPUNIT_ASSERT_INET_ADDR(expected, actual) check_inet_addr(expected, actual, CPPUNIT_SOURCELINE())
#define CPPUNIT_ASSERT_SUCCESS(expr, n) do { int r = (expr); check_success(r, n, argc, CPPUNIT_SOURCELINE()); } while (0)
#define CPPUNIT_ASSERT_FAILURE(expr, n) do { int r = (expr); check_failure(r, n, argc, CPPUNIT_SOURCELINE()); } while (0)

class FilterCreate : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(FilterCreate);
	CPPUNIT_TEST( test_empty         );
	CPPUNIT_TEST( test_basic         );
	CPPUNIT_TEST( test_invalid_input );
	CPPUNIT_TEST( test_starttime     );
	CPPUNIT_TEST( test_endtime       );
	CPPUNIT_TEST( test_mampid        );
	CPPUNIT_TEST( test_iface         );
	CPPUNIT_TEST( test_eth_vlan      );
	CPPUNIT_TEST( test_eth_type1     );
	CPPUNIT_TEST( test_eth_type2     );
	CPPUNIT_TEST( test_eth_type3     );
	CPPUNIT_TEST( test_eth_src       );
	CPPUNIT_TEST( test_eth_dst       );
	CPPUNIT_TEST( test_ip_proto      );
	CPPUNIT_TEST( test_ip_src        );
	CPPUNIT_TEST( test_ip_dst        );
	CPPUNIT_TEST( test_tp_sport      );
	CPPUNIT_TEST( test_tp_dport      );
	CPPUNIT_TEST( test_missing       );
	CPPUNIT_TEST( test_equal_sign    );
	CPPUNIT_TEST( test_shortname     );
	CPPUNIT_TEST( test_mode_and      );
	CPPUNIT_TEST( test_mode_or       );
	CPPUNIT_TEST( test_mode_invalid  );
	CPPUNIT_TEST( test_bpf_valid     );
	CPPUNIT_TEST( test_bpf_invalid   );
	CPPUNIT_TEST( test_ethertype1   );
	CPPUNIT_TEST( test_ethertype2   );
	CPPUNIT_TEST( test_ethertype3   );
	CPPUNIT_TEST( test_ethertype4   );
	CPPUNIT_TEST( test_frame_range   );
	CPPUNIT_TEST_SUITE_END();

	struct filter filter;
	char* argv[64];
	int argc;

public:

	void generate_argv(const char* name, ...){
		va_list ap;
		argc = 0;
		const char* arg;

		argv[argc++] = strdup(name);
		strings.push_back(argv[argc-1]);

		va_start(ap, name);
		do {
			arg = va_arg(ap, const char*);
			argv[argc++] = arg ? strdup(arg) : NULL;
			strings.push_back(argv[argc-1]);
		} while ( arg );

		/* -1 because it will fill the last one with NULL sentinel which shouldn't count */
		argc -= 1;
	}

	void tearDown(){
		filter_close(&filter);
	}

	void test_empty(){
		argc = 0;
		CPPUNIT_ASSERT( filter_from_argv(&argc, NULL, &filter) == 0 );
	}

	void test_invalid_input(){
		argc = 1;
		CPPUNIT_ASSERT( filter_from_argv(NULL, NULL, NULL) == EINVAL );
		CPPUNIT_ASSERT( filter_from_argv(&argc, NULL, NULL) == EINVAL );
		CPPUNIT_ASSERT( filter_from_argv(&argc, NULL, &filter) == EINVAL );
	}

	void test_basic(){
		const char* orig[] = {
			"programname",
			"--spam",
			"fred",
			"--ham",
			"barney",
			"bacon"
		};
		int argc = sizeof(orig) / sizeof(orig[0]);

		char* argv[argc];
		for ( int i = 0; i < argc; i++ ){
			argv[i] = strdup(orig[i]);
		}

		CPPUNIT_ASSERT_EQUAL(0, filter_from_argv(&argc, argv, &filter));
		CPPUNIT_ASSERT_EQUAL(6, argc);

		for ( int i = 0; i < argc; i++ ){
			CPPUNIT_ASSERT(strcmp(argv[i], orig[i]) == 0);
			free(argv[i]);
		}
	}

	void test_starttime(){
		/**@todo Check all supported date formats */
		generate_argv("programname", "--begin", "123.4007", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_START_TIME, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint32_t)123, filter.starttime.tv_sec);
		CPPUNIT_ASSERT_EQUAL((uint64_t)400700000000, filter.starttime.tv_psec);
	}

	void test_endtime(){
		/**@todo Check all supported date formats */
		generate_argv("programname", "--end", "123.4007", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_END_TIME, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint32_t)123, filter.endtime.tv_sec);
		CPPUNIT_ASSERT_EQUAL((uint64_t)400700000000, filter.endtime.tv_psec);
	}

	void test_mampid(){
		generate_argv("programname", "--mampid", "foobar", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_MAMPID, filter.index);
		CPPUNIT_ASSERT(strcmp(filter.mampid, "foobar") == 0);
	}

	void test_iface(){
		generate_argv("programname", "--iface", "foobar", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IFACE, filter.index);
		CPPUNIT_ASSERT(strcmp(filter.iface, "foobar") == 0);
	}

	void test_eth_vlan(){
		generate_argv("programname", "--eth.vlan", "1234/4321", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_VLAN, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint16_t)1234, filter.vlan_tci);
		CPPUNIT_ASSERT_EQUAL((uint16_t)4321, filter.vlan_tci_mask);
	}

	void test_eth_type1(){
		generate_argv("programname", "--eth.type", "ip", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.index", (uint32_t)FILTER_ETH_TYPE, filter.index);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.eth_type", (uint16_t)ETH_P_IP, filter.eth_type);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.eth_type_mask", (uint16_t)0xffff, filter.eth_type_mask);
	}

	void test_eth_type2(){
		generate_argv("programname", "--eth.type", "arp/0xff00", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.index", (uint32_t)FILTER_ETH_TYPE, filter.index);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.eth_type", (uint16_t)0x0800, filter.eth_type);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.eth_type_mask", (uint16_t)0xff00, filter.eth_type_mask);
	}

	void test_eth_type3(){
		generate_argv("programname", "--eth.type", "2048/0xffff", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.index", (uint32_t)FILTER_ETH_TYPE, filter.index);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.eth_type", (uint16_t)ETH_P_IP, filter.eth_type);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("filter.eth_type_mask", (uint16_t)0xffff, filter.eth_type_mask);
	}

	void test_eth_src(){
		struct ether_addr addr = *ether_aton("01:00:00:00:00:02");
		struct ether_addr mask1 = *ether_aton("FF:FF:FF:FF:FF:FF");
		struct ether_addr mask2 = *ether_aton("FF:00:00:00:00:FF");

		generate_argv("programname", "--eth.src", "01:00:00:00:00:02", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_ETH_SRC, filter.index);
		CPPUNIT_ASSERT_ETH_ADDR(addr,  filter.eth_src);
		CPPUNIT_ASSERT_ETH_ADDR(mask1, filter.eth_src_mask);

		generate_argv("programname", "--eth.src", "01:00:00:00:00:02/FF:00:00:00:00:ff", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_ETH_SRC, filter.index);
		CPPUNIT_ASSERT_ETH_ADDR(addr,  filter.eth_src);
		CPPUNIT_ASSERT_ETH_ADDR(mask2, filter.eth_src_mask);
	}

	void test_eth_dst(){
		generate_argv("programname", "--eth.dst", "01:00:00:00:00:02/FF:00:00:00:00:00", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		struct ether_addr addr = *ether_aton("01:00:00:00:00:00");
		struct ether_addr mask = *ether_aton("FF:00:00:00:00:00");

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_ETH_DST, filter.index);
		CPPUNIT_ASSERT_ETH_ADDR(addr, filter.eth_dst);
		CPPUNIT_ASSERT_ETH_ADDR(mask, filter.eth_dst_mask);
	}

	void test_ip_proto(){
		generate_argv("programname", "--ip.proto", "tcp", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_PROTO, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint32_t)6, (uint32_t)filter.ip_proto);

		generate_argv("programname", "--ip.proto", "6", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_PROTO, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint32_t)6, (uint32_t)filter.ip_proto);
	}

	void test_ip_src(){
		in_addr addr = {inet_addr("1.2.3.0")};
		in_addr mask = {inet_addr("255.255.255.192")};

		generate_argv("programname", "--ip.src", "1.2.3.4/255.255.255.192", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_SRC, filter.index);
		CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_src);
		CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_src_mask);

		generate_argv("programname", "--ip.src", "1.2.3.4/26", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_SRC, filter.index);
		CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_src);
		CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_src_mask);
	}

	void test_ip_dst(){
		in_addr addr = {inet_addr("1.2.3.0")};
		in_addr mask = {inet_addr("255.255.255.192")};

		generate_argv("programname", "--ip.dst", "1.2.3.4/255.255.255.192", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_DST, filter.index);
		CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_dst);
		CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_dst_mask);

		generate_argv("programname", "--ip.dst", "1.2.3.4/26", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_DST, filter.index);
		CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_dst);
		CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_dst_mask);
	}

	void test_tp_sport(){
		generate_argv("programname", "--tp.sport", "80/123", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_SRC_PORT, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint16_t)80,  filter.src_port);
		CPPUNIT_ASSERT_EQUAL((uint16_t)123, filter.src_port_mask);

		generate_argv("programname", "--tp.sport", "http/123", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_SRC_PORT, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint16_t)80,  filter.src_port);
		CPPUNIT_ASSERT_EQUAL((uint16_t)123, filter.src_port_mask);
	}

	void test_tp_dport(){
		generate_argv("programname", "--tp.dport", "22/123", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_DST_PORT, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint16_t)18,  filter.dst_port);
		CPPUNIT_ASSERT_EQUAL((uint16_t)123, filter.dst_port_mask);

		generate_argv("programname", "--tp.dport", "ssh/123", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_DST_PORT, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint16_t)18,  filter.dst_port);
		CPPUNIT_ASSERT_EQUAL((uint16_t)123, filter.dst_port_mask);
	}

	void test_missing(){
		generate_argv("programname", "--starttime", NULL);
		CPPUNIT_ASSERT_FAILURE(filter_from_argv(&argc, argv, &filter), 1);
	}

	void test_equal_sign(){
		generate_argv("programname", "--endtime=123.4007", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);
		CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_END_TIME, filter.index);
		CPPUNIT_ASSERT_EQUAL((uint32_t)123, filter.endtime.tv_sec);
		CPPUNIT_ASSERT_EQUAL((uint64_t)400700000000, filter.endtime.tv_psec);
	}

	void test_shortname(){
		generate_argv("programname", "3.cap", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 2);
	}

	void test_mode_and(){
		generate_argv("programname", "--filter-mode", "aNd", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);
		CPPUNIT_ASSERT_EQUAL(FILTER_AND, filter.mode);
	}

	void test_mode_or(){
		generate_argv("programname", "--filter-mode", "Or", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);
		CPPUNIT_ASSERT_EQUAL(FILTER_OR, filter.mode);
	}

	void test_mode_invalid(){
		generate_argv("programname", "--filter-mode", "foo", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);
	}

	void test_bpf_valid(){
		const std::string expr = "icmp or net 1.2.3.0/24";
		generate_argv("test_bpf_valid", "--bpf", expr.c_str(), NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);
		CPPUNIT_ASSERT_EQUAL(std::string(filter.bpf_expr), expr);
	}

	void test_bpf_invalid(){
		generate_argv("test_bpf_invalid", "--bpf", "some invalid string", NULL);
#ifdef HAVE_PCAP
		CPPUNIT_ASSERT_FAILURE(filter_from_argv(&argc, argv, &filter), 1);
#else
		/* cannot test for validity unless pcap is enabled, this test reverts to the same as `test_bpf_valid`. */
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);
#endif
	}

	void test_ethertype1(){
		const struct ethertype* ethertype = ethertype_by_name("ip");
		CPPUNIT_ASSERT_EQUAL(0x0800, ethertype ? ethertype->value : 0);
	}

	void test_ethertype2(){
		const struct ethertype* ethertype = ethertype_by_name("IP");
		CPPUNIT_ASSERT_EQUAL(0x0800, ethertype ? ethertype->value : 0);
	}

	void test_ethertype3(){
		const struct ethertype* ethertype = ethertype_by_name("invalid");
		CPPUNIT_ASSERT_EQUAL(0, ethertype ? ethertype->value : 0);
	}

	void test_ethertype4(){
		const struct ethertype* ethertype = ethertype_by_number(0x0800);
		std::string name = ethertype ? ethertype->name : "invalid";
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		CPPUNIT_ASSERT_EQUAL(std::string("ipv4"), name);
	}

	void test_frame_range(){
		generate_argv("programname", "--frame-num=-10,13,20-25,50-", NULL);
		CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

		int i;
		struct frame_num_node* cur;
		for ( i=0, cur = filter.frame_num; cur; ++i, cur = cur->next ){
			switch (i){
			case 0:
				CPPUNIT_ASSERT_EQUAL_MESSAGE("-10 lower", -1, cur->lower);
				CPPUNIT_ASSERT_EQUAL_MESSAGE("-10 upper", 10, cur->upper);
				break;
			case 1:
				CPPUNIT_ASSERT_EQUAL_MESSAGE("13 lower", 13, cur->lower);
				CPPUNIT_ASSERT_EQUAL_MESSAGE("13 upper", 13, cur->upper);
				break;
			case 2:
				CPPUNIT_ASSERT_EQUAL_MESSAGE("-20,25 lower", 20, cur->lower);
				CPPUNIT_ASSERT_EQUAL_MESSAGE("-20,25 upper", 25, cur->upper);
				break;
			case 3:
				CPPUNIT_ASSERT_EQUAL_MESSAGE("50- lower", 50, cur->lower);
				CPPUNIT_ASSERT_EQUAL_MESSAGE("50- upper", -1, cur->upper);
				break;
			}
		}

		CPPUNIT_ASSERT_EQUAL_MESSAGE("num ranges", 4, i);
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(FilterCreate);

int main(int argc, const char* argv[]){
	CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
	CppUnit::TextUi::TestRunner runner;
	filter_from_argv_opterr = 0;

	runner.addTest(suite);
	runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr));

	int ret = runner.run() ? 0 : 1;

	for ( std::list<char*>::iterator it = strings.begin(); it != strings.end(); ++it ){
		free(*it);
	}
	strings.clear();

	return ret;
}
