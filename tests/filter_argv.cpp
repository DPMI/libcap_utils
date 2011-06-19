#include <caputils/filter.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

int generate_argv(char** dst, const char* name, ...){
  va_list ap;
  int argc = 0;
  const char* arg;

  dst[argc++] = strdup(name);
  va_start(ap, name);
  do {
    arg = va_arg(ap, const char*);
    dst[argc++] = arg ? strdup(arg) : NULL;
  } while ( arg );

  return argc - 1;
}

void free_argv(int argc, char** argv){
  for ( int i = 0; i < argc; i++ ){
    free(argv[i]);
  }
}

extern "C" const char* hexdump_address_r(const struct ether_addr* address, char* buf);
void check_eth_addr(const struct ether_addr& a, const struct ether_addr& b, CppUnit::SourceLine sourceLine){
  for ( int i = 0; i < ETH_ALEN; i++ ){
    if ( a.ether_addr_octet[i] != b.ether_addr_octet[i] ){
      char expected[24], actual[24];
      CppUnit::Asserter::failNotEqual(hexdump_address_r(&a, expected), hexdump_address_r(&b, actual), sourceLine);
    }
  }
}

void check_success(int ret, int expected, int actual, CppUnit::SourceLine sourceLine){
  if ( ret != 0 ){
    CppUnit::Asserter::failNotEqual("(no error)", strerror(ret), sourceLine, "function did not return successfully");
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
  CPPUNIT_TEST( test_eth_type      );
  CPPUNIT_TEST( test_eth_src       );
  CPPUNIT_TEST( test_eth_dst       );
  CPPUNIT_TEST( test_ip_proto      );
  CPPUNIT_TEST( test_ip_src        );
  CPPUNIT_TEST( test_ip_dst        );
  CPPUNIT_TEST( test_tp_sport      );
  CPPUNIT_TEST( test_tp_dport      );
  CPPUNIT_TEST_SUITE_END();

  struct filter filter;
  char* argv[64];
  int argc;

public:
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
    argc = generate_argv(argv, "programname", "--begin", "123.4007", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_START_TIME, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint32_t)123, filter.starttime.tv_sec);
    CPPUNIT_ASSERT_EQUAL((uint64_t)4007000000000, filter.starttime.tv_psec);
  }

  void test_endtime(){
    argc = generate_argv(argv, "programname", "--end", "123.4007", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_END_TIME, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint32_t)123, filter.endtime.tv_sec);
    CPPUNIT_ASSERT_EQUAL((uint64_t)4007000000000, filter.endtime.tv_psec);
  }

  void test_mampid(){
    argc = generate_argv(argv, "programname", "--mampid", "foobar", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_MAMPID, filter.index);
    CPPUNIT_ASSERT(strcmp(filter.mampid, "foobar") == 0);
  }

  void test_iface(){
    argc = generate_argv(argv, "programname", "--iface", "foobar", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IFACE, filter.index);
    CPPUNIT_ASSERT(strcmp(filter.iface, "foobar") == 0);
  }

  void test_eth_vlan(){
    argc = generate_argv(argv, "programname", "--eth.vlan", "1234/4321", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_VLAN, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint16_t)1234, filter.vlan_tci);
    CPPUNIT_ASSERT_EQUAL((uint16_t)4321, filter.vlan_tci_mask);
  }

  void test_eth_type(){
    argc = generate_argv(argv, "programname", "--eth.type", "ip", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_ETH_TYPE, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint16_t)ETH_P_IP, filter.eth_type);

    argc = generate_argv(argv, "programname", "--eth.type", "2048", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_ETH_TYPE, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint16_t)ETH_P_IP, filter.eth_type);
  }

  void test_eth_src(){
    argc = generate_argv(argv, "programname", "--eth.src", "01:00:00:00:00:02/FF:FF:FF:FF:FF:00", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    struct ether_addr addr = *ether_aton("01:00:00:00:00:02");
    struct ether_addr mask = *ether_aton("FF:FF:FF:FF:FF:00");
   
    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_ETH_SRC, filter.index);
    CPPUNIT_ASSERT_ETH_ADDR(addr, filter.eth_src);
    CPPUNIT_ASSERT_ETH_ADDR(mask, filter.eth_src_mask);
  }

  void test_eth_dst(){
    argc = generate_argv(argv, "programname", "--eth.dst", "01:00:00:00:00:02/FF:FF:FF:FF:FF:00", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);
    
    struct ether_addr addr = *ether_aton("01:00:00:00:00:02");
    struct ether_addr mask = *ether_aton("FF:FF:FF:FF:FF:00");

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_ETH_DST, filter.index);
    CPPUNIT_ASSERT_ETH_ADDR(addr, filter.eth_dst);
    CPPUNIT_ASSERT_ETH_ADDR(mask, filter.eth_dst_mask);
  }

  void test_ip_proto(){
    argc = generate_argv(argv, "programname", "--ip.proto", "tcp", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_PROTO, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint32_t)6, (uint32_t)filter.ip_proto);

    argc = generate_argv(argv, "programname", "--ip.proto", "6", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_PROTO, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint32_t)6, (uint32_t)filter.ip_proto);
  }

  void test_ip_src(){
    in_addr addr = {inet_addr("1.2.3.4")};
    in_addr mask = {inet_addr("255.255.255.192")};

    argc = generate_argv(argv, "programname", "--ip.src", "1.2.3.4/255.255.255.192", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_SRC, filter.index);
    CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_src);
    CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_src_mask);

    argc = generate_argv(argv, "programname", "--ip.src", "1.2.3.4/26", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_SRC, filter.index);
    CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_src);
    CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_src_mask);
  }

  void test_ip_dst(){
    in_addr addr = {inet_addr("1.2.3.4")};
    in_addr mask = {inet_addr("255.255.255.192")};

    argc = generate_argv(argv, "programname", "--ip.dst", "1.2.3.4/255.255.255.192", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_DST, filter.index);
    CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_dst);
    CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_dst_mask);

    argc = generate_argv(argv, "programname", "--ip.dst", "1.2.3.4/26", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_IP_DST, filter.index);
    CPPUNIT_ASSERT_INET_ADDR(addr, filter.ip_dst);
    CPPUNIT_ASSERT_INET_ADDR(mask, filter.ip_dst_mask);
  }

  void test_tp_sport(){
    argc = generate_argv(argv, "programname", "--tp.sport", "80/123", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_SRC_PORT, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint16_t)80,  filter.src_port);
    CPPUNIT_ASSERT_EQUAL((uint16_t)123, filter.src_port_mask);
  }

  void test_tp_dport(){
    argc = generate_argv(argv, "programname", "--tp.dport", "80/123", NULL);
    CPPUNIT_ASSERT_SUCCESS(filter_from_argv(&argc, argv, &filter), 1);

    CPPUNIT_ASSERT_EQUAL((uint32_t)FILTER_DST_PORT, filter.index);
    CPPUNIT_ASSERT_EQUAL((uint16_t)80,  filter.dst_port);
    CPPUNIT_ASSERT_EQUAL((uint16_t)123, filter.dst_port_mask);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(FilterCreate);

int main(int argc, const char* argv[]){
  CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();

  CppUnit::TextUi::TestRunner runner;

  runner.addTest( suite );
  runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr ));

  return runner.run() ? 0 : 1;
}

