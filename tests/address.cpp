#include <caputils/filter.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

extern "C" const char* hexdump_address_r(const struct ether_addr* address, char* buf);
void check_eth_addr(const struct ether_addr& a, const struct ether_addr& b, CppUnit::SourceLine sourceLine){
  for ( int i = 0; i < ETH_ALEN; i++ ){
    if ( a.ether_addr_octet[i] != b.ether_addr_octet[i] ){
      char expected[24], actual[24];
      CppUnit::Asserter::failNotEqual(hexdump_address_r(&a, expected), hexdump_address_r(&b, actual), sourceLine);
    }
  }
}

void check_error(int expected, int actual, CppUnit::SourceLine line){
  if ( expected == actual ){
    return;
  }
  CppUnit::Asserter::failNotEqual(strerror(expected), strerror(actual), line);
}

#define CPPUNIT_ASSERT_ETH_ADDR(expected, actual) check_eth_addr(expected, actual, CPPUNIT_SOURCELINE())
#define CPPUNIT_ASSERT_ERROR(expected, actual) check_error(expected, actual, CPPUNIT_SOURCELINE())

static char msg[1024];

class AddressTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(AddressTest);
  CPPUNIT_TEST( test_ethernet_colon  );
  CPPUNIT_TEST( test_ethernet_dash   );
  CPPUNIT_TEST( test_ethernet_none   );
  CPPUNIT_TEST( test_ethernet_short  );
  CPPUNIT_TEST( test_ethernet_leading);
  CPPUNIT_TEST( test_guess_eth       );
	CPPUNIT_TEST( test_prefix_eth      );
  CPPUNIT_TEST( test_prefix_filename );
  CPPUNIT_TEST( test_prefix_invalid  );
  CPPUNIT_TEST_SUITE_END();

public:
  void compare_eth_addr(const char* sample, const char* test, const CppUnit::SourceLine& line){
    struct ether_addr* tmp = ether_aton(sample);
    if ( !tmp ){
      sprintf(msg, "ether_aton() failed");
      CppUnit::Asserter::fail(msg);
    }
    struct ether_addr addr = *tmp;

    stream_addr_t dest;
    int ret;
    if ( (ret=stream_addr_aton(&dest, test, STREAM_ADDR_ETHERNET, 0)) != 0 ){
      sprintf(msg, "stream_addr_aton() returned %d: %s", ret, strerror(ret));
      CppUnit::Asserter::fail(msg, line);
    }

    CPPUNIT_ASSERT_ETH_ADDR(addr, dest.ether_addr);
  }

  void test_ethernet_colon(){
    compare_eth_addr("cb:a9:87:65:43:21", "cb:a9:87:65:43:21", CPPUNIT_SOURCELINE());
  }

  void test_ethernet_dash(){
    compare_eth_addr("cb:a9:87:65:43:21", "cb-a9-87-65-43-21", CPPUNIT_SOURCELINE());
  }

  void test_ethernet_none(){
    compare_eth_addr("cb:a9:87:65:43:21", "cba987654321", CPPUNIT_SOURCELINE());
  }

  void test_ethernet_short(){
    compare_eth_addr("01:00:00:00:00:09", "01::09", CPPUNIT_SOURCELINE());
    compare_eth_addr("01:00:00:00:00:09", "1::9", CPPUNIT_SOURCELINE());
    compare_eth_addr("01:02:00:00:00:09", "01:02::09", CPPUNIT_SOURCELINE());
    compare_eth_addr("01:00:00:00:08:09", "01::08:09", CPPUNIT_SOURCELINE());
  }

  void test_ethernet_leading(){
    compare_eth_addr("00:01:02:03:04:05", "0:1:2:3:4:5", CPPUNIT_SOURCELINE());
  }

  void test_guess_eth(){
    const char* sample = "cb:a9:87:65:43:21";
    struct ether_addr* expected = ether_aton(sample);
    stream_addr_t addr;
    int ret;

    if ( (ret=stream_addr_aton(&addr, sample, STREAM_ADDR_GUESS, 0)) != 0 ){
      sprintf(msg, "stream_addr_aton() returned %d: %s", ret, strerror(ret));
      CppUnit::Asserter::fail(msg);
    }

    CPPUNIT_ASSERT_ETH_ADDR(*expected, addr.ether_addr);
  }

  void test_guess_filename(){
    std::string sample = "/path/to/file";
    stream_addr_t addr;
    int ret;

    if ( (ret=stream_addr_aton(&addr, sample.c_str(), STREAM_ADDR_GUESS, 0)) != 0 ){
      sprintf(msg, "stream_addr_aton() returned %d: %s", ret, strerror(ret));
      CppUnit::Asserter::fail(msg);
    }

    CPPUNIT_ASSERT_EQUAL(sample, std::string(addr.local_filename));
  }

	void test_prefix_eth(){
    const char* sample = "eth://cb:a9:87:65:43:21";
    struct ether_addr* expected = ether_aton(sample+6);
    stream_addr_t addr;
    int ret;

    if ( (ret=stream_addr_aton(&addr, sample, STREAM_ADDR_GUESS, 0)) != 0 ){
      sprintf(msg, "stream_addr_aton() returned %d: %s", ret, strerror(ret));
      CppUnit::Asserter::fail(msg);
    }

    CPPUNIT_ASSERT_EQUAL(STREAM_ADDR_ETHERNET, stream_addr_type(&addr));
    CPPUNIT_ASSERT_ETH_ADDR(*expected, addr.ether_addr);
	}

	void test_prefix_filename(){
    const char* sample = "file://cb:a9:87:65:43:21";
    stream_addr_t addr;
    int ret;

    if ( (ret=stream_addr_aton(&addr, sample, STREAM_ADDR_GUESS, 0)) != 0 ){
      sprintf(msg, "stream_addr_aton() returned %d: %s", ret, strerror(ret));
      CppUnit::Asserter::fail(msg);
    }

    CPPUNIT_ASSERT_EQUAL(STREAM_ADDR_CAPFILE, stream_addr_type(&addr));
    CPPUNIT_ASSERT_EQUAL(std::string("cb:a9:87:65:43:21"), std::string(addr.local_filename));
	}

	void test_prefix_invalid(){
    stream_addr_t addr;
    if ( stream_addr_aton(&addr, "nonsense://foobar", STREAM_ADDR_GUESS, 0) == 0 ){
      CppUnit::Asserter::fail("invalid prefix was accepted");
    }
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(AddressTest);

int main(int argc, const char* argv[]){
  CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();

  CppUnit::TextUi::TestRunner runner;

  runner.addTest( suite );
  runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr ));

  return runner.run() ? 0 : 1;
}

