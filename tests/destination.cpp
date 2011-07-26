#include <caputils/filter.h>
#include <stdlib.h>
#include <string.h>

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
#define CPPUNIT_ASSERT_ETH_ADDR(expected, actual) check_eth_addr(expected, actual, CPPUNIT_SOURCELINE())

class DestinationTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(DestinationTest);
  CPPUNIT_TEST( test_ethernet_colon  );
  CPPUNIT_TEST( test_ethernet_dash   );
  CPPUNIT_TEST( test_ethernet_none   );
  CPPUNIT_TEST_SUITE_END();

public:
  void compare_eth_addr(const char* sample, const char* test, const CppUnit::SourceLine& line){
    static char msg[1024];
    struct ether_addr* tmp = ether_aton(sample);
    if ( !tmp ){
      sprintf(msg, "ether_aton() failed");
      CppUnit::Asserter::fail(msg);
    }
    struct ether_addr addr = *tmp;

    destination_t dest;
    int ret;
    if ( (ret=destination_aton(&dest, test, DEST_ETHERNET)) != 0 ){
      sprintf(msg, "destination_aton() returned %d: %s", ret, strerror(ret));
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

};

CPPUNIT_TEST_SUITE_REGISTRATION(DestinationTest);

int main(int argc, const char* argv[]){
  CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();

  CppUnit::TextUi::TestRunner runner;

  runner.addTest( suite );
  runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr ));

  return runner.run() ? 0 : 1;
}

