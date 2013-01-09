#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/stream.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>


class Test: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Test);
  CPPUNIT_TEST( test_num_stream_single );
  CPPUNIT_TEST_SUITE_END();

public:
  void test_num_stream_single(){
	  stream_t st;
	  stream_addr_t addr = STREAM_ADDR_INITIALIZER;

	  stream_addr_str(&addr, TOP_SRCDIR "/tests/empty.cap", 0);
	  int ret = stream_open(&st, &addr, NULL, 0);

	  CPPUNIT_ASSERT_EQUAL(std::string(strerror(0)), std::string(strerror(ret)));
    CPPUNIT_ASSERT_EQUAL((unsigned int)1, stream_num_address(st));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Test);

int main(int argc, const char* argv[]){
  CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();

  CppUnit::TextUi::TestRunner runner;

  runner.addTest( suite );
  runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr ));

  return runner.run() ? 0 : 1;
}

