#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/picotime.h"

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

class TimepicoTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(TimepicoTest);
  CPPUNIT_TEST( test_sub );
  CPPUNIT_TEST_SUITE_END();

public:

  void test_sub(){
	  timepico a = { 3, 1e11 };
	  timepico b = { 1, 9e11 };
	  timepico diff = timepico_sub(&a, &b);

	  CPPUNIT_ASSERT_EQUAL((uint32_t)1,    diff.tv_sec );
	  CPPUNIT_ASSERT_EQUAL((uint64_t)2e11, diff.tv_psec);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(TimepicoTest);

int main(int argc, const char* argv[]){
  CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();

  CppUnit::TextUi::TestRunner runner;

  runner.addTest( suite );
  runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr ));

  return runner.run() ? 0 : 1;
}

