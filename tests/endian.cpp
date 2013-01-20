#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "be64toh.h"
#include <limits>
extern "C" uint64_t _int_htobe64(uint64_t val);
extern "C" uint64_t _int_be64toh(uint64_t val);

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

static uint64_t values[4] = {
	std::numeric_limits<uint64_t>::min(),
	std::numeric_limits<uint64_t>::min() + 1,
	std::numeric_limits<uint64_t>::max() - 1,
	std::numeric_limits<uint64_t>::max()
};

class EndianTest: public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(EndianTest);
#ifdef HAVE_BE64TOH
	CPPUNIT_TEST( test_endian );
#else
#warning be64toh is not available on build system, test disabled
#endif
	CPPUNIT_TEST_SUITE_END();

public:

	void test_endian(){
		uint64_t tmp[2][4];

		for ( int i = 0; i < 4; i++ ){
			tmp[0][i] = htobe64(values[i]);
			tmp[1][i] = _int_htobe64(values[i]);
			CPPUNIT_ASSERT_EQUAL(tmp[0][i], tmp[1][i]);
		}

		for ( int i = 0; i < 4; i++ ){
			uint64_t rev = _int_htobe64(tmp[1][i]);
			CPPUNIT_ASSERT_EQUAL(values[i], rev);
		}
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(EndianTest);

int main(int argc, const char* argv[]){
	CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();

	CppUnit::TextUi::TestRunner runner;

	runner.addTest(suite);
	runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr));

	return runner.run() ? 0 : 1;
}

