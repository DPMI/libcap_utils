#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/picotime.h"

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

static void check_timepico(const timepico& expected, const timepico& actual, CppUnit::SourceLine sourceLine){
	CppUnit::assertEquals(expected.tv_sec,  actual.tv_sec,  sourceLine, "Seconds");
	CppUnit::assertEquals(expected.tv_psec, actual.tv_psec, sourceLine, "Picoseconds");
}

static void check_timepico(const timepico& expected, const char* string, CppUnit::SourceLine sourceLine){
	timepico actual;
	CppUnit::assertEquals(0, timepico_from_string(&actual, string), sourceLine, "failed to parse");
	check_timepico(expected, actual, sourceLine);
}

static timepico t(uint32_t a, uint64_t b){ timepico tmp = {a,b}; return tmp; }

#define CPPUNIT_ASSERT_TIMEPICO(expected, actual) check_timepico(expected, actual, CPPUNIT_SOURCELINE())

class TimepicoTest: public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(TimepicoTest);
	CPPUNIT_TEST(test_sub);
	CPPUNIT_TEST(from_string_unix);
	CPPUNIT_TEST_SUITE_END();

public:
	void test_sub(){
		timepico a = { 3, (uint64_t)1e11 };
		timepico b = { 1, (uint64_t)9e11 };
		timepico diff = timepico_sub(a, b);

		CPPUNIT_ASSERT_EQUAL((uint32_t)1,    diff.tv_sec );
		CPPUNIT_ASSERT_EQUAL((uint64_t)2e11, diff.tv_psec);
	}

	void from_string_unix(){
		CPPUNIT_ASSERT_TIMEPICO(t(1, 0), "1");
		CPPUNIT_ASSERT_TIMEPICO(t(2, 100000000000), "2.1");
		CPPUNIT_ASSERT_TIMEPICO(t(3, 120000000000), "3.12");
		CPPUNIT_ASSERT_TIMEPICO(t(4, 9), "4.000000000009");
		CPPUNIT_ASSERT_TIMEPICO(t(1341272547, 795973301000), "1341272547.795973301000");
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
