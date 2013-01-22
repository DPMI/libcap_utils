#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/packet.h>

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

static char data[1024];
static const cap_head* caphead = (const cap_head*)data;

class Test: public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(Test);
	CPPUNIT_TEST(test_level_from_string);
	CPPUNIT_TEST(test_layer_physical);
	CPPUNIT_TEST(test_layer_link);
	CPPUNIT_TEST(test_layer_network);
	CPPUNIT_TEST(test_layer_transport);
	CPPUNIT_TEST(test_layer_application);
	CPPUNIT_TEST(test_payload_physical);
	CPPUNIT_TEST(test_payload_link);
	CPPUNIT_TEST(test_payload_network);
	CPPUNIT_TEST(test_payload_transport);
	CPPUNIT_TEST_SUITE_END();

public:
	void test_level_from_string(){
		CPPUNIT_ASSERT_EQUAL(LEVEL_PHYSICAL,    level_from_string("physical"));
		CPPUNIT_ASSERT_EQUAL(LEVEL_LINK,        level_from_string("link"));
		CPPUNIT_ASSERT_EQUAL(LEVEL_NETWORK,     level_from_string("network"));
		CPPUNIT_ASSERT_EQUAL(LEVEL_TRANSPORT,   level_from_string("transport"));
		CPPUNIT_ASSERT_EQUAL(LEVEL_APPLICATION, level_from_string("application"));
		CPPUNIT_ASSERT_EQUAL(LEVEL_LINK,        level_from_string("lINk"));
		CPPUNIT_ASSERT_EQUAL(LEVEL_INVALID,     level_from_string("invalid"));
		CPPUNIT_ASSERT_EQUAL(LEVEL_INVALID,     level_from_string("anything"));
	}

	void test_layer_physical(){
		CPPUNIT_ASSERT_EQUAL((size_t)0, layer_size(LEVEL_PHYSICAL, caphead));
	}

	void test_layer_link(){
		CPPUNIT_ASSERT_EQUAL((size_t)505, layer_size(LEVEL_LINK, caphead));
	}

	void test_layer_network(){
		CPPUNIT_ASSERT_EQUAL((size_t)491, layer_size(LEVEL_NETWORK, caphead));
	}

	void test_layer_transport(){
		CPPUNIT_ASSERT_EQUAL((size_t)471, layer_size(LEVEL_TRANSPORT, caphead));
	}

	void test_layer_application(){
		CPPUNIT_ASSERT_EQUAL((size_t)439, layer_size(LEVEL_APPLICATION, caphead));
	}

	void test_payload_physical(){
		CPPUNIT_ASSERT_EQUAL((size_t)505, payload_size(LEVEL_PHYSICAL, caphead));
	}

	void test_payload_link(){
		CPPUNIT_ASSERT_EQUAL((size_t)491, payload_size(LEVEL_LINK, caphead));
	}

	void test_payload_network(){
		CPPUNIT_ASSERT_EQUAL((size_t)471, payload_size(LEVEL_NETWORK, caphead));
	}

	void test_payload_transport(){
		CPPUNIT_ASSERT_EQUAL((size_t)439, payload_size(LEVEL_TRANSPORT, caphead));
	}

};

CPPUNIT_TEST_SUITE_REGISTRATION(Test);

int main(int argc, const char* argv[]){
	CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
	CppUnit::TextUi::TestRunner runner;

	const char* path = TOP_SRCDIR"/tests/http.packet";
	FILE* fp = fopen(path, "r");
	if ( !fp ){
		fprintf(stderr, "failed to read `%s'\n", path);
		return 1;
	}
	fread(data, 1, sizeof(data), fp);
	fclose(fp);

	runner.addTest(suite);
	runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr));

	return runner.run() ? 0 : 1;
}
