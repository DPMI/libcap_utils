#include "test.hpp"

#include <caputils/packet.h>
#include "src/format/format.h"

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
	CPPUNIT_TEST(test_limited_caplen);
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

	void test_limited_caplen(){
		union {
			char buffer[2 + sizeof(struct cap_header)];
			struct cap_header cp;
		};
		cp.caplen = 2;

		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 0] <- 1 bytes", !limited_caplen(&cp, cp.payload+0, 1));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 0] <- 2 bytes", !limited_caplen(&cp, cp.payload+0, 2));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 0] <- 3 bytes",  limited_caplen(&cp, cp.payload+0, 3));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 1] <- 1 bytes", !limited_caplen(&cp, cp.payload+1, 1));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 1] <- 2 bytes",  limited_caplen(&cp, cp.payload+1, 2));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 1] <- 3 bytes",  limited_caplen(&cp, cp.payload+1, 3));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 2] <- 1 bytes",  limited_caplen(&cp, cp.payload+2, 1));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 2] <- 2 bytes",  limited_caplen(&cp, cp.payload+2, 2));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[ 2] <- 3 bytes",  limited_caplen(&cp, cp.payload+2, 3));
		CPPUNIT_ASSERT_MESSAGE("cp.payload[-1] <- 1 bytes",  limited_caplen(&cp, cp.payload-1, 1));
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(Test);
