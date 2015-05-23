#include "test.hpp"

#include <caputils/packet.h>
#include "src/format/format.h"

#include <cstdlib>
#include <cstring>

class Data {
public:
	Data(size_t bytes)
		: bytes(bytes) {
		ptr = new char[bytes];

		for ( size_t i = 0; i < bytes; i++ ){
			ptr[i] = (i+32) % 256;
		}
	}

	~Data(){
		delete [] ptr;
	}

	size_t size() const {
		return bytes;
	}

	const char* get() const {
		return ptr;
	}

private:
	size_t bytes;
	char* ptr;
};
Data data(1);

/* log.c */
extern "C" size_t aligned(size_t value, size_t n);

class Test: public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(Test);
	CPPUNIT_TEST(test_aligned);
	CPPUNIT_TEST(test_fin_address);
	CPPUNIT_TEST_SUITE_END();

public:
	void test_aligned(){
		CPPUNIT_ASSERT_EQUAL((size_t)0,  aligned(0,  16));
		CPPUNIT_ASSERT_EQUAL((size_t)16, aligned(1,  16));
		CPPUNIT_ASSERT_EQUAL((size_t)16, aligned(16, 16));
		CPPUNIT_ASSERT_EQUAL((size_t)32, aligned(17, 16));
	}

	void test_fin_address(){
		char* dump = hexdump_str(data.get(), data.size());

		/* find last line in string */
		char* last_line = dump;
		const size_t len = strlen(dump);
		for ( size_t i = 0; i < len; i++ ){
			if ( dump[i] == '\n' ){
				dump[i] = 0;
				if ( dump[i+1] != 0 ){
					last_line = dump+i+1;
				}
			}
		}

		/* ensure last line contains address final address */
		int addr;
		if ( sscanf(last_line, "[%X]", &addr) != 1 ){
			CPPUNIT_FAIL("Failed to parse final size");
		}

		CPPUNIT_ASSERT_EQUAL(data.size(), (size_t)addr);
		free(dump);
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(Test);
