#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

#include "src/slist.h"
#include <string.h>

class Test: public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(Test);
	//CPPUNIT_TEST(test_empty);
	//CPPUNIT_TEST(test_put);
	//CPPUNIT_TEST(test_get);
	CPPUNIT_TEST(test_memory);
	//CPPUNIT_TEST(test_find);
	//CPPUNIT_TEST(test_grow);
	CPPUNIT_TEST_SUITE_END();

public:
	void test_empty(){
		struct simple_list slist;
		slist_init(&slist, sizeof(char*), sizeof(char*), 0);
		{
			CPPUNIT_ASSERT_EQUAL((size_t)0, slist.size);
			CPPUNIT_ASSERT_EQUAL((size_t)0, slist.capacity);
		}
		slist_free(&slist);
	}

	void test_put(){
		struct simple_list slist;
		slist_init(&slist, sizeof(char*), sizeof(int), 10);
		{
			int* value = (int*)slist_put(&slist, strdup("foo"));
			*value = 4711;

			CPPUNIT_ASSERT_EQUAL((size_t)1,  slist.size);
			CPPUNIT_ASSERT_EQUAL((size_t)10, slist.capacity);
		}
		slist_free(&slist);
	}

	void test_get(){
		struct simple_list slist;
		slist_init(&slist, sizeof(char*), sizeof(int), 10);
		{
			int* value = (int*)slist_put(&slist, strdup("foo"));
			*value = 4711;

			int* fetch = (int*)slist_get(&slist, 0);
			CPPUNIT_ASSERT_EQUAL((size_t)1,  slist.size);
			CPPUNIT_ASSERT_EQUAL((size_t)10, slist.capacity);
			CPPUNIT_ASSERT(fetch);
			CPPUNIT_ASSERT_EQUAL(4711, *(int*)fetch);
		}
		slist_free(&slist);
	}


	void test_memory(){
		struct foo { int a; int b; int c; int d; };
		const long element_size = sizeof(struct foo);;
		struct simple_list slist;
		slist_init(&slist, sizeof(char*), element_size, 10);
		{
			struct foo* pa = (struct foo*)slist_put(&slist, strdup("foo"));
			struct foo* pb = (struct foo*)slist_put(&slist, strdup("bar"));

			struct foo* ga = (struct foo*)slist_get(&slist, 0);
			struct foo* gb = (struct foo*)slist_get(&slist, 1);

			CPPUNIT_ASSERT_EQUAL((long)1, pb - pa);
			CPPUNIT_ASSERT_EQUAL((long)1, gb - ga);
			CPPUNIT_ASSERT_EQUAL(element_size, (char*)pb - (char*)pa);
			CPPUNIT_ASSERT_EQUAL(element_size, (char*)gb - (char*)ga);
		}
		slist_free(&slist);
	}

	void test_find(){
		struct simple_list slist;
		slist_init(&slist, sizeof(char*), sizeof(int), 10);
		{
			int* value = (int*)slist_put(&slist, strdup("foo"));
			*value = 4711;

			int* fetch = (int*)slist_find(&slist, "foo", slist_strcmp);
			CPPUNIT_ASSERT_EQUAL((size_t)1,  slist.size);
			CPPUNIT_ASSERT_EQUAL((size_t)10, slist.capacity);
			CPPUNIT_ASSERT(fetch);
			CPPUNIT_ASSERT_EQUAL(4711, *(int*)fetch);
		}
		slist_free(&slist);
	}

	void test_grow(){
		struct simple_list slist;
		slist_init(&slist, sizeof(char*), sizeof(int), 2);
		{
			slist_put(&slist, strdup("foo"));
			slist_put(&slist, strdup("bar"));
			slist_put(&slist, strdup("baz"));

			CPPUNIT_ASSERT_EQUAL((size_t)3, slist.size);
			CPPUNIT_ASSERT_EQUAL((size_t)4, slist.capacity);
		}
		slist_free(&slist);
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
