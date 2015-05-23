#include "test.hpp"

#ifdef DATA_FILENAME
char data[1024];
#endif

int main(int argc, const char* argv[]){
	CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
	CppUnit::TextUi::TestRunner runner;

#ifdef DATA_FILENAME
	const char* path = TOP_SRCDIR "/" DATA_FILENAME;
	FILE* fp = fopen(path, "r");
	if ( !fp ){
		fprintf(stderr, "failed to read `%s'\n", path);
		return 1;
	}

	/* read the test packet */
	int bytes;
	const int expected = DATA_SIZE;
	if ( (bytes=fread(data, 1, sizeof(data), fp)) < expected ){
		fprintf(stderr, "failed to read `%s' (data truncated, read %d bytes, expected %d)\n", path, bytes, expected);
		return 1;
	}
	fclose(fp);
#endif

	runner.addTest(suite);
	runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(), std::cerr));

	return runner.run() ? 0 : 1;
}
