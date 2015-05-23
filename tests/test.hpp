#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>

#include "../caputils/capture.h"

#ifdef DATA_FILENAME
extern char data[1024];
static __attribute__((unused)) const cap_head* caphead = (const cap_head*)data;
#endif
