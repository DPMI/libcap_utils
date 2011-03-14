# 
# Make stuff
#

srcdir = .
prefix = /usr

INCPATH=$(prefix)/include
LIBPATH=$(prefix)/lib
MANPATH=$(prefix)/man
BINPATH=$(prefix)/bin

DESTDIR=

DB=$(DESTDIR)$(BINPATH)
DI=$(DESTDIR)$(INCPATH)
DL=$(DESTDIR)$(LIBPATH)
DM=$(DESTDIR)$(MANPATH)
DP=$(DESTDIR)$(prefix)

CFLAGS+=-c -fPIC -O2 -Wall
objects= createstream.o openstream.o closestream.o createfilter.o filter.o readpost.o writepost.o valtopico.o spectopico.o timecmp.o ethaton.o



targetlib=/usr/lib/
targetinclude=/usr/include/
libname=libcap_utils
version=1.0.5

all: $(objects)
	$(CC) -shared -Wl,-soname,$(libname).so.1 -o $(libname).so.$(version) $(objects) -lc
createfilter.o:	createfilter.c cap_utils.h
	$(CC) $(CFLAGS) createfilter.c
filter.o: filter.c cap_utils.h
	$(CC) $(CFLAGS) filter.c
openstream.o: openstream.c cap_utils.h
	$(CC) $(CFLAGS) openstream.c
closestream.o: closestream.c cap_utils.h
	$(CC) $(CFLAGS) closestream.c
createstream.o: createstream.c cap_utils.h
	$(CC) $(CFLAGS) createstream.c
readpost.o: readpost.c cap_utils.h
	$(CC) $(CFLAGS) readpost.c
writepost.o: writepost.c cap_utils.h
	$(CC) $(CFLAGS) writepost.c
valtopico.o: valtopico.c cap_utils.h
	$(CC) $(CFLAGS) valtopico.c
spectopico.o: spectopico.c  cap_utils.h
	$(CC) $(CFLAGS) spectopico.c
timecmp.o: timecmp.c cap_utils.h
	$(CC) $(CFLAGS) timecmp.c
ethaton.o: ethaton.c cap_utils.h
	$(CC) $(CFLAGS) ethaton.c
clean:
	rm $(objects) libcap_utils.so.$(version)
install:
	-@if [ ! -d $(DP) ]; then mkdir $(DP); fi
	-@if [ ! -d $(DL) ]; then mkdir $(DL); fi
	-@if [ ! -d $(DI) ]; then mkdir $(DI); fi
	cp $(libname).so.$(version) $(DL)/$(libname).so.$(version); \
	cp cap_utils.h $(DI)/cap_utils.h; \
	/sbin/ldconfig;\
	ln -sf $(DL)/$(libname).so.$(version) $(DL)/$(libname).so
	ln -sf $(DL)/$(libname).so.$(version) $(DL)/$(libname).so.1
uninstall:
	rm $(DL)/libcap_utils.*; \
	rm $(DI)/cap_utils.h

update: all uninstall install
