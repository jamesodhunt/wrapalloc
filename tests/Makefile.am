include $(top_srcdir)/common.mk

TESTS = \
    check_wrapalloc \
    test_wrapalloc.sh$(EXEEXT)

check_PROGRAMS = check_wrapalloc test_wrapalloc

check_SCRIPTS = test_wrapalloc.sh$(EXEEXT)
CLEANFILES = $(check_SCRIPTS)

include_HEADERS = $(top_srcdir)/src/wrap_alloc.h
AM_CPPFLAGS = -I. -I$(top_srcdir)/src

EXTRA_DIST = test_wrapalloc.sh.in

test_wrapalloc.sh$(EXEEXT): test_wrapalloc.sh.in Makefile test_wrapalloc
	sed -e 's|[@]abs_builddir[@]|$(abs_builddir)|g' \
	    -e 's|[@]preload_library[@]|../src/libwrapalloc.la|g' \
	    $< > $@
	chmod +x $@

# Test environment:
# 
# 1) Disable core file production for tests to avoid running out of
#    storage! :-)
# 2) Disable free(3) from actually being called to allow the tests to
#    check the contents of the memory "post-free()" (without getting a
#    SEGV due to invalid memory access :-).
#    XXX: Note that the variable must be exported since check runs the
#    tests in subprocesses.
# 3) Disable (e)glibc's malloc checking.
#
AM_TESTS_ENVIRONMENT = ulimit -c 0; \
                       export WRAP_ALLOC_DISABLE_FREE=1; \
                       export MALLOC_CHECK_=0;

check_wrapalloc_SOURCES = check_wrapalloc.c
test_wrapalloc_SOURCES = test_wrapalloc.c

check_wrapalloc_CFLAGS = @CHECK_CFLAGS@ -g -O0
test_wrapalloc_CFLAGS = @CHECK_CFLAGS@ -g -O0

check_wrapalloc_LDFLAGS = $(all_libraries) $(LIBS) -L$(top_srcdir)/src
test_wrapalloc_LDFLAGS = $(all_libraries) $(LIBS)

check_wrapalloc_LDADD = \
    $(top_builddir)/src/libwrapalloc.la \
    @CHECK_LIBS@ \
    -lm -lpthread -lrt -lwrapalloc

# XXX: Do *NOT* link with the wrapalloc library!
test_wrapalloc_LDADD =
