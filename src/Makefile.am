include $(top_srcdir)/common.mk

lib_LTLIBRARIES = libwrapalloc.la

libwrapalloc_la_SOURCES = \
  wrap_alloc.c \
  wa_util.c \
  wa_list.c

libwrapalloc_la_LDFLAGS = \
	$(LIBS) \
	-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=alloca,--wrap=free

include_HEADERS = \
  wrap_alloc.h \
  wa_list.h \
  wa_util.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = wrapalloc-0.1.pc
