#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([wrapalloc], [0.1], [jamesodhunt@ubuntu.com])
AC_CONFIG_SRCDIR([src/wrap_alloc.c])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])


#---------------------------------------------------------------------
# disable default compiler optimisation

: ${CFLAGS=""}

#---------------------------------------------------------------------
# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AR
AC_PROG_LIBTOOL

# Look for C unit test framework (http://check.sourceforge.net/).
AM_PATH_CHECK

#---------------------------------------------------------------------
# Checks for libraries.
AC_CHECK_LIB([dl], [dlsym])

#---------------------------------------------------------------------
# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([limits.h stddef.h stdlib.h string.h syslog.h unistd.h])

#---------------------------------------------------------------------
# Checks for typedefs, structures, and compiler characteristics.

AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T

#---------------------------------------------------------------------
# Checks for library functions.

AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([clock_gettime getpagesize mmap memset munmap strdup strstr strtol alloca])

#---------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/Makefile.am
                 src/wrapalloc-0.1.pc
                 tests/Makefile
                 ])

AC_OUTPUT

#---------------------------------------------------------------------
