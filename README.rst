.. image:: https://travis-ci.org/jamesodhunt/wrapalloc.svg?branch=master
   :target: https://travis-ci.org/jamesodhunt/wrapalloc

.. image:: https://scan.coverity.com/projects/5310/badge.svg
   :target: https://scan.coverity.com/projects/wrapalloc
   :alt: Coverity Scan Build Status

.. image:: https://img.shields.io/badge/license-GPL-3.0.svg

.. image:: https://img.shields.io/badge/donate-flattr-red.svg
   :alt: Donate via flattr
   :target: https://flattr.com/profile/jamesodhunt

=========
wrapalloc
=========

.. contents::
.. sectnum::

Overview
--------

wrapalloc is a tool that intercepts calls to the libc memory
management routines. This allows it:

- perform checks on:

  - *overruns*
    (where the calling program writes beyond the end of the memory it
    has allocated).

  - *underruns*
    (where the calling program writes before the start of
    the memory it has allocated).

- display memory management statistics.
- arrange for memory to be initialised with a particular bit pattern.
- arrange for memory to be returned to the system after first
  overwriting it with a particular bit pattern.

wrapalloc is similar to ``dmalloc(1)`` and ``electric-fence(efence(3))``,
but it's lighter-weight (and less clever).

Design
------

When the user allocates a block of say 16 bytes of memory like this::

    char *p = malloc (16);

... what actually happens is::

     +---------+------------+--------+-------------+
     | MCB     | pre-buffer | memory | post-buffer |
     +---------+------------+--------+-------------+
      .memory               0 ..... 15            
         |     ^            ^                      ^
         |     |            |                      |
         +-----|------------^                      |
               |            |                      |
      .begin --+            p                      |
                                                   |
      .end ----------------------------------------+

      .request_size ------->{________}

      .total_size
          |
     +----+
     V
     {_____________________________________________}


The user is returned the address of a block of the size they specified.
However, we also allocate a pre- and post- buffer or "margin" either
side and immediately adjacent to the chunk of space requested.

Immediately before the pre-buffer is the MCB or "``MemoryCtlBlock``", a
structure used for recording information about the allocation and
buffers/margins. The MCB has a number of elements useful for tracking
the original allocation including:

- ``.memory`` which points to the memory block returned to the user.
- ``.begin`` which points to the start of the pre-buffer.
- ``.end`` which points to the end of the post-buffer.
- ``.request_size`` which records the size of the block of memory the
  user requested.
- ``.total_size`` which records the actual amount of memory allocated
  (requested size + pre-buffer size + post-buffer size + MCB).

If the program either overruns or underruns such that either the pre- or
post-buffers get modified, this is detected both when ``realloc(3)`` is
called, and when ``free(3)`` is called.

The size of the pre- and post-buffers are configurable using environment
variables, either independently::

  export WRAP_ALLOC_PRE_BORDER=<size>
  export WRAP_ALLOC_POST_BORDER=<size>

... or together::

  export WRAP_ALLOC_BORDER=<size>

Where "``<size>``" is a value in bytes. Note that the smaller the
border sizes, the lower the likelihood of detecting buffer over- and
under-runs.

Notes: 

The library is built using a linker trick [#linker-trick]_ to redirect
(interpose) all calls to the standard memory allocation routines with
the internal library versions.

Environment Variables
---------------------

Variables are used to modify the behaviour of this library. Note that
internally, those variables are queried *as late as possible* since
loading all recognised environment variables at library load time is
*NOT* useful since it precludes the caller from being able to modify the
behaviour (since the caller will run after library load time).

See the man page for the complete list of available environment
variables to control the behaviour of this library.

Limitations
-----------

- Won't work correctly for threaded apps (due to simplistic setting of 'caller').

- Although the code handles it, the library cannot be built to use the
  dynamic linker rather than the linker trick since the dynamic linker
  routines allocate memory, resulting in recursive execution followed
  by a crash.

Running
-------

Pre-requisites
~~~~~~~~~~~~~~

Make sure you disable all glibc/glib memory checkers by setting the
following prior to running the application you want `wrapalloc` to
check::

    # disable (e)glibc checking
    export MALLOC_CHECK_=0

    # disable glib checking
    export G_DEBUG=gc-friendly,resident-modules
    export G_SLICE=always-malloc

Playing with the tests
~~~~~~~~~~~~~~~~~~~~~~

Forcing an underrun
...................

Run the test program with ``LD_PRELOAD`` to force a write before the
buffer the test program allocates::

  $ (LD_PRELOAD=$PWD/src/.libs/libwrapalloc.so WRAP_ALLOC_LOGFILE=wrap-alloc.log ./tests/test_wrapalloc underrun)
  $ cat wrap-alloc.log 
  ERROR: underrun - expected fill byte 0x0 got 0x55 (1 byte before
  beginning of user memory 0x7fbc1145f058 of size 6)
  ERROR: damaged pre-border:
  INFO: caught SIGSEGV - aborting

Forcing an overrun
...................

Run the test program with ``LD_PRELOAD`` to force a write beyond the
buffer the test program allocates::

  $ (LD_PRELOAD=$PWD/src/.libs/libwrapalloc.so WRAP_ALLOC_LOGFILE=wrap-alloc.log ./tests/test_wrapalloc overrun)
  $ cat wrap-alloc.log 
  ERROR: overrun - expected fill byte 0x0 got 0x4f (1 byte beyond end of
  user memory 0x7ff19373c058 of size 6)
  ERROR: damaged post-border:
  INFO: caught SIGSEGV - aborting

Show the damaged buffer
~~~~~~~~~~~~~~~~~~~~~~~

By increasing the debug level, you can get a dump of the post buffer to
see exactly how the program has overwritten the memory::

  $ (LD_PRELOAD=$PWD/src/.libs/libwrapalloc.so WRAP_ALLOC_DEBUG=3 WRAP_ALLOC_LOGFILE=wrap-alloc.log WRAP_ALLOC_BORDER=8 ./tests/test_wrapalloc overrun)
  $ cat wrap-alloc.log 
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1036:func=wa_init:DEBUG: --------------------
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1038:func=wa_init:DEBUG: wrap-alloc version 0.1
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1039:func=wa_init:DEBUG: 
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1041:func=wa_init:DEBUG: build date: Jun  1 2015 at 20:17:22
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1043:func=wa_init:DEBUG: build type:
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1050:func=wa_init:DEBUG:   - mmap
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1061:func=wa_init:DEBUG: functions:
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1063:func=wa_init:DEBUG:   __wa_wrap_malloc=0x7fedd9787cbf
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1064:func=wa_init:DEBUG:   __real_malloc=0x7fedd9786310
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1066:func=wa_init:DEBUG:   __wa_wrap_calloc=0x7fedd9787d55
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1067:func=wa_init:DEBUG:   __real_calloc=0x7fedd978632a
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1069:func=wa_init:DEBUG:   __wa_wrap_realloc=0x7fedd9787ded
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1070:func=wa_init:DEBUG:   __real_realloc=0x7fedd978634f
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1079:func=wa_init:DEBUG:   __wa_wrap_free=0x7fedd9787ff5
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1080:func=wa_init:DEBUG:   __real_free=0x7fedd9786374
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1082:func=wa_init:DEBUG:   __cyg_profile_func_enter=0x7fedd94cfd40
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1083:func=wa_init:DEBUG:   __cyg_profile_func_exit=0x7fedd94cfd40
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1085:func=wa_init:DEBUG:   malloc=0x7fedd9786310
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1086:func=wa_init:DEBUG:   calloc=0x7fedd978632a
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1087:func=wa_init:DEBUG:   realloc=0x7fedd978634f
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1088:func=wa_init:DEBUG:   free=0x7fedd9786374
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1091:func=wa_init:DEBUG:    dlopen=0x7fedd91b7030
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1092:func=wa_init:DEBUG:    dlsym=0x7fedd91b7100
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1093:func=wa_init:DEBUG:    dlerror=0x7fedd91b7370
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1094:func=wa_init:DEBUG:    dlclose=0x7fedd91b70a0
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1098:func=wa_init:DEBUG:    mmap=0x7fedd94bb720
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1099:func=wa_init:DEBUG:    munmap=0x7fedd94bb750
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1102:func=wa_init:DEBUG: option settings:
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1104:func=wa_init:DEBUG:   free: enabled
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1107:func=wa_init:DEBUG:   pre buffer size: 8
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1109:func=wa_init:DEBUG:   post buffer size: 8
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1112:func=wa_init:DEBUG:   pre buffer fill byte: 0x0
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1114:func=wa_init:DEBUG:   post buffer fill byte: 0x0
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1115:func=wa_init:DEBUG:   alloc byte: 0x0
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1116:func=wa_init:DEBUG:   free byte: 0x0
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1117:func=wa_init:DEBUG:   debug: 0x3
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1118:func=wa_init:DEBUG: --------------------
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=811:func=__wa_wrap_malloc:DEBUG: caller requested allocation of 6 bytes
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=638:func=__wa_new_mem_block:DEBUG: __wa_new_mem_block called with size=6
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=592:func=wa_show_ctl_block:DEBUG: MemoryCtlBlock=0x7fedd9bac000
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=593:func=wa_show_ctl_block:DEBUG:   pre_border_size=8
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=594:func=wa_show_ctl_block:DEBUG:   post_border_size=8
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=595:func=wa_show_ctl_block:DEBUG:   eye_catcher='WACTLBK'
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=596:func=wa_show_ctl_block:DEBUG:   memory=0x7fedd9bac060
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=597:func=wa_show_ctl_block:DEBUG:   begin=0x7fedd9bac058
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=598:func=wa_show_ctl_block:DEBUG:   end=0x7fedd9bac06e
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=599:func=wa_show_ctl_block:DEBUG:   request_size=6
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=600:func=wa_show_ctl_block:DEBUG:   total_size=110
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=608:func=wa_show_ctl_block:DEBUG:   call_time=1433187315.274992508
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=737:func=__wa_new_mem_block:DEBUG: filling user buffer with alloc byte value 0x0
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=741:func=__wa_new_mem_block:DEBUG: returning m->memory=0x7fedd9bac060
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=947:func=__wa_wrap_free:DEBUG: caller requested freeing of 6 bytes
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=568:func=wa_check_ctl_block:ERROR: overrun - expected fill byte 0x0 got 0x4f (1 byte beyond end of user memory 0x7fedd9bac060 of size 6)
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=570:func=wa_check_ctl_block:ERROR: damaged post-border:
  wrap-alloc:pid=5960:ppid=2928:file=wa_util.c:line=473:func=wa_tohex:DEBUG: 000000: 4f00 0000 0000 0000                      O.......
  wrap-alloc:pid=5960:ppid=2928:file=wrap_alloc.c:line=1334:func=wa_abort:INFO: caught SIGSEGV - aborting

Notes:

- The penultimate line above shows the bogus write - the ``test_wrapalloc`` program writes a "``O``" when requested to perform an over-run.
- The default buffer has been changed to only 8 bytes using the ``WRAP_ALLOC_BORDER`` variable to make the example above clearer.


Running a standard command using ``LD_PRELOAD``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here's an example of running "``sleep 1``" via ``LD_PRELOAD``::

  $ (LD_PRELOAD=$PWD/src/.libs/libwrapalloc.so WRAP_ALLOC_LOGFILE=wrap-alloc.log /bin/sleep 1)

Footnotes
---------

.. [#linker-trick]

   The linker trick is "``ld -Wl,--wrap=malloc,--wrap=calloc,--wrap=free ...``".

