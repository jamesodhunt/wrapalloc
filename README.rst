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

When the user allocates a block of memory like this::

    char *p = malloc (16);

... what actually happens is::

     +---------+------------+--------+-------------+
     | MCB     | pre-buffer | memory | post-buffer |
     +---------+------------+--------+-------------+
      'memory'              0 ..... 16
         |                  ^
         |                  |
         +------------------^
                            |
                            p

The user is returned the address of a block of the size they specified.
However, we also allocate a pre- and post- buffer or "margin" either
side and immediately adjacent to the chunk of space requested.

Immediately before the pre-buffer is the MCB or MemoryCtlBlock, a
control block used for recording information about the allocation and
buffers/margins. The MCB has a 'memory' element that points at the
address returned to the user.

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

Make sure you disable all glibc/glib memory checkers by setting the
following prior to running the application you want `wrapalloc` to
check::

    # disable (e)glibc checking
    export MALLOC_CHECK_=0

    # disable glib checking
    export G_DEBUG=gc-friendly,resident-modules
    export G_SLICE=always-malloc

Footnotes
---------

.. [#linker-trick]

   The linker trick is "``ld -Wl,--wrap=malloc,--wrap=calloc,--wrap=free ...``".

