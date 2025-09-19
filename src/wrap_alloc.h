/*--------------------------------------------------------------------
 * wrapalloc - memory allocation debugging library header.
 *
 * Copyright (C) 2011-2015 James Hunt <jamesodhunt@gmail.com>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *--------------------------------------------------------------------
 */

#ifndef _WRAP_ALLOC_H
#define _WRAP_ALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_ALLOCA
#include <alloca.h>
#endif

#include <errno.h>
#ifdef USE_MMAP
#include <sys/mman.h>
#endif

#define WA_MAIN
#include <wa_util.h>

#include <wa_list.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#ifdef HAVE_LIBDL

/* XXX: required for RTLD_NEXT - see dlopen(3) */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#define __USE_GNU
#endif

#include <dlfcn.h>

#endif

extern char **environ;

typedef unsigned char byte;
typedef unsigned char bool;

/**
 * MemoryCtlBlock:
 *
 * Object that resides *just before* address of new block of memory
 * allocated at users request.
 *
 */
typedef struct memory_ctl_block
{
    /* Required to be first member of structure by WMList */
    WMList entry;

    /* This would of course normally be the first structure member
     * (but for entry :-)
     */
    char eye_catcher[WA_EYE_CATCHER_LEN];

    /* Address of beginning margin
     * (wa_get_border_size(WA_BUFFER_TYPE_PRE) bytes before 'memory')
     */
    void *begin;

    /* Size of pre buffer */
    //size_t pre_buffer_size;

    /* Address of chunk of memory user has actually asked for */
    void *memory;

    /* Size of post buffer */
    /* FIXME: needed ? */
    //size_t post_buffer_size;

    /* Last byte of end margin */
    void *end;

    /* number of bytes user requested */
    size_t request_size;

    /* number of bytes actually allocated (the MemoryCtlBlock +
     * request_size).
     */
    size_t total_size;

#ifdef USE_INSTRUMENT
    /* function that requested the allocation */
    void *caller;
#endif

    /* time memory was allocated */
    struct timespec call_time;

    /* TRUE if @memory should be considered as freed */
    bool freed;

} MemoryCtlBlock;

enum wa_buffer_type
{
    WA_BUFFER_TYPE_PRE,
    WA_BUFFER_TYPE_POST
};

enum wa_segv_action
{
    WA_SEGV_ABORT,
    WA_SEGV_RAISE_SIGNAL,
    WA_SEGV_SLEEP_AND_ABORT,
    WA_SEGV_EXIT,
};

// ="sleep:20,signal:17"

struct wa_segv_action_details
{
    enum wa_segv_action action;
    long int            value;
};

struct statistics {
    size_t malloc_calls;
    size_t calloc_calls;
    size_t realloc_calls;
    size_t free_calls;

#ifdef HAVE_ALLOCA
    size_t alloca_calls;
#endif

    size_t free_null_calls;
    size_t malloc_zero_calls;

    /* realloc (ptr, 0) */
    size_t realloc_zero_calls;

    /* realloc (NULL, size) */
    size_t realloc_null_calls;

    size_t total_request_bytes_allocated;
    size_t total_bytes_allocated;
    size_t total_bytes_freed;
};

typedef struct address
{
    WMList entry;
    void *address;
} Address;

#endif /* _WRAP_ALLOC_H */
