/*--------------------------------------------------------------------
 * wrapalloc - memory allocation debugging library.
 *
 * Copyright (C) 2011-2025 James Hunt <jamesodhunt@gmail.com>.
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

#include <wrap_alloc.h>

/********************************************************************/
/* globals */

static struct wa_segv_action_details wa_segv_details = {
    .action = WA_SEGV_ABORT,
    .value = 0,
};

/**
 * wa_orig_sigsegv_handler:
 *
 * Callers original SIGSEGV handler.
 **/
static void (*wa_orig_sigsegv_handler)(int) = NULL;

/**
 * address of last caller of any of the wrapped functions
 *
 * FIXME: this clearly won't work for threaded apps.
 **/
#ifdef USE_INSTRUMENT
static void *wa_caller;
#endif

/**
 * wa_debug_value:
 *
 * Set if caller wants debug output.
 **/
int wa_debug_value = 0;

/**
 * wa_initialized:
 *
 * Set when all setup has been performed.
 **/
static bool wa_initialized = false;

/**
 * wa_mcb_list:
 *
 * Doubly-linked list of MemoryCtlBlock's in use.
 **/
static WMList *wa_mcb_list = NULL;

/**
 * wa_address_list:
 *
 * Doubly-linked list of Addresses that have (ever) been used.
 *
 * We only add to this list as an aide to debugging where a particular
 * address comes from.
 **/
static WMList *wa_address_list = NULL;

/**
 * wa_stats:
 *
 * Statistics structure.
 *
 **/
static struct statistics wa_stats;

/********************************************************************/
/* prototypes */

static void
wa_abort(void);

static int
wa_rate_limit(size_t secs) __attribute__((unused));

static bool
wa_get_number(const char *number, long int *value);

void *__attribute((no_instrument_function))
__wa_wrap_malloc(size_t size);

void *__attribute((no_instrument_function))
__wa_wrap_calloc(size_t nmemb, size_t size);

void *__attribute((no_instrument_function))
__wa_wrap_realloc(void *ptr, size_t size);

void __attribute((no_instrument_function))
__wa_wrap_free(void *ptr);

#if 1
#ifdef HAVE_ALLOCA
void *__attribute((no_instrument_function))
__wa_wrap_alloca(size_t size);
#endif
#endif

#ifdef USE_INSTRUMENT
void __attribute((no_instrument_function))
__cyg_profile_func_enter(void *func, void *call_site);

void __attribute((no_instrument_function))
__cyg_profile_func_exit(void *func, void *call_site);
#endif

static void __attribute__((constructor, no_instrument_function))
wa_init(void);

static void __attribute__((/*destructor*/, no_instrument_function))
wa_finish(void);

/********************************************************************/
/* functions */

void *
malloc(size_t size)
{
    return __wa_wrap_malloc(size);
}

void *
calloc(size_t nmemb, size_t size)
{
    return __wa_wrap_calloc(nmemb, size);
}

void *
realloc(void *ptr, size_t size)
{
    return __wa_wrap_realloc(ptr, size);
}

void
free(void *ptr)
{
    __wa_wrap_free(ptr);
}

#if 0
#ifdef HAVE_ALLOCA
void *
alloca (size_t size)
{
    return __wa_wrap_alloca (size);
}
#endif
#endif

/*
 * wa_get_number:
 *
 * Convert a string representation of a number.
 *
 * Returns: true on success, else false.
 *
 * Accepts numbers in:
 *
 * - decimal.
 * - hex.
 * - octal.
 */
static bool
wa_get_number(const char *number, long int *value)
{
    const char *p = number;
    char *endptr;
    int base = 10;

    wa_assert(number);

    if (strstr(p, "0x") == p) {
        /* hex */
        base = 16;
    } else if (strstr(p, "0o") == p) {
        /* octal */
        base = 8;
    }

    /* Don't bother with error checking since the value
     * returned on error is usable.
     */
    errno = 0;
    *value = strtol(p, &endptr, base);
    if (errno || *endptr) {
        return false;
    }

    return true;
}

/**
 * wa_get_fill_byte:
 *
 * Determine the "fill byte" for @buffer_type.
 *
 * @buffer_type: type of buffer to query fill byte for.
 *
 * Returns: fill byte.
 **/
WA_PRIVATE unsigned char
wa_get_fill_byte(enum wa_buffer_type buffer_type)
{
    char *specific;
    char *default_fill;
    char *use;
    long int value = 0;

    default_fill = getenv(WRAP_ALLOC_FILL_ENV);

    specific =
        getenv(buffer_type == WA_BUFFER_TYPE_PRE ? WRAP_ALLOC_PRE_FILL_ENV
                                                 : WRAP_ALLOC_POST_FILL_ENV);

    use = specific ? specific : default_fill;

    if (use) {
        if (!wa_get_number(use, &value) || value < 0) {
            goto out;
        }

        if (value < CHAR_MIN || value > UCHAR_MAX) {
            goto out;
        }

        return (char)value;
    }

out:
    return DEFAULT_FILL_BYTE;
}

/**
 * wa_get_alloc_fill_byte:
 *
 * Returns the byte that will be used to fill a newly-allocated
 * block of memory before it is returned to the caller.
 **/
WA_PRIVATE unsigned char
wa_get_alloc_fill_byte(void)
{
    char *p;
    long int value;

    if ((p = getenv(WRAP_ALLOC_ALLOC_BYTE_ENV))) {
        if (wa_get_number(p, &value) && value >= CHAR_MIN &&
            value <= UCHAR_MAX) {
            return value;
        } else {
            goto out;
        }
    }

out:
    return (unsigned char)DEFAULT_ALLOC_FILL_BYTE;
}

/**
 * wa_get_free_fill_byte:
 *
 * Returns the byte that will be used to overwrite the memory just prior
 * to calling free(3).
 **/
WA_PRIVATE unsigned char
wa_get_free_fill_byte(void)
{
    char *p;
    long int value;

    if ((p = getenv(WRAP_ALLOC_FREE_BYTE_ENV))) {
        if (wa_get_number(p, &value) && value >= CHAR_MIN &&
            value <= UCHAR_MAX) {
            return value;
        } else {
            goto out;
        }
    }

out:
    return (unsigned char)DEFAULT_FREE_FILL_BYTE;
}

/**
 * wa_get_border_size:
 *
 * Determine size of pre- or post-border.
 *
 * @buffer_type: type of buffer whose size is requested.
 *
 * Returns: size of pre- or post- border (bytes).
 **/
WA_PRIVATE unsigned long
wa_get_border_size(enum wa_buffer_type buffer_type)
{
    char *p;
    long value;

    p = getenv(buffer_type == WA_BUFFER_TYPE_PRE ? WRAP_ALLOC_PRE_BORDER_ENV
                                                 : WRAP_ALLOC_POST_BORDER_ENV);

    if (!p) {
        p = getenv(WRAP_ALLOC_BORDER_ENV);
    }

    if (p && *p) {
        char *endptr;

        errno = 0;
        value = strtol(p, &endptr, 10);
        if (errno || *endptr) {
            return WA_DEFAULT_BUFFER_SIZE;
        } else {
            goto out;
        }
    }

    value = sysconf(_SC_PAGESIZE);

out:
    return value > 0 ? value : WA_DEFAULT_BUFFER_SIZE;
}

/**
 * wa_get_segv_action:
 *
 * Determine what action should be taken on error.
 *
 **/
WA_PRIVATE void
wa_get_segv_action(void)
{
    char *e;
    char *p;
    char signal_tag[] = "signal:";
    char exit_tag[] = "exit:";
    char sleep_tag[] = "sleep:";
    char crash_tag[] = "abort";
    int default_signal = SIGABRT;

    e = getenv(WRAP_ALLOC_SEGV_ACTION_ENV);
    if (!e || !*e) {
        return;
    }

    if (strstr(e, signal_tag) == e) {
        wa_segv_details.action = WA_SEGV_RAISE_SIGNAL;

        p = e + strlen(signal_tag);
        if (p && *p) {
            if (isdigit(*p)) {
                /* numeric signal number */
                if (!wa_get_number(p, &wa_segv_details.value) ||
                    wa_segv_details.value < 0) {
                    wa_segv_details.value = default_signal;
                }
            } else {
                /* symbolic signal name */
                wa_segv_details.value = wa_signal_name_to_num(p);
                if (wa_segv_details.value < 0) {
                    wa_segv_details.value = default_signal;
                }
            }

            // FIXME
            printf("FIXME:%s:%d: wa_segv_details: action=%d, value=%d\n",
                   __func__,
                   __LINE__,
                   (int)wa_segv_details.action,
                   (int)wa_segv_details.value);
            fflush(NULL);

        } else {
            wa_segv_details.value = default_signal;
        }
    } else if (strstr(e, exit_tag) == e) {
        wa_segv_details.action = WA_SEGV_EXIT;

        p = e + strlen(exit_tag);
        if (p && *p) {
            if (!wa_get_number(p, &wa_segv_details.value) ||
                wa_segv_details.value < 0 || wa_segv_details.value > 255) {
                wa_segv_details.value = 255;
            }
        } else {
            wa_segv_details.value = EXIT_FAILURE;
        }
    } else if (strstr(e, sleep_tag) == e) {
        wa_segv_details.action = WA_SEGV_SLEEP_AND_ABORT;

        p = e + strlen(sleep_tag);
        if (p && *p) {
            if (!wa_get_number(p, &wa_segv_details.value) ||
                wa_segv_details.value < 0) {
                wa_segv_details.value = 0;
            }
        }
    } else if (!strcmp(e, crash_tag)) {
        wa_segv_details.action = WA_SEGV_ABORT;
    }
}

/**
 * wa_show_unfreed:
 *
 * Display details of unfreed blocks of memory
 * (those still on the wa_mcb_list).
 **/
static void
wa_show_unfreed(void)
{
    if (WA_LIST_EMPTY(wa_mcb_list)) {
        wa_debug("No unfreed memory detected\n");
        return;
    }

    WA_LIST_FOREACH(wa_mcb_list, iter)
    {
        MemoryCtlBlock *m = (MemoryCtlBlock *)iter;
        wa_debug("Memory at address %p of size %lu not freed\n",
                 m->memory,
                 m->request_size);
    }
}

/**
 * wa_show_stats:
 *
 * Display some basic statistics.
 **/
static void
wa_show_stats(void)
{
    wa_debug(WA_DELIMITER);
    wa_debug("statistics:\n");
    wa_debug("  malloc calls          : %lu\n",
             (unsigned long int)wa_stats.malloc_calls);
    wa_debug("  calloc calls          : %lu\n",
             (unsigned long int)wa_stats.calloc_calls);
    wa_debug("  realloc calls         : %lu\n",
             (unsigned long int)wa_stats.realloc_calls);
    wa_debug("  free calls            : %lu\n",
             (unsigned long int)wa_stats.free_calls);
#if 0
#ifdef HAVE_ALLOCA
    wa_debug ("  alloca calls          : %lu\n", (unsigned long int)wa_stats.alloca_calls);
#endif
#endif
    wa_debug("  malloc zero calls     : %lu\n",
             (unsigned long int)wa_stats.malloc_zero_calls);
    wa_debug("  free zero calls       : %lu\n",
             (unsigned long int)wa_stats.free_null_calls);
    wa_debug("  realloc zero calls    : %lu\n",
             (unsigned long int)wa_stats.realloc_zero_calls);
    wa_debug("  realloc NULL calls    : %lu\n",
             (unsigned long int)wa_stats.realloc_null_calls);

    wa_debug("  total bytes allocated : %lu\n",
             (unsigned long int)wa_stats.total_bytes_allocated);
    wa_debug("  total bytes freed     : %lu\n",
             (unsigned long int)wa_stats.total_bytes_freed);
    wa_debug(WA_DELIMITER);
}

/**
 * wa_check_ctl_block:
 *
 * Perform all possible checks on an MCB.
 *
 * All errors are fatal.
 **/
WA_PRIVATE void __attribute((no_instrument_function))
wa_check_ctl_block(const MemoryCtlBlock *m)
{
    byte *p;
    size_t count;
    byte fill_byte;

    /* Where the underrun/overrun was found in relation to m->memory */
    size_t offset;

    unsigned long pre_border;
    unsigned long post_border;

    wa_assert(m);
    wa_assert(&m->entry);

    wa_assert(m->begin);
    wa_assert(m->memory);
    wa_assert(m->end);
    wa_assert(m->request_size);

    pre_border = wa_get_border_size(WA_BUFFER_TYPE_PRE);
    post_border = wa_get_border_size(WA_BUFFER_TYPE_POST);

    wa_assert(m->total_size == (sizeof(MemoryCtlBlock) + m->request_size +
                                pre_border + post_border));

    wa_assert(!memcmp(m->eye_catcher, WA_EYE_CATCHER, strlen(WA_EYE_CATCHER)));

    /* XXX: note the 'byte *' conversions to ensure we're counting in the
     * correct units! */

    /* course sanity checks */
    wa_assert((byte *)m < (byte *)m->begin);
    wa_assert((byte *)m < (byte *)m->memory);
    wa_assert((byte *)m < (byte *)m->end);
    wa_assert(m->begin < m->memory);
    wa_assert(m->memory < m->end);

    /* precise checks (relative to the allocated memory) */
    wa_assert(m->begin == (((byte *)m->memory) - pre_border));
    wa_assert(m->end == (((byte *)m->memory) + m->request_size + post_border));
    wa_assert((byte *)m ==
              (((byte *)m->memory) - pre_border - sizeof(MemoryCtlBlock)));

    /* precise checks (relative to the MCB) */
    wa_assert(m->begin == ((byte *)m + sizeof(MemoryCtlBlock)));
    wa_assert(m->end == ((byte *)m + sizeof(MemoryCtlBlock) + pre_border +
                         m->request_size + post_border));
    wa_assert(m->memory ==
              ((byte *)m + (sizeof(MemoryCtlBlock) + pre_border)));

#ifdef USE_INSTRUMENT
    wa_assert(m->caller);
#endif

    fill_byte = wa_get_fill_byte(WA_BUFFER_TYPE_PRE);

    /* Check for caller underruns */
    p = wa_mcb_to_pre_border(m);
    wa_assert(p);

    for (count = 0; count < pre_border; count++, p++) {
        if (*p != fill_byte) {
            offset = (byte *)m->memory - p;

            wa_err("underrun - expected fill byte 0x%x got 0x%x"
                   " (%lu byte%s before beginning of user memory %p of size "
                   "%lu)\n",
                   fill_byte,
                   *p,
                   offset,
                   offset > 1 ? "s" : "",
                   m->memory,
                   (unsigned long int)m->request_size);

            wa_err("damaged pre-border:\n");
            wa_tohex(pre_border, m->begin);

            wa_abort();
        }
    }

    fill_byte = wa_get_fill_byte(WA_BUFFER_TYPE_POST);

    /* Check for caller overruns */
    p = wa_mcb_to_post_border(m);

    for (count = 0; count < post_border; count++, p++) {
        if (*p != fill_byte) {
            offset = 1 + (unsigned long int)count;

            wa_err("overrun - expected fill byte 0x%x got 0x%x"
                   " (%lu byte%s beyond end of user memory %p of size %lu)\n",
                   fill_byte,
                   *p,
                   offset,
                   offset > 1 ? "s" : "",
                   m->memory,
                   (unsigned long int)m->request_size);

            wa_err("damaged post-border:\n");
            wa_tohex(post_border, (byte *)m->memory + m->request_size);

            wa_abort();
        }
    }
}

/**
 * wa_show_ctl_block:
 *
 * Display the contents of the MCB to stderr.
 **/
static void __attribute((no_instrument_function))
wa_show_ctl_block(const MemoryCtlBlock *m)
{
    wa_assert(m);

    if (!wa_debug_value) {
        return;
    }

    wa_debug("MemoryCtlBlock=%p\n", (void *)m);
    wa_debug("  pre_border_size=%lu\n",
             wa_get_border_size(WA_BUFFER_TYPE_PRE));
    wa_debug("  post_border_size=%lu\n",
             wa_get_border_size(WA_BUFFER_TYPE_POST));
    wa_debug("  eye_catcher='%*.*s'\n",
             strlen(WA_EYE_CATCHER),
             strlen(WA_EYE_CATCHER),
             m->eye_catcher);
    wa_debug("  memory=%p\n", (void *)m->memory);
    wa_debug("  begin=%p\n", (void *)m->begin);
    wa_debug("  end=%p\n", (void *)m->end);
    wa_debug("  request_size=%d\n", m->request_size);
    wa_debug("  total_size=%d\n", m->total_size);

#ifdef USE_INSTRUMENT
    wa_debug("  caller=%p\n", m->caller);
#endif

    wa_debug("  call_time=%lu.%lu\n",
             m->call_time.tv_sec,
             m->call_time.tv_nsec);
}

/**
 * __wa_new_mem_block:
 *
 * @size: size of memory block requested by user (for example using
 * malloc(3)).
 *
 * Allocate a new memory block comprising:
 *
 * - an MCB
 * - a pre-border
 * - a block of memory requested by the user.
 * - a post-border
 *
 * Returns: Pointer to address of memory requested by the user,
 * or NULL on error.
 **/
static void *__attribute((no_instrument_function))
__wa_new_mem_block(size_t size)
{
    size_t total_size;
    void *v = NULL;
    MemoryCtlBlock *m = NULL;
    byte fill_byte;

    if (wa_debug_value > 1) {
        wa_debug("%s called with size=%lu\n",
                 __func__,
                 (unsigned long int)size);
    }

    wa_mcb_list_init();
    wa_address_list_init();

    /* XXX: call each time to ensure our handler gets called */
    if (getenv(WRAP_ALLOC_SIGSEGV_HANDLER_ENV)) {
        wa_setup_signals();
    }

#ifdef USE_INSTRUMENT
    wa_debug("%s: last_function=%p\n",
             __func__,
             (unsigned long int *)wa_caller);
#endif

#if 0
    if (! size)
        return NULL;
#endif

    total_size = sizeof(MemoryCtlBlock) +
                 wa_get_border_size(WA_BUFFER_TYPE_PRE) + size +
                 wa_get_border_size(WA_BUFFER_TYPE_POST);

    v = wa_get_memory(total_size);

    if (!v) {
        return NULL;
    }

    m = (MemoryCtlBlock *)v;

    wa_list_init(&m->entry);

    memcpy(m->eye_catcher, WA_EYE_CATCHER, strlen(WA_EYE_CATCHER));
    m->request_size = size;
    m->total_size = total_size;
    m->begin = (void *)((byte *)m + sizeof(MemoryCtlBlock));
    m->end = (void *)((byte *)m + m->total_size);
    m->memory =
        (void *)((byte *)m->begin + wa_get_border_size(WA_BUFFER_TYPE_PRE));
#ifdef USE_INSTRUMENT
    m->caller = wa_caller;
#endif
    clock_gettime(CLOCK_REALTIME, &m->call_time);

    wa_assert(m->begin);

    fill_byte = wa_get_fill_byte(WA_BUFFER_TYPE_PRE);

    memset(m->begin, fill_byte, wa_get_border_size(WA_BUFFER_TYPE_PRE));

    fill_byte = wa_get_fill_byte(WA_BUFFER_TYPE_POST);

    memset((byte *)m->end - wa_get_border_size(WA_BUFFER_TYPE_POST),
           fill_byte,
           wa_get_border_size(WA_BUFFER_TYPE_POST));

    wa_list_add(wa_mcb_list, &m->entry);

    if (getenv(WRAP_ALLOC_STORE_ALL_ADDRESSES_ENV)) {
        Address *addr = NULL;

        addr = wa_get_memory(sizeof(Address));
        wa_assert(addr);
        wa_assert(m->memory);

        wa_list_init(&addr->entry);
        addr->address = m->memory;

        wa_list_add(wa_address_list, &addr->entry);
    }

#if 0
    /* FIXME: can't use mprotect unless amount of memory allocated is
     * aligned to a page boundary
     */
#ifdef HAVE_MMAP
    ret = mprotect (m->begin, wa_get_border_size (WA_BUFFER_TYPE_PRE), PROT_NONE);
    if (ret != 0)
    {
        fprintf (stderr, "mprotect failed - errno=%d\n", errno);
    }

    wa_assert (ret == 0);
    ret = mprotect (m->end - wa_get_border_size (WA_BUFFER_TYPE_POST), wa_get_border_size (WA_BUFFER_TYPE_POST), PROT_NONE);
    if (ret != 0)
    {
        fprintf (stderr, "mprotect failed - errno=%d\n", errno);
    }
    wa_assert (ret == 0);
#endif
#endif

    wa_check_ctl_block(m);

    if (wa_debug_value > 1) {
        wa_show_ctl_block(m);
    }

    fill_byte = wa_get_alloc_fill_byte();
    wa_debug("filling user buffer with alloc byte value 0x%x\n", fill_byte);
    memset(m->memory, fill_byte, m->request_size);

    if (wa_debug_value > 1) {
        wa_debug("returning m->memory=%p\n", m->memory);
    }

    wa_stats.total_request_bytes_allocated += m->request_size;
    wa_stats.total_bytes_allocated += m->total_size;

    return m->memory;
}

/**
 * __wa_free_mem_block:
 *
 * @memory: address of memory to free,
 * @length: Number of bytes in block.
 *
 * Free the memory block specified.
 *
 * Returns zero on success, < 0 on error.
 **/
static int __attribute((no_instrument_function))
__wa_free_mem_block(void *memory, size_t length)
{
    byte fill_byte;

    wa_assert(memory);
    wa_assert(length);

    wa_mcb_list_init();
    wa_address_list_init();

    fill_byte = wa_get_free_fill_byte();

    if (wa_debug_value > 1) {
        wa_debug("filling user buffer with free byte value 0x%x\n", fill_byte);
    }

    memset(memory, fill_byte, length);

    if (getenv(WRAP_ALLOC_DISABLE_FREE_ENV)) {
        if (wa_debug_value > 1) {
            wa_debug("not calling free(3) at user request\n");
        }
        return 0;
    }

    wa_stats.total_bytes_freed += length;

#ifdef HAVE_MMAP
    return munmap(memory, length);
#else
    __real_free(memory);

    /* free(3) doesn't return a value, but we need one (for parity with
     * the munmap(2) codepath).
     */
    return 0;
#endif
}

void *__attribute((no_instrument_function))
__wa_wrap_malloc(size_t size)
{
    wa_stats.malloc_calls++;

    if (!size) {
        wa_stats.malloc_zero_calls++;
        return NULL;
    }

    if (wa_debug_value > 2) {
        wa_debug("caller requested allocation of %lu bytes\n",
                 (unsigned long int)size);
    }

    return __wa_new_mem_block(size);
}

void *__attribute((no_instrument_function))
__wa_wrap_calloc(size_t nmemb, size_t size)
{
    wa_stats.calloc_calls++;

    if (wa_debug_value > 2) {
        wa_debug("caller requested allocation of %ld members of size %lu "
                 "bytes (total=%lu)\n",
                 (unsigned long int)nmemb,
                 (unsigned long int)size,
                 (unsigned long int)nmemb * size);
    }
    return __wa_new_mem_block(nmemb * size);
}

void *__attribute((no_instrument_function))
__wa_wrap_realloc(void *ptr, size_t size)
{
    MemoryCtlBlock *old, *new;

    wa_stats.realloc_calls++;

    /* XXX: We got passed a pointer to memory obtained via an
     * alternative allocator.
     */
    if (ptr && !wa_address_valid(ptr)) {
        return __real_realloc(ptr, size);
    }

    /* Call is now equivalent to malloc(3) - see realloc(3). */
    if (!ptr) {
        wa_stats.realloc_null_calls++;
        if (wa_debug_value > 2) {
            wa_debug("caller requested memory of size %ld bytes\n", size);
        }

        return __wa_wrap_malloc(size);
    }

    /* Call is now equivalent to free(3) - see realloc(3). */
    if (!size) {
        wa_stats.realloc_zero_calls++;

        __wa_wrap_free(ptr);
        return NULL;
    }

    old = wa_ptr_to_mcb(ptr);
    wa_assert(old);

    wa_check_ctl_block(old);

    if (wa_debug_value > 2) {
        wa_debug("caller requested changing size of memory block from %ld to "
                 "%ld bytes\n",
                 old->request_size,
                 size);
    }

    if (size == old->request_size) {
        /* No change */
        return ptr;
    }

    new = __wa_new_mem_block(size);

    if (!new) {
        return NULL;
    }

    /* Retain as much of the old memory contents as possible */
    memcpy(new,
           old->memory,
           size > old->request_size ? old->request_size : size);

    /* Tidy up */
    __wa_wrap_free(ptr);

    return new;
}

#if 0
#ifdef HAVE_ALLOCA
void *
__attribute ((no_instrument_function))
__wa_wrap_alloca (size_t size)
{
    wa_stats.alloca_calls++;
    return __wa_new_mem_block (size);
}
#endif
#endif

void __attribute((no_instrument_function))
__wa_wrap_free(void *ptr)
{
    MemoryCtlBlock *m;

    /* Sigh... so many apps call free(0). */
    if (!ptr) {
        wa_stats.free_null_calls++;
        return;
    }

    wa_stats.free_calls++;

#ifdef USE_INSTRUMENT
    wa_debug("%s: last_function=%p\n",
             __func__,
             (unsigned long int *)wa_caller);
#endif

    /* XXX: We got passed a pointer to memory obtained via an
     * alternative allocator.
     */
    if (!wa_address_valid(ptr)) {
        /* address isn't known to us, so just pass the call through to
         * free(3).
         */
        if (getenv(WRAP_ALLOC_DISABLE_FREE_ENV)) {
            wa_debug("not calling free at user request\n");
            return;
        }

        __real_free(ptr);
        return;
    }

    m = wa_ptr_to_mcb(ptr);
    wa_assert(m);

    if (wa_debug_value > 2) {
        wa_debug("caller requested freeing of %ld bytes\n", m->request_size);
    }

    wa_check_ctl_block(m);
    if (wa_debug_value > 1) {
        wa_show_ctl_block(m);

        wa_debug("%s called with %p. actually freeing %p\n",
                 __func__,
                 ptr,
                 (void *)m);
    }

    wa_list_remove(&m->entry);

    /* Consider the memory as unusable now */
    m->freed = true;

    if (__wa_free_mem_block(m, m->total_size) != 0) {
        wa_warn("failed to free memory block\n");
    }
}

#ifdef USE_INSTRUMENT
/* XXX: note that this function cannot be static */
void __attribute((no_instrument_function))
__cyg_profile_func_enter(void *func, void *call_site)
{
    WA_IGNORE_WRAPPERS();
    wa_caller = func;

    wa_debug("%s: func=%p, call_site=%p, last_function=%p\n",
             __func__,
             func,
             call_site,
             wa_caller);
}

/* XXX: note that this function cannot be static */
void __attribute((no_instrument_function))
__cyg_profile_func_exit(void *func, void *call_site)
{
    WA_IGNORE_WRAPPERS();
    wa_caller = func;

    wa_debug("%s: func=%p, call_site=%p, last_function=%p\n",
             __func__,
             func,
             call_site,
             wa_caller);
}
#endif

WA_PRIVATE void
wa_mcb_list_init(void)
{
    if (!wa_mcb_list) {
        wa_mcb_list = wa_list_new();
    }

    wa_assert(wa_mcb_list);
}

WA_PRIVATE void
wa_address_list_init(void)
{
    if (!wa_address_list) {
        wa_address_list = wa_list_new();
    }

    wa_assert(wa_address_list);
}

/**
 * wa_init:
 *
 * Setup.
 *
 **/
static void __attribute__((constructor, no_instrument_function))
wa_init(void)
{
    char *p;
    long int value;

    if (wa_initialized) {
        return;
    }

    wa_mcb_list_init();

    if ((p = getenv(WRAP_ALLOC_DEBUG_ENV))) {
        if (wa_get_number(p, &value) && value >= CHAR_MIN &&
            value <= UCHAR_MAX) {
            wa_debug_value = value;
        }
    }

    if (getenv(WRAP_ALLOC_DEBUG_ENV)) {
        wa_debug(WA_DELIMITER);
    }

    wa_debug("%s version %s\n", APP_NAME, APP_VERSION);
    wa_debug("\n");
    wa_debug("build date: %s at %s\n", __DATE__, __TIME__);

    wa_debug("build type:\n");

#if defined USE_LD_PRELOAD
    wa_debug("  - LD_PRELOAD\n");
#endif

#ifdef HAVE_MMAP
    wa_debug("  - mmap\n");
#endif

#ifdef USE_INSTRUMENT
    wa_debug("  - instrumentation enabled\n");
#endif

#if !defined(USE_LD_PRELOAD) && !defined(HAVE_MMAP)
    wa_debug("  - default\n");
#endif

    wa_debug("functions:\n");

    wa_debug("  __wa_wrap_malloc=%p\n", __wa_wrap_malloc);
    wa_debug("  __real_malloc=%p\n", __real_malloc);

    wa_debug("  __wa_wrap_calloc=%p\n", __wa_wrap_calloc);
    wa_debug("  __real_calloc=%p\n", __real_calloc);

    wa_debug("  __wa_wrap_realloc=%p\n", __wa_wrap_realloc);
    wa_debug("  __real_realloc=%p\n", __real_realloc);

#if 0
#ifdef HAVE_ALLOCA
    wa_debug ("  __wa_wrap_alloca=%p\n", __wa_wrap_alloca);
    wa_debug ("  __real_alloca=%p\n", __real_alloca);
#endif /* HAVE_ALLOCA */
#endif

    wa_debug("  __wa_wrap_free=%p\n", __wa_wrap_free);
    wa_debug("  __real_free=%p\n", __real_free);

#ifdef USE_INSTRUMENT
    wa_debug("  __cyg_profile_func_enter=%p\n", __cyg_profile_func_enter);
    wa_debug("  __cyg_profile_func_exit=%p\n", __cyg_profile_func_exit);
#endif

    wa_debug("  malloc=%p\n", malloc);
    wa_debug("  calloc=%p\n", calloc);
    wa_debug("  realloc=%p\n", realloc);
    wa_debug("  free=%p\n", free);

#ifdef HAVE_LIBDL
    wa_debug("   dlopen=%p\n", dlopen);
    wa_debug("   dlsym=%p\n", dlsym);
    wa_debug("   dlerror=%p\n", dlerror);
    wa_debug("   dlclose=%p\n", dlclose);
#endif

#ifdef HAVE_MMAP
    wa_debug("   mmap=%p\n", mmap);
    wa_debug("   munmap=%p\n", munmap);
#endif

    wa_debug("option settings:\n");
    wa_debug("  free: %sabled\n",
             getenv(WRAP_ALLOC_DISABLE_FREE_ENV) ? "dis" : "en");

    wa_debug("  pre buffer size: %lu\n",
             wa_get_border_size(WA_BUFFER_TYPE_PRE));
    wa_debug("  post buffer size: %lu\n",
             wa_get_border_size(WA_BUFFER_TYPE_POST));

    wa_debug("  pre buffer fill byte: 0x%x\n",
             wa_get_fill_byte(WA_BUFFER_TYPE_PRE));
    wa_debug("  post buffer fill byte: 0x%x\n",
             wa_get_fill_byte(WA_BUFFER_TYPE_POST));
    wa_debug("  alloc byte: 0x%x\n", wa_get_alloc_fill_byte());
    wa_debug("  free byte: 0x%x\n", wa_get_free_fill_byte());
    wa_debug("  debug: 0x%x\n", wa_debug_value);
    wa_debug(WA_DELIMITER);

#ifdef USE_LD_PRELOAD
    /* BUG: we can't actually make use of the real routines since
     * dlsym(3) calls calloc(3)!
     *
     * XXX: Note the horrid casts that are required when compiling with
     * "-pedantic": it's legal to convert a "void *" to an integer (or int
     *  pointer), and any integer can then be converted to "any pointer".
     */
    __real_calloc =
        (void *(*)(size_t, size_t))(intptr_t)dlsym(RTLD_NEXT, "calloc");
    if (!__real_calloc) {
        wa_err("cannot find real calloc %s\n", dlerror());
    }

    __real_malloc = (void *(*)(size_t))(intptr_t)dlsym(RTLD_NEXT, "malloc");
    if (!__real_malloc) {
        wa_err("cannot find real malloc %s\n", dlerror());
    }

    __real_realloc =
        (void *(*)(void *, size_t))(intptr_t)dlsym(RTLD_NEXT, "realloc");
    if (!__real_realloc) {
        wa_err("cannot find real realloc %s\n", dlerror());
    }

    __real_free = (void (*)(void *))(intptr_t)dlsym(RTLD_NEXT, "free");
    if (!__real_free) {
        wa_err("cannot find real free %s\n", dlerror());
    }

#if 0
#ifdef HAVE_ALLOCA
    __real_alloca = (void *(*)(size_t))(intptr_t)dlsym (RTLD_NEXT, "alloca");
    if (!__real_alloca)
        wa_err ("cannot find real alloca %s\n", dlerror ());
#endif
#endif

#endif

    /* We'd like to just rely on malloc_finish(), but that doesn't work
     * for the LD_PRELOAD scenario.
     */
    // FIXME
    atexit(wa_finish);

    if (getenv(WRAP_ALLOC_SIGSEGV_HANDLER_ENV)) {
        wa_setup_signals();
    }

    wa_initialized = true;
}

static void __attribute__((/*destructor*/, no_instrument_function))
wa_finish(void)
{
    wa_show_stats();
    wa_show_unfreed();
}

/**
 * Return 1 if time changed by secs seconds, else 0.
 *
 * This allow you to something like:
 *
 * if (wa_rate_limit(2)) printf("value=%d\n", value);
 *
 * ...which will print value at most once every 2 seconds.
 **/
static int
wa_rate_limit(size_t secs)
{
    static int initialized = 0;

    /* Used to hold the time this function was last called */
    static time_t wa_rate_limit_prev_time = 0;

    time_t now;

    if (!initialized) {
        wa_rate_limit_prev_time = time(NULL);
        initialized = 1;
    }

    now = time(NULL);

    if ((size_t)(now - wa_rate_limit_prev_time) >= secs) {
        wa_rate_limit_prev_time = now;
        return 1;
    }

    return 0;
}

/**
 * wa_address_valid:
 *
 * @ptr: Address of user-requested memory to check.
 *
 * Determine if @ptr refers to a memory address we created (in other
 * words one which has an associated MemoryCtlBlock).
 *
 * Returns: true if @ptr is known, else false.
 **/
bool
wa_address_valid(void *ptr)
{
    if (!ptr) {
        return false;
    }

    wa_mcb_list_init();

    WA_LIST_FOREACH(wa_mcb_list, iter)
    {
        MemoryCtlBlock *m = (MemoryCtlBlock *)iter;

        if (m->memory == ptr) {
            return true;
        }
    }

    return false;
}

// FIXME: signum unused.
void
wa_signal_handler(int signum)
{
    wa_abort();
}

void
wa_setup_signals(void)
{
    void (*handler)(int);

    handler = signal(SIGSEGV, wa_signal_handler);

    if (handler == SIG_ERR) {
        wa_warn("failed to register SIGSEGV handler\n");
        return;
    }

    if (wa_debug_value > 1) {
        wa_debug("registered SIGSEGV handler\n");
    }

    /* Save callers handler */
    if (handler && handler != wa_signal_handler &&
        handler != wa_orig_sigsegv_handler) {
        /* FIXME: not used */
        wa_orig_sigsegv_handler = handler;
    }
}

/**
 * Perform an appropriate action on failure.
 **/
static void
wa_abort(void)
{
    wa_get_segv_action();

    switch (wa_segv_details.action) {

        case WA_SEGV_RAISE_SIGNAL:
        {
            const char *name;

            name = wa_signal_num_to_name(wa_segv_details.value);

            wa_msg("caught SIGSEGV - raising signal %d (%s)\n",
                   (int)wa_segv_details.value,
                   name ? name : "<<UNKNOWN>>");
            fflush(NULL);

            raise(wa_segv_details.value);
        } break;

        case WA_SEGV_EXIT:
            wa_msg("caught SIGSEGV - exiting with value %d\n",
                   (int)wa_segv_details.value);
            fflush(NULL);

            exit(wa_segv_details.value);
            break;

        case WA_SEGV_SLEEP_AND_ABORT:
            wa_msg(
                "caught SIGSEGV - sleeping for %d seconds before aborting\n",
                (int)wa_segv_details.value);
            fflush(NULL);

            sleep(wa_segv_details.value);

            abort();
            break;

        default:
            wa_msg("caught SIGSEGV - aborting\n");
            fflush(NULL);

            abort();
            break;
    }
}
