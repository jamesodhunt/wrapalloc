/*--------------------------------------------------------------------
 * wrapalloc - utility routines header.
 *
 * Copyright (C) 2011-2015 James Hunt <james.hunt@ubuntu.com>.
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

#ifndef _WA_UTIL
#define _WA_UTIL

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE (!TRUE)
#endif

#if (defined WA_MAIN) || defined (WA_TESTS)
#define WA_PRIVATE /*static*/
#else /* ! (WA_MAIN | WA_TESTS) */
#define WA_PRIVATE extern
#endif /* (WA_MAIN | WA_TESTS) */

/********************************************************************/

struct wa_signal_map {
    int    signum;
    char  *signame;
};

extern struct wa_signal_map wa_signal_map[];

/********************************************************************/
/* prototypes */

WA_PRIVATE void *
__attribute ((malloc, warn_unused_result, no_instrument_function, unused))
wa_get_memory (size_t size);

WA_PRIVATE void
wa_signal_handler (int signum);

WA_PRIVATE void
wa_setup_signals (void);

/* assert(3) can call malloc(3), so we have to do the job ourselves */
WA_PRIVATE void
wa_assert_fail (const char *file,
        int line,
        const char *function,
        const char *expr);

WA_PRIVATE void
_wa_log_msg (const char *file,
        int line,
        const char *func,
        const char *fmt, ...)
__attribute ((no_instrument_function));

WA_PRIVATE int
wa_address_valid (void *ptr);

int
wa_address_was_valid (void *ptr);

WA_PRIVATE void
wa_mcb_list_init (void);

WA_PRIVATE void
wa_address_list_init (void);

WA_PRIVATE void
wa_tohex (size_t bytes, const void *data);

WA_PRIVATE int
wa_show_printable (size_t bytes, const void *data, char *buffer);

WA_PRIVATE const char *
wa_signal_num_to_name (int signum);

WA_PRIVATE int
wa_signal_name_to_num (const char *signame);

/**************************************/

#ifdef USE_LD_PRELOAD

WA_PRIVATE void *(*__real_malloc)(size_t);
WA_PRIVATE void *(*__real_calloc)(size_t nmemb, size_t size);
WA_PRIVATE void *(*__real_realloc)(void *ptr, size_t size);
WA_PRIVATE void (*__real_free)(void *ptr);

#ifdef HAVE_ALLOCA
WA_PRIVATE void *(*__real_alloca)(size_t size);
#endif /* HAVE_ALLOCA */

#else /* ! USE_LD_PRELOAD */

extern void *__real_malloc (size_t size);
extern void *__real_calloc (size_t nmemb, size_t size);
extern void *__real_realloc (void *ptr, size_t size);
extern void __real_free (void *ptr);

#ifdef HAVE_ALLOCA
extern void *__real_alloca (size_t size);
#endif /* HAVE_ALLOCA */

#endif /* USE_LD_PRELOAD */

/********************************************************************/

#define APP_NAME    "wrap-alloc"
#define APP_VERSION "0.1"

#define WA_DELIMITER  "--------------------\n"

/* Value that marks an MemoryCtlBlock */
#define WA_EYE_CATCHER      "WACTLBK"

/* Length of EYE_CATCHER */
#define WA_EYE_CATCHER_LEN  (7+1)

/* size of buffer used by logger */
#define WA_BUFSIZE              1024
#define WA_LOG_BUFSIZE         WA_BUFSIZE

#define WA_DEFAULT_BUFFER_SIZE 4096

/* Behave like calloc(3) by default */
#ifndef DEFAULT_FILL_BYTE
  #define DEFAULT_FILL_BYTE  0x0
#endif

#define DEFAULT_ALLOC_FILL_BYTE DEFAULT_FILL_BYTE
#define DEFAULT_FREE_FILL_BYTE  DEFAULT_FILL_BYTE

/********************************************************************/
/* environment variables */

/* Enable debug output if set to any value */
#define WRAP_ALLOC_DEBUG_ENV        "WRAP_ALLOC_DEBUG"

/* Size of border buffer (in bytes) */
#define WRAP_ALLOC_BORDER_ENV   "WRAP_ALLOC_BORDER"

/* Size of pre buffer (in bytes).
 *
 * If not specified, uses WRAP_ALLOC_BORDER_ENV, or if that
 * isn't specified, uses the systems page size (atleast 4k).
 */
#define WRAP_ALLOC_PRE_BORDER_ENV   "WRAP_ALLOC_PRE_BORDER"

/* Size of post buffer (in bytes).
 *
 * If not specified, uses WRAP_ALLOC_BORDER_ENV, or if that
 * isn't specified, uses the systems page size (atleast 4k).
 */
#define WRAP_ALLOC_POST_BORDER_ENV  "WRAP_ALLOC_POST_BORDER"

/* Byte value used to fill pre and post buffers */
#define WRAP_ALLOC_FILL_ENV         "WRAP_ALLOC_FILL"

/* Byte value used to fill pre buffers.
 *
 * If not specified, uses WRAP_ALLOC_FILL_ENV, or if that isn't
 * specified, uses DEFAULT_FILL_BYTE.
 */
#define WRAP_ALLOC_PRE_FILL_ENV     "WRAP_ALLOC_PRE_FILL"

/* Byte value used to fill post buffers.
 *
 * If not specified, uses WRAP_ALLOC_FILL_ENV, or if that isn't
 * specified, uses DEFAULT_FILL_BYTE.
 */
#define WRAP_ALLOC_POST_FILL_ENV    "WRAP_ALLOC_POST_FILL"

/* Byte value use to fill memory area requested by user.
 * If not specified, value will be DEFAULT_ALLOC_FILL_BYTE.
 */
#define WRAP_ALLOC_ALLOC_BYTE_ENV   "WRAP_ALLOC_ALLOC_BYTE"

/* Byte value use to fill memory area requested by user just before
 * memory is passed to free(3).
 * If not specified, value will be DEFAULT_FREE_FILL_BYTE.
 */
#define WRAP_ALLOC_FREE_BYTE_ENV   "WRAP_ALLOC_FREE_BYTE"

/* If set, never free memory */
#define WRAP_ALLOC_DISABLE_FREE_ENV  "WRAP_ALLOC_DISABLE_FREE"

/* FIXME: we don't seem to display the addresses atm? */
/* If set, store all addresses in @address_list to aid in debugging */
#define WRAP_ALLOC_STORE_ALL_ADDRESSES_ENV "WRAP_ALLOC_STORE_ALL_ADDRESSES"

/* If set, install a SIGSEGV handler that will be agressively installed
 * and will pause the process.
 */
#define WRAP_ALLOC_SIGSEGV_HANDLER_ENV "WRAP_ALLOC_SIGSEGV_HANDLER"

#define WRAP_ALLOC_SEGV_ACTION_ENV "WRAP_ALLOC_SEGV_ACTION"

// FIXME: implement
#define WRAP_ALLOC_LOGFILE_ENV "WRAP_ALLOC_LOGFILE"

/********************************************************************/

/* Convert a "user pointer" as returned by (m|c)alloc to a
 * MemoryCtlBlock.
 */
#define wa_ptr_to_mcb(ptr) \
    (MemoryCtlBlock *) \
    ((byte *)ptr \
        - (sizeof (MemoryCtlBlock) \
        + wa_get_border_size (WA_BUFFER_TYPE_PRE)))

#define wa_mcb_to_pre_border(mcb) \
    ((byte *)(mcb)->begin)

#define wa_mcb_to_post_border(mcb) \
    (((byte *)(mcb)->end) - wa_get_border_size (WA_BUFFER_TYPE_POST))

#define wa_assert(expr) \
    ((expr)) \
        ? (void)0 \
        : wa_assert_fail (__FILE__, __LINE__, __func__, #expr)

/* Display an informational message */
#define wa_msg(...) \
    _wa_log_msg (__FILE__, __LINE__, __func__, "INFO: " __VA_ARGS__)

#define wa_warn(...) \
    _wa_log_msg (__FILE__, __LINE__, __func__, "WARNING: " __VA_ARGS__)

/* FIXME */
#if 0
#define wa_debug(...) \
    if (wa_debug_value) \
        _wa_log_msg (__FILE__, __LINE__, __func__, "DEBUG: " __VA_ARGS__)
#endif
#define wa_debug(...) \
    if (getenv (WRAP_ALLOC_DEBUG_ENV)) \
        _wa_log_msg (__FILE__, __LINE__, __func__, "DEBUG: " __VA_ARGS__)

#define wa_err(...) \
    _wa_log_msg (__FILE__, __LINE__, __func__, "ERROR: " __VA_ARGS__)

/* Return TRUE if sufficient data has been processed to display a line
 * of data.
 *
 * bytes: 0-based byte count.
 */
#define WA_HAVE_LINE_TO_DISPLAY(bytes) \
        (((bytes + 1) % WA_BYTES_PER_LINE) == 0)

#define WA_BYTES_PER_LINE 16

#define WA_TOHEX_OUTPUT_AND_CLEAR(buffer, p, ret, byte_count) \
    wa_debug ("%s\n", buffer); \
    memset (buffer, '\0', WA_BUFSIZE); \
    ret = byte_count = 0; \
    p = buffer

#define wa_signal_map_entry(s) \
    {s, #s}

/********************************************************************/

#ifdef USE_INSTRUMENT
/**
 * WA_IGNORE_WRAPPERS:
 *
 * Macro called when instrumenting to ensure we don't trace the wrapper
 * functions created by the linker.
 **/
#define WA_IGNORE_WRAPPERS() \
    if (func ==__wrap_malloc   || \
        func == __wrap_calloc  || \
        func == __wrap_realloc || \
        func == __wrap_alloca  || \
        func == __wrap_free)      \
            return
#endif /* USE_INSTRUMENT */

#endif /* _WA_UTIL */
