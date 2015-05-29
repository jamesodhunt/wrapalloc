/*--------------------------------------------------------------------
 * wrapalloc - utility routines.
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

/* For asprintf(3) */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <wrap_alloc.h>
#include <wa_util.h>

#if HAVE_CONFIG_H
#include <config.h>
#endif

extern int wa_debug_value;

static int wa_have_performed_setup = FALSE;

WA_PRIVATE char wa_hexmap[] = "0123456789abcdef";

struct wa_signal_map wa_signal_map[] = {

    wa_signal_map_entry (SIGABRT),
    wa_signal_map_entry (SIGALRM),
    wa_signal_map_entry (SIGBUS),

    { SIGCHLD, "SIGCLD" },
    { SIGCHLD, "SIGCHLD" },

    wa_signal_map_entry (SIGCONT),
    wa_signal_map_entry (SIGFPE),
    wa_signal_map_entry (SIGHUP),
    wa_signal_map_entry (SIGILL),
    wa_signal_map_entry (SIGINT),
    wa_signal_map_entry (SIGKILL),
    wa_signal_map_entry (SIGPIPE),
    wa_signal_map_entry (SIGQUIT),
    wa_signal_map_entry (SIGSEGV),
    wa_signal_map_entry (SIGSTOP),
    wa_signal_map_entry (SIGTERM),
    wa_signal_map_entry (SIGTRAP),
    wa_signal_map_entry (SIGTSTP),
    wa_signal_map_entry (SIGTTIN),
    wa_signal_map_entry (SIGTTOU),
    wa_signal_map_entry (SIGUSR1),
    wa_signal_map_entry (SIGUSR2),
    wa_signal_map_entry (SIGIO),
    wa_signal_map_entry (SIGIOT),

#ifdef linux
    /* synonym of SIGIO */
    {SIGPOLL, "SIGPOLL" },
#endif

    wa_signal_map_entry (SIGPROF),

#ifdef linux
    wa_signal_map_entry (SIGPWR),
    wa_signal_map_entry (SIGSTKFLT),
#endif

    wa_signal_map_entry (SIGSYS),

#ifdef linux
    wa_signal_map_entry (SIGUNUSED),
#endif
    wa_signal_map_entry (SIGURG),
    wa_signal_map_entry (SIGVTALRM),
    wa_signal_map_entry (SIGWINCH),
    wa_signal_map_entry (SIGXCPU),
    wa_signal_map_entry (SIGXFSZ),

    /* terminator */
    { 0, NULL }
};

static void
wa_perform_setup (void)
{
    wa_assert (! wa_have_performed_setup);
}

WA_PRIVATE void
wa_assert_fail (const char *file,
        int line,
        const char *function,
        const char *expr)
{
    wa_err ("Assertion failure: %s:%d:%s:%s\n",
            file, line, function, expr);

    abort ();
}

/**
 * _wa_log_msg:
 *
 * @file: filename of caller,
 * @line: line number of caller,
 * @func: function name of caller,
 * @fmt: printf-style format and possible args.
 *
 * Log a printf-style message to stderr
 * using write(2).
 *
 * Calls abort(3) on (internal/ENOMEM) error.
 */
void WA_PRIVATE
_wa_log_msg (const char *file,
        int line,
        const char *func,
        const char *fmt, ...)
{
    char     buffer[WA_LOG_BUFSIZE];
    char    *p = buffer;
    char    *logfile = NULL;
    va_list  ap;
    pid_t    pid;
    pid_t    ppid;
    int      ret = 0;
    size_t   len = 0;
    int      fd = STDERR_FILENO;

    pid  = getpid ();
    ppid = getppid ();

    if (! wa_have_performed_setup) {
        wa_perform_setup ();
    }

    logfile = getenv (WRAP_ALLOC_LOGFILE_ENV);
    if (logfile) {
        fd = open (logfile, (O_CREAT|O_APPEND|O_WRONLY), 0640);
        if (fd < 0) {
            goto err_open_logfile;
        }
    }

    if (wa_debug_value > 1) {
        ret = sprintf (p, "%s:pid=%d:ppid=%d:file=%s:line=%d:func=%s:",
                APP_NAME, pid, ppid, file, line, func);
        if (ret < 0)
            goto err;
        len += ret;
        p += len;
    }

    va_start (ap, fmt);

    ret = vsnprintf (p, WA_LOG_BUFSIZE-len, fmt, ap);
    if (ret < 0)
        goto err;
    len += ret;

    va_end (ap);

    strcat (buffer, "\n");

    if (write (fd, buffer, len) < 0)
        goto oh_dear;

    if (fd != STDERR_FILENO)
        close (fd);

    return;

err:
    /* we're getting REALLY desperate now! */
    len = sprintf (buffer,
            "ERROR: pid=%d, ppid=%d:file=%s:line=%d:func=%s: "
            "failed to prepare buffer (fmt=\"%s\")\n",
            pid, ppid, file, line, func,
            fmt);

    if (write (STDERR_FILENO, buffer, len) < 0)
        goto oh_dear;

    abort ();

err_open_logfile:
    len = sprintf (buffer,
            "ERROR: pid=%d, ppid=%d:file=%s:line=%d:func=%s: "
            "failed to open logfile %s (errno=%d [%s])\n",
            pid, ppid, file, line, func,
            logfile, errno, strerror (errno));

    if (write (STDERR_FILENO, buffer, len) < 0)
        goto oh_dear;

    abort ();

oh_dear:
    fprintf (stderr, "ERROR: write of length %lu failed\n",
            (unsigned long int)len);
    abort ();
}

/**
 * wa_get_memory:
 *
 * @size: number of bytes to allocate.
 *
 * Allocate memory using a safe method.
 *
 * Returns memory block of size @size bytes, or NULL on error.
 **/
WA_PRIVATE void *
__attribute ((malloc, warn_unused_result, no_instrument_function))
wa_get_memory (size_t size)
{
    void *v = NULL;

    if (! size)
        return NULL;

#ifdef HAVE_MMAP
    v = mmap (NULL,
            size,
            PROT_READ|PROT_WRITE,   
            MAP_ANON|MAP_PRIVATE,
            -1, 0);

    if (v == MAP_FAILED) {
        wa_debug ("%s: memory allocation failed (requested size=%lu, size=%lu",
                __func__,
                (unsigned long int)size,
                (unsigned long int)size);
        return NULL;
    }

#elif USE_LD_PRELOAD

#error "ERROR: need mmap as cannot call real mem routines in LD_PRELOAD environment."

#else /* linker-trick mode */

    v = __real_calloc (1, size);

#endif

    return v;
}

/*!
 * Convert arbitrary data into printable format.
 *
 * \param bytes Number of Bytes to consider.
 * \param data Data to consider.
 * \param buffer Buffer to write printable characters to.
 * \return Number of characters written to buffer.
 *
 * \note buffer must be atleast as large as 'data' (ie atleast
 * 'bytes'+1 bytes long).
 *
 * \warning It is the callers responsibility to ensure buffer is large
 * enough.
 */
WA_PRIVATE int
wa_show_printable (size_t       bytes,
                   const void  *data,
                   char        *buffer) {
    char *b = buffer;
    const byte *p = (const byte *)data;
    size_t total = 0;

    assert (buffer);

    if (bytes == 0 || !data) {
        return 0;
    }

    while (bytes) {
        if (isspace (*p)) {
            *b = ' ';
        } else if (isprint (*p)) {
            *b = *p;
        } else {
            *b = '.';
        }

        total++;
        p++;
        b++;
        bytes--;
    }

    return total;
}

/* Output the specified data in both hex and printable ASCII characters.
 *
 * Limitations: should really display like gdb does (ie 0x0 == '\0'),
 * but the simple alignment code used here wouldn't work in that
 * scenario.
 */
WA_PRIVATE void
wa_tohex (size_t count, const void *data)
{
    char         buffer[WA_BUFSIZE];
    char        *p;
    const byte  *bytes;
    size_t       byte_count = 0;
    size_t       i;
    int          ret;

    int          blanks = 0;

    wa_assert (count);
    wa_assert (data);

    bytes = (const byte *)data;
    p = buffer;

    memset (buffer, '\0', WA_BUFSIZE);

    /* initial offset */
    ret = sprintf (p, "%06lx: ", (unsigned long int)0x0);
    if (ret < 0)
        goto error;
    p += ret;
    byte_count += ret;

    for (i = 0; i < count; i++) {

        /* print 2 bytes in hex */
        *p++ = wa_hexmap[ (((unsigned int) bytes[i]) & 0xF0) >> 4 ];
        *p++ = wa_hexmap[ (((unsigned int) bytes[i]) & 0x0F) ];
        byte_count += 2;

        /* add spaces between blocks of 2 bytes */
        ret = sprintf (p, "%s", (((i % 2) == 0) ? "" : " "));
        if (ret < 0)
            goto error;
        p += ret;
        byte_count += ret;

        if (WA_HAVE_LINE_TO_DISPLAY (i)) {
            int indent = i + 1 - WA_BYTES_PER_LINE;

            *p++ = ' ';
            byte_count++;

            /* display ASCII equivalent after hex string */
            ret = wa_show_printable (WA_BYTES_PER_LINE, bytes + indent, p);
            p += ret;
            byte_count += ret;

            WA_TOHEX_OUTPUT_AND_CLEAR(buffer, p, ret, byte_count);

            /* header */
            ret = sprintf (p, "%06lx: ", (unsigned long int) i + 1);
            p += ret;
            byte_count += ret;
        }
    }

    /* unless the amount of data to display is an exact multiple of BYTES_PER_LINE,
     * the last line will be shorter than the rest and needs
     * space-padding.
     */
    blanks = (WA_BYTES_PER_LINE - (count % WA_BYTES_PER_LINE));

    if (blanks < WA_BYTES_PER_LINE) {
        int tmpblanks = blanks;

        /* print a chunk of spaces to fill the gap of "blanks" blank hex
         * digits (hence the "2*" since each hex digit is represented as 2
         * actual digits).
         */
        ret = sprintf (p, "%*s", (2 * tmpblanks), " ");
        if (ret < 0)
            goto error;

        p += ret;
        byte_count += ret;

        /* allow for spaces between each block of 2 hex digits */
        tmpblanks = blanks / 2;

        ret = sprintf (p, "%*s", tmpblanks, " ");
        if (ret < 0)
            goto error;

        p += ret;
        byte_count += ret;

        /* fine-tuning */
        ret = sprintf (p, " ");
        if (ret < 0)
            goto error;

        p += ret;
        byte_count += ret;

        /* finally, bump pointer along if there are an odd numbe of digits
         * to display in the last line since this implies that we've got to
         * make up for the fact that we only have the "first half" of a set
         * of 2 hex digits no the last line.
         */
        if (blanks % 2) {
            ret = sprintf (p, " ");
            if (ret < 0)
                goto error;
            p += ret;
            byte_count += ret;
        }

        ret = wa_show_printable (WA_BYTES_PER_LINE - blanks,
                                 ((byte *)data) +
                                 (count - (WA_BYTES_PER_LINE - blanks)),
                                 p);
        p += ret;
        byte_count += ret;

        WA_TOHEX_OUTPUT_AND_CLEAR(buffer, p, ret, byte_count);
    }

    return;

error:

    fprintf (stderr, "ERROR: failed to convert bytes to hex\n");
}

WA_PRIVATE const char *
wa_signal_num_to_name (int signum)
{
    assert (signum >= 0);

    struct wa_signal_map *p;

    for (p = wa_signal_map; p && p->signame; p++) {
        if (signum == p->signum)
            return p->signame;
    }

    return NULL;
}

WA_PRIVATE int
wa_signal_name_to_num (const char *signame)
{
    assert (signame);

    struct wa_signal_map *p;

    for (p = wa_signal_map; p && p->signame; p++) {
        if (! strcmp (signame, p->signame) ||
                /* +3 to hop over leading 'SIG' */
                strstr (p->signame, signame) == p->signame+3)
            return p->signum;
    }

    return -1;
}

