/*--------------------------------------------------------------------
 * wrapalloc - check unit test program (see http://check.sourceforge.net/).
 *
 * Copyright (C) 2012-2015 James Hunt <jamesodhunt@gmail.com>.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define WA_TESTS
#include <wrap_alloc.h>
#include <check.h>

#define                  WA_TEST_BUFSIZE 1024
#define KILOBYTE(n)      (1024 * (n))
#define MEGABYTE(n)      (1024 * KILOBYTE (n))

/* arbitrary value that is also a prime to make life interesting */
static const int value = 17;

/********************************************************************/

START_TEST(test_alloc)
{
    size_t          request_size;
    size_t          request_size_max = KILOBYTE (1);
    size_t          i;
    size_t          len;
    char           *requested;
    char           *p;
    MemoryCtlBlock *m;
    unsigned long   pre_border_size;
    unsigned long   post_border_size;
    byte            fill_byte;
    char           *pre_border;
    char           *post_border;

    pre_border_size = wa_get_border_size (WA_BUFFER_TYPE_PRE);
    post_border_size = wa_get_border_size (WA_BUFFER_TYPE_POST);

    for (request_size = 0; request_size < request_size_max; request_size++) {

        requested = malloc (request_size);

        if (! request_size) {
            /* handle malloc (0) */
            ck_assert_ptr_eq (requested, NULL);
            continue;
        }

        ck_assert_ptr_ne (requested, NULL);

        m = wa_ptr_to_mcb (requested);
        ck_assert_ptr_ne (m, NULL);

        /* perform a couple of checks that wa_check_ctl_block() can't */
        ck_assert_uint_eq (m->request_size, (unsigned int)request_size);
        ck_assert_ptr_eq (m->memory, requested);

        wa_check_ctl_block (m);

        /************************************************************/
        /* Check pre border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_PRE);
        pre_border = wa_mcb_to_pre_border (m);

        /* Note: we can't use strspn(3) since 0x0 (aka '\0') is a valid
         * fill byte.
         */

        for (i = 0; i < pre_border_size; i++) {
            p = pre_border + i;
            assert (*p == fill_byte);
        }

        /************************************************************/
        /* Check post border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_POST);
        post_border = wa_mcb_to_post_border (m);

        for (i = 0; i < post_border_size; i++) {
            p = post_border + i;
            assert (*p == fill_byte);
        }

        free (requested);
    }
}
END_TEST

/********************************************************************/

START_TEST(test_realloc)
{
    size_t          request_size;
    size_t          request_size_max = KILOBYTE (1);
    size_t          i;
    size_t          len;
    char           *orig;
    char           *requested;
    char           *p;
    MemoryCtlBlock *m;
    unsigned long   pre_border_size;
    unsigned long   post_border_size;
    byte            fill_byte;
    char           *pre_border;
    char           *post_border;
    size_t          original_size = 1;

    pre_border_size = wa_get_border_size (WA_BUFFER_TYPE_PRE);
    post_border_size = wa_get_border_size (WA_BUFFER_TYPE_POST);

    /* Test malloc(3)-like functionality.
     *
     * Note that the behaviour of "realloc (NULL, 0)" seems to be undefined.
     */
    for (request_size = 1; request_size < request_size_max; request_size++) {

        requested = realloc (NULL, request_size);
        ck_assert_ptr_ne (requested, NULL);

        ck_assert (wa_address_valid (requested));

        m = wa_ptr_to_mcb (requested);
        ck_assert_ptr_ne (m, NULL);

        /* perform a couple of checks that wa_check_ctl_block() can't */
        ck_assert_uint_eq (m->request_size, (unsigned int)request_size);
        ck_assert_ptr_eq (m->memory, requested);

        wa_check_ctl_block (m);

        /************************************************************/
        /* Check pre border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_PRE);
        pre_border = wa_mcb_to_pre_border (m);

        /* Note: we can't use strspn(3) since 0x0 (aka '\0') is a valid
         * fill byte.
         */

        for (i = 0; i < pre_border_size; i++) {
            p = pre_border + i;
            assert (*p == fill_byte);
        }

        /************************************************************/
        /* Check post border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_POST);
        post_border = wa_mcb_to_post_border (m);

        for (i = 0; i < post_border_size; i++) {
            p = post_border + i;
            assert (*p == fill_byte);
        }

        free (requested);
    }

    orig = malloc (original_size);
    ck_assert_ptr_ne (orig, NULL);

    /* Test re-allocation functionality */
    for (request_size = 1; request_size < request_size_max; request_size++) {

        requested = realloc (orig, request_size);
        ck_assert_ptr_ne (requested, NULL);

        m = wa_ptr_to_mcb (requested);
        ck_assert_ptr_ne (m, NULL);

        /* perform a couple of checks that wa_check_ctl_block() can't */
        ck_assert_uint_eq (m->request_size, (unsigned int)request_size);
        ck_assert_ptr_eq (m->memory, requested);

        wa_check_ctl_block (m);

        /************************************************************/
        /* Check pre border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_PRE);
        pre_border = wa_mcb_to_pre_border (m);

        /* Note: we can't use strspn(3) since 0x0 (aka '\0') is a valid
         * fill byte.
         */

        for (i = 0; i < pre_border_size; i++) {
            p = pre_border + i;
            assert (*p == fill_byte);
        }

        /************************************************************/
        /* Check post border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_POST);
        post_border = wa_mcb_to_post_border (m);

        for (i = 0; i < post_border_size; i++) {
            p = post_border + i;
            assert (*p == fill_byte);
        }

        orig = requested;
    }

    free (requested);

}
END_TEST

/********************************************************************/

// FIXME: check build specifies -std=gnu99 to ensure alloca calls not
// inlined.
#if 0
/* Note that wrapalloc changes the behaviour of alloca; normally the
 * memory is allocated on the stack, but wrapalloc subverts the calls
 * and allocates on the heap. This means that free(3) *MUST* be called
 * for the tests, but must *NOT* be called in real code since when not
 * linked to wrapalloc, that would introduce a memory leak.
 */
START_TEST(test_alloca)
{
    size_t          request_size;
    //size_t          request_size_max = KILOBYTE (1);
    size_t          request_size_max = 8;
    size_t          i;
    size_t          len;
    char           *requested;
    char           *p;
    MemoryCtlBlock *m;
    unsigned long   pre_border_size;
    unsigned long   post_border_size;
    byte            fill_byte;
    char           *pre_border;
    char           *post_border;

    pre_border_size = wa_get_border_size (WA_BUFFER_TYPE_PRE);
    post_border_size = wa_get_border_size (WA_BUFFER_TYPE_POST);

    /* alloca(0) behaviour is undefined seemingly, so start at 1 */
    for (request_size = 1; request_size < request_size_max; request_size++) {

        printf ("FIXME: request_size=%d\n", (int)request_size);fflush (NULL);

        requested = alloca (request_size);
        ck_assert_ptr_ne (requested, NULL);

        m = wa_ptr_to_mcb (requested);
        ck_assert_ptr_ne (m, NULL);

        /* perform a couple of checks that wa_check_ctl_block() can't */
        ck_assert_uint_eq (m->request_size, (unsigned int)request_size);
        ck_assert_ptr_eq (m->memory, requested);

        wa_check_ctl_block (m);

        /************************************************************/
        /* Check pre border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_PRE);
        pre_border = wa_mcb_to_pre_border (m);

        /* Note: we can't use strspn(3) since 0x0 (aka '\0') is a valid
         * fill byte.
         */

        for (i = 0; i < pre_border_size; i++) {
            p = pre_border + i;
            assert (*p == fill_byte);
        }

        /************************************************************/
        /* Check post border */

        fill_byte = wa_get_fill_byte (WA_BUFFER_TYPE_POST);
        post_border = wa_mcb_to_post_border (m);

        for (i = 0; i < post_border_size; i++) {
            p = post_border + i;
            assert (*p == fill_byte);
        }

        /* Safe, and correct - we're not really calling alloca(3)
         * remember.
         */
        free (requested);
    }
}
END_TEST
#endif

/********************************************************************/

/* XXX: Makes use of @_i magic loop variable passed in by caller */
START_TEST(test_underrun)
{
    char           *requested;
    MemoryCtlBlock *m;
    size_t          request_size = value;

    requested = malloc (request_size);
    ck_assert_ptr_ne (requested, NULL);

    m = wa_ptr_to_mcb (requested);
    ck_assert_ptr_ne (m, NULL);

    /* Force an underrun */
    *(requested - _i) = 'X';

    free (requested);
}
END_TEST

/********************************************************************/

START_TEST(test_overrun)
{
    byte            *requested;
    MemoryCtlBlock  *m;
    size_t           request_size = value;

    requested = malloc (request_size);
    ck_assert_ptr_ne (requested, NULL);

    m = wa_ptr_to_mcb (requested);
    ck_assert_ptr_ne (m, NULL);

    /* Force an overrun */
    *((requested + (request_size - 1)) + _i) = 'X';

    free (requested);
}
END_TEST

/********************************************************************/

START_TEST(test_exit_on_abort)
{
    byte            *requested;
    MemoryCtlBlock  *m;
    size_t           request_size = value;
    char             buffer[] = "exit:XXX";
    char            *p;

    p = buffer;
    sprintf (p, "exit:%d", _i);

    ck_assert (!setenv (WRAP_ALLOC_SEGV_ACTION_ENV, buffer, 1));

    requested = malloc (request_size);
    ck_assert_ptr_ne (requested, NULL);

    m = wa_ptr_to_mcb (requested);
    ck_assert_ptr_ne (m, NULL);

    /* Force an underrun */
    *(requested -1) = 'X';

    /* @NOTREACHED */
    free (requested);
}
END_TEST

/********************************************************************/

START_TEST(test_signal_num_on_abort)
{
    byte            *requested;
    MemoryCtlBlock  *m;
    size_t           request_size = value;
    char             buffer[] = "signal:XXX";
    char            *p;

    p = buffer;
    sprintf (p, "signal:%d", _i);

    ck_assert (!setenv (WRAP_ALLOC_SEGV_ACTION_ENV, buffer, 1));

    requested = malloc (request_size);
    ck_assert_ptr_ne (requested, NULL);

    m = wa_ptr_to_mcb (requested);
    ck_assert_ptr_ne (m, NULL);

    /* Force an underrun */
    *(requested -1) = 'X';

    /* @NOTREACHED */
    free (requested);
}
END_TEST

/********************************************************************/

START_TEST(test_signal_name_on_abort)
{
    byte            *requested;
    MemoryCtlBlock  *m;
    size_t           request_size = value;
    char             buffer[] = "signal:SIGXXXXXXXX";
    char            *p;

    p = buffer;
    sprintf (p, "signal:%s", wa_signal_num_to_name (_i));

    ck_assert (!setenv (WRAP_ALLOC_SEGV_ACTION_ENV, buffer, 1));

    requested = malloc (request_size);
    ck_assert_ptr_ne (requested, NULL);

    m = wa_ptr_to_mcb (requested);
    ck_assert_ptr_ne (m, NULL);

    /* Force an underrun */
    *(requested -1) = 'X';

    /* @NOTREACHED */
    free (requested);
}
END_TEST

/********************************************************************/

START_TEST(test_fill_on_alloc)
{
    byte            *requested;
    byte            *p;
    MemoryCtlBlock  *m;
    size_t           request_size = value;
    size_t           i;
    size_t           len = 0;
    byte             fill_byte;

    ck_assert (!setenv (WRAP_ALLOC_ALLOC_BYTE_ENV, "0xab", 1));

    p = requested =  malloc (request_size);
    ck_assert_ptr_ne (requested, NULL);

    m = wa_ptr_to_mcb (requested);
    ck_assert_ptr_ne (m, NULL);

    fill_byte = wa_get_alloc_fill_byte ();
    ck_assert (fill_byte == 0xab);

    for (i = 0; i < request_size; i++) {
        if (*(p+i) == 0xab)
            len++;
    }

    ck_assert_uint_eq (len, request_size);

    free (requested);

}
END_TEST

/********************************************************************/

START_TEST(test_fill_on_clear)
{
    byte            *requested;
    byte            *p;
    MemoryCtlBlock  *m;
    size_t           request_size = value;
    size_t           i;
    size_t           len = 0;
    byte             fill_byte;

    ck_assert (!setenv (WRAP_ALLOC_FREE_BYTE_ENV, "0xcd", 1));

    p = requested = malloc (request_size);
    ck_assert_ptr_ne (requested, NULL);

    m = wa_ptr_to_mcb (requested);
    ck_assert_ptr_ne (m, NULL);

    fill_byte = wa_get_free_fill_byte ();
    ck_assert (fill_byte == 0xcd);

    free (requested);

    /* XXX: note that this is only legal since the tests are run with 
     * WRAP_ALLOC_DISABLE_FREE_ENV set.
     */
    for (i = 0; i < request_size; i++) {
        if (*(p+i) == 0xcd)
            len++;
    }
    ck_assert_uint_eq (len, request_size);
}
END_TEST

/********************************************************************/

START_TEST(test_wa_show_printable)
{
    char   buffer[WA_TEST_BUFSIZE];
    int    ret;
    char  *str0 = "";
    char  *str1 = "a";
    char  *str2 = "abcdefghijklmnopqrstuvwxyz";
    char  *str3 = "012345 	\t6789\0\1\2\3\4abcdefGHI";
    int    str3_len = 27;
    char  *str4 = "\t\v";
    int    str4_len = 2;

    memset (buffer, '\0', sizeof (buffer));
    ret = wa_show_printable (strlen (str0), str0, buffer);
    ck_assert_int_eq (ret, strlen (str0));
    ck_assert (buffer[0] == '\0');

    memset (buffer, '\0', sizeof (buffer));
    ret = wa_show_printable (strlen (str1), str1, buffer);
    ck_assert_int_eq (ret, strlen (str1));
    ck_assert_str_eq (buffer, str1);

    memset (buffer, '\0', sizeof (buffer));
    ret = wa_show_printable (strlen (str2), str2, buffer);
    ck_assert_int_eq (ret, strlen (str2));
    ck_assert_str_eq (buffer, str2);

    memset (buffer, '\0', sizeof (buffer));
    ret = wa_show_printable (str3_len, str3, buffer);
    ck_assert_int_eq (ret, str3_len);
    ck_assert_str_eq (buffer, "012345   6789.....abcdefGHI");

    memset (buffer, '\0', sizeof (buffer));
    ret = wa_show_printable (strlen (str4), str4, buffer);
    ck_assert_int_eq (ret, str4_len);
    ck_assert_str_eq (buffer, "  ");
}
END_TEST

/********************************************************************/

Suite *
wrapalloc_suite (void)
{
    Suite *s;
    TCase *tc_core;

    size_t underrun_bytes_max;
    size_t overrun_bytes_max;

    int i;
    struct wa_signal_map *p;

    s = suite_create ("wrapalloc");
    assert (s);

    tc_core = tcase_create ("core");

    underrun_bytes_max = wa_get_border_size (WA_BUFFER_TYPE_PRE);
    overrun_bytes_max = wa_get_border_size (WA_BUFFER_TYPE_POST);

    /*******************************/
    /* Add each test */

    tcase_add_test (tc_core, test_alloc);
    tcase_add_test (tc_core, test_realloc);

    tcase_add_test (tc_core, test_wa_show_printable);

    // FIXME: unbork alloca code.
    //tcase_add_test (tc_core, test_alloca);
    
    /* XXX: Only test around the beginning and end of the borders since
     * checking the entire range is prohibitively expensive wrt time
     * (since check forks for each iteration).
     *
     * FIXME: resolve this by setting WRAP_ALLOC_BORDER=32
     *
     * Note that the test starts at 1 (since writing a "negative"
     * offset of zero is NOT an error :-)
     */

    tcase_add_loop_test_raise_signal (tc_core, test_underrun,
            SIGABRT, 1, value+1);

    tcase_add_loop_test_raise_signal (tc_core, test_underrun,
            SIGABRT, underrun_bytes_max - value, underrun_bytes_max);

    tcase_add_loop_test_raise_signal (tc_core, test_overrun,
            SIGABRT, 1, value+1);

    tcase_add_loop_test_raise_signal (tc_core, test_overrun,
            SIGABRT, overrun_bytes_max - value, overrun_bytes_max);

    tcase_add_test (tc_core, test_fill_on_alloc);

    tcase_add_test (tc_core, test_fill_on_clear);

    for (i = 0; i < 256; i++) {
        tcase_add_loop_exit_test (tc_core, test_exit_on_abort, i, i, i+1);
    }

    /* values > 255 should be converted to 255 as that is the largest
     * value that can be returned via exit(2).
     */
    tcase_add_loop_exit_test (tc_core, test_exit_on_abort, 255, 256, 257);

    /* There are too many issues testing all possible signals, hence
     * just test a selection.
     */
    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_num_on_abort,
            SIGHUP, SIGHUP, SIGHUP+1);
    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_name_on_abort,
            SIGHUP, SIGHUP, SIGHUP+1);

    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_num_on_abort,
            SIGINT, SIGINT, SIGINT+1);
    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_name_on_abort,
            SIGINT, SIGINT, SIGINT+1);

    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_num_on_abort,
            SIGUSR1, SIGUSR1, SIGUSR1+1);
    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_name_on_abort,
            SIGUSR1, SIGUSR1, SIGUSR1+1);

    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_num_on_abort,
            SIGUSR2, SIGUSR2, SIGUSR2+1);
    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_name_on_abort,
            SIGUSR2, SIGUSR2, SIGUSR2+1);

    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_num_on_abort,
            SIGABRT, SIGABRT, SIGABRT+1);
    tcase_add_loop_test_raise_signal (tc_core,
            test_signal_name_on_abort,
            SIGABRT, SIGABRT, SIGABRT+1);

    /*******************************/

    suite_add_tcase(s, tc_core);

    return s;
}

/********************************************************************/

int
main (int argc, char *argv[])
{
    Suite    *s;
    SRunner  *sr;
    int       number_failed;

    s = wrapalloc_suite ();
    sr = srunner_create (s);

    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (! number_failed) ? EXIT_SUCCESS : EXIT_FAILURE;
}
