/*--------------------------------------------------------------------
 * wrapalloc - basic test program.
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

/*--------------------------------------------------------------------
 * Description: Test program for wrapalloc that can cause an underrun or
 * overrun, but which is NOT linked with -lwrapalloc. This allows us to
 * test the LD_PRELOAD handling.
 *--------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#define WORD "hello"

char *program_name;

void
test_wrapalloc (const char *action)
{
    char   *string = WORD;
    size_t  len;

    assert (action);

    len = strlen (string);

    string = (char *)malloc (len+1);

    if (! string) {
        fprintf (stderr,
                "%s:%d: malloc failed - errno=%d\n",
                __func__, __LINE__, errno);
        exit (EXIT_FAILURE);
    }

    strncpy (string, WORD, len+1);

    if (! strcmp (action, "underrun")) {
        fprintf (stderr, "forcing an underrun\n");
        *(string-1) = 'U';
    } else if (! strcmp (action, "overrun")) { 
        fprintf (stderr, "forcing an overrun\n");
        *(string + len+1) = 'O';
    } else {
        fprintf (stderr, "No under/over-run requested\n");
    }

    free (string);
}

int main (int argc, char *argv[])
{
    const char *action;

    program_name = argv[0];

    if (argc != 2) {
        fprintf (stderr, "ERROR: usage: %s <underrun|overrun|normal>\n",
                program_name);
        exit (EXIT_FAILURE);
    }

    action = argv[1];
    test_wrapalloc (action);

    exit (EXIT_SUCCESS);
}
