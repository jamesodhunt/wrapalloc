/*--------------------------------------------------------------------
 * wrapalloc - basic test program.
 *
 * Copyright (C) 2012-2025 James Hunt <jamesodhunt@gmail.com>.
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
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WORD "hello"

char *program_name;

#define UNDERRUN_BYTE 'U'
#define OVERRUN_BYTE  'O'

void
test_wrapalloc(const char *action)
{
    char *string = WORD;
    size_t len;
    size_t bytes;

    assert(action);

    len = strlen(string);

    bytes = len + 1;

    printf("INFO: allocating %lu bytes\n", bytes);
    fflush(NULL);

    string = (char *)malloc(bytes);

    if (!string) {
        int saved = errno;

        fprintf(stderr,
                "ERROR: %s:%d: malloc failed: errno: %d ('%s')\n",
                __func__,
                __LINE__,
                saved,
                strerror(saved));

        exit(EXIT_FAILURE);
    }

    printf("INFO: allocated %lu bytes\n", bytes);

    strncpy(string, WORD, len + 1);

    if (!strcmp(action, "underrun")) {
        printf("INFO: forcing an underrun with byte '%c' (0x%x)\n",
               UNDERRUN_BYTE,
               UNDERRUN_BYTE);
        *(string - 1) = UNDERRUN_BYTE;

    } else if (!strcmp(action, "overrun")) {
        printf("INFO: forcing an overrun with byte '%c' (0x%x)\n",
               OVERRUN_BYTE,
               OVERRUN_BYTE);
        *(string + len + 1) = OVERRUN_BYTE;
    } else {
        printf("INFO: No under/over-run requested\n");
    }

    printf("INFO: freeing %lu bytes\n", bytes);
    fflush(NULL);

    free(string);

    printf("INFO: freed %lu bytes\n", bytes);
}

int
main(int argc, char *argv[])
{
    const char *action;

    program_name = argv[0];

    if (argc != 2) {
        fprintf(stderr,
                "ERROR: usage: %s <underrun|overrun|normal>\n",
                program_name);
        exit(EXIT_FAILURE);
    }

    action = argv[1];
    test_wrapalloc(action);

    exit(EXIT_SUCCESS);
}
