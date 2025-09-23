/*--------------------------------------------------------------------
 * wrapalloc - generic list handling header.
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

#ifndef _WM_LIST
#define _WM_LIST

#include <stdio.h>

#include <wa_util.h>

typedef struct wa_list
{
    struct wa_list *prev;
    struct wa_list *next;
} WMList;

#define WA_LIST_FOREACH(list, iter)                                           \
    for (WMList *iter = (list)->next; iter != (list); iter = iter->next)

#define WA_LIST_EMPTY(list)                                                   \
    (((list)->prev == (list)) && ((list)->next) == (list))

typedef int (*WMListHandler)(WMList *entry, void *data);

WMList *
wa_list_new(void);

void
wa_list_init(WMList *entry);

WMList *
wa_list_add(WMList *list, WMList *entry);

WMList *
wa_list_add_after(WMList *list, WMList *entry);

WMList *
wa_list_remove(WMList *entry);

int
wa_list_destroy(WMList *entry);

int
wa_list_foreach(const WMList *list,
                size_t *len,
                WMListHandler handler,
                void *data);

#endif /* _WM_LIST */
