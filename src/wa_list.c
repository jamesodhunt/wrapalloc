/*--------------------------------------------------------------------
 * wrapalloc - generic list handling routines.
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

#include <wa_list.h>

static inline WMList *wa_list_cut (WMList *entry);

WMList *
wa_list_new (void)
{
    WMList *list;

    list = (WMList *)wa_get_memory (sizeof (WMList));
    if (! list)
        return NULL;

    wa_list_init (list);

    return list;
}

void
wa_list_init (WMList *entry)
{
    wa_assert (entry);

    entry->prev = entry->next = entry;
}

WMList *
wa_list_add (WMList *list,
        WMList *entry)
{
    wa_assert (list);
    wa_assert (entry);

    wa_list_cut (entry);

    entry->prev = list->prev;
    list->prev->next = entry;
    list->prev = entry;
    entry->next = list;

    return entry;
}

WMList *
wa_list_add_after (WMList *list,
        WMList *entry)
{
    wa_assert (list);
    wa_assert (entry);

    wa_list_cut (entry);

    entry->next = list->next;
    list->next->prev = entry;
    list->next = entry;
    entry->prev = list;

    return entry;
}

static inline WMList *
wa_list_cut (WMList *entry)
{
    wa_assert (entry);

    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;

    return entry;
}

WMList *
wa_list_remove (WMList *entry)
{
    wa_assert (entry);

    wa_list_cut (entry);
    wa_list_init (entry);

    return entry;
}

int
wa_list_destroy (WMList *entry)
{
    wa_assert (entry);

    wa_list_cut (entry);

    return 0;
}


/**
 * wa_list_foreach:
 *
 * @list: list,
 * @len: pointer to int that will contain length of list,
 * @handler: optional function called for each list entry,
 * @data: optional data to pass to handler along with list entry.
 *
 * If @handler is NULL, list length will be returned in @len.
 * If @handler returns 1, @len will be set to the number of list entries
 * processed successfully up to that point.
 *
 * Returns 0 on success, or -1 if handler returns an error.
 **/
int
wa_list_foreach (const WMList *list, size_t *len,
        WMListHandler handler, void *data)
{
    int ret;

    wa_assert (list);

    *len = 0;

    WA_LIST_FOREACH (list, iter) {
        if (handler) {
            ret = handler (iter, data);
            if (!ret) return -1;
        }
        ++*len;
    }

    return 0;
}
