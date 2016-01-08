/*
   SSSD

   Secrets provider

   Copyright (C) Christian Heimes <cheimes@redhat.com> 2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __PROVIDERS_SECRETS_H__
#define __PROVIDERS_SECRETS_H__


#include <stdint.h>
#include <stdlib.h>

struct secrets_context {
    char *appname;
    const char *socket_name;
};

struct secrets_data {
    size_t length;
    uint8_t *data; /* null terminates data */
};

struct secrets_list {
    int count;
    struct secrets_data *elements[];
};

int secrets_init(struct secrets_context **pctx,
                 const char *appname);
int secrets_get(struct secrets_context *ctx,
                const char *name,
                struct secrets_data *data);
int secrets_put(struct secrets_context *ctx,
                const char *name,
                struct secrets_data *data);
int secrets_list(struct secrets_context *ctx,
                 const char *path,
                 struct secrets_list *list);

void secrets_context_free(struct secrets_context **pctx);
void secrets_list_contents_free(struct secrets_list *list);
void secrets_data_contents_free(struct secrets_data *data);

#endif /* __PROVIDERS_SECRETS_H__ */
