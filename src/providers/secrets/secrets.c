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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "providers/secrets/secrets.h"
#include "util/atomic_io.h"

char request[] = "\
%s /secrets/%s/%s HTTP/1.1\r\n\
Host: localhost\r\n\
\r\n\
";

static int secrets_data_contents_set(struct secrets_data *, void *, size_t);

static int
do_request(struct secrets_context *ctx, const char *method,
           const char *name, struct secrets_data *data)
{
    struct sockaddr_un address;
    int fd = -1;
    int nbytes;
    char buffer[4096];

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    nbytes = snprintf(address.sun_path,
                      sizeof(address.sun_path) - 1,
                      ctx->socket_name);
    if (nbytes >= sizeof(address.sun_path) - 1) {
        errno = ENAMETOOLONG;
        goto error;
    }

    if (connect(fd,
                (struct sockaddr *)&address,
                sizeof(struct sockaddr_un)) != 0) {
        goto error;
    }

    nbytes = snprintf(buffer, sizeof(buffer), request,
                      method, ctx->appname, name);
    if (nbytes >= sizeof(buffer)) {
        errno = ENAMETOOLONG;
        goto error;
    }

    /* check */
    if (sss_atomic_write_s(fd, buffer, nbytes) < 0) {
        goto error;
    }

    /* check */
    nbytes = sss_atomic_read_s(fd, buffer, sizeof(buffer));
    if (nbytes < 0) {
        goto error;
    }
    if (secrets_data_contents_set(data, buffer, nbytes) < 0) {
        goto error;
    }

    close(fd);
    return 0;

   error:
    if (fd >= 0) {
        close(fd);
    }
    return -1;
}

int
secrets_get(struct secrets_context *ctx,
            const char *name,
            struct secrets_data *data)
{
    return do_request(ctx, "GET", name, data);
}

int
secrets_put(struct secrets_context *ctx,
            const char *name,
            struct secrets_data *data)
{
    return -1;
}

int
secrets_list(struct secrets_context *ctx,
             const char *path,
             struct secrets_list *list)
{
    return -1;
}

int
secrets_init(struct secrets_context **pctx,
             const char *appname)
{
    struct secrets_context *ctx = NULL;
    size_t len;

    if (appname == NULL) {
        errno = EINVAL;
        goto error;
    }

    ctx = (struct secrets_context *)malloc(sizeof(struct secrets_context));
    if (ctx == NULL) {
        errno = ENOMEM;
        goto error;
    }

    len = strlen(appname);
    if ((ctx->appname = (char*)malloc(len + 1)) == NULL) {
        errno = ENOMEM;
        goto error;
    }
    strncpy(ctx->appname, appname, len);
    ctx->appname[len] = '\0';

    ctx->socket_name = SSS_SECRETS_SOCKET_NAME;

    *pctx = ctx;
    return 0;

  error:
    secrets_context_free(pctx);
    return -1;
}

void
secrets_context_free(struct secrets_context **pctx)
{
    struct secrets_context *ctx;

    if (pctx == NULL) {
        return;
    }
    ctx = *pctx;
    if (ctx->appname != NULL) {
        free(ctx->appname);
    }
    free(ctx);
    *pctx = NULL;
}

void
secrets_list_contents_free(struct secrets_list *list)
{
    size_t i;

    if (list == NULL) {
        return;
    }

    for (i = 0; i < list->count; i++) {
        secrets_data_contents_free(list->elements[i]);
    }
    list->count = 0;
    free(list->elements);
}

static int
secrets_data_contents_set(struct secrets_data *data,
                          void *buffer,
                          size_t length)
{
    data->data = (uint8_t *)malloc(length+1);
    if (data->data == NULL) {
        errno = ENOMEM;
        data->length = 0;
        return -1;
    }
    memcpy(data->data, buffer, length);
    data->data[length] = 0;
    data->length = length;

    return 0;
}

void
secrets_data_contents_free(struct secrets_data *data)
{
    if (data == NULL) {
        return;
    }
    if (data->data != NULL) {
        free(data->data);
        data->data = NULL;
    }
    data->length = 0;
}
