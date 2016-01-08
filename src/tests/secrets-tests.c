/*
    SSSD

    secrets-tests.c

    Authors:
        Christian Heimes <cheimes@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <stdio.h>

#include "providers/secrets/secrets.h"

int main(int argc, const char *argv[]) {
    int rc = 0;
    struct secrets_context *ctx;
    struct secrets_data data = {0};

    if (secrets_init(&ctx, "demo") < 0) {
        perror("secrets_init failed");
        rc = 1;
        goto exit;
    }

    if (secrets_get(ctx, "/example", &data) < 0) {
        perror("secrets_get failed");
        rc = 2;
        goto exit;
    }
    fprintf(stdout, "%*s\n", (int)data.length, data.data);

  exit:
    secrets_data_contents_free(&data);
    secrets_context_free(&ctx);
    return rc;
}
