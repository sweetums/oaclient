/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "accessor.h"
#include "ctx.h"
#include "sql_db.h"

int oaclient_ctx_create(struct oaclient_ctx **out,
                        struct oaclient_callbacks *callbacks)
{
    int result=OAC_OK, sqlresult;

    *out=NULL;

    struct oaclient_ctx *self = calloc(sizeof(**out), 1);
    if (!self) {
        return ENOMEM;
    }

    /* 
     * XXXXXXX Instead of NULL here we probably ought to do something other 
     * than the default local directory filename.  The default should be in 
     * the user home directory (or equivalent on Windows), and it should be
     * possible to override this with configuration but we don't have a real
     * config system yet.
     */
    sqlresult = oac_db_open(self, NULL);
    if (SQLITE_OK != sqlresult) {
      free(self);
      return OAC_FAIL;
    }

    self->callbacks = callbacks;
    *out = self;
    return result;
}

void oaclient_ctx_destroy(struct oaclient_ctx *self)
{
    if (NULL == self)
        return;
    oac_db_close(self);

    if (self->db_filename)
      free(self->db_filename);

    free(self);
}

void *oaclient_ctx_set_rock(struct oaclient_ctx *ctx, void *rock)
{
    void *old = ctx->rock;
    ctx->rock = rock;
    return old;
}

void *oaclient_ctx_get_rock(struct oaclient_ctx *ctx)
{
    return ctx->rock;
}

void oaclient_ctx_set_state(struct oaclient_ctx *ctx, enum oaclient_ctx_state state) 
{
    ctx->state = state;
}

enum oaclient_ctx_state oaclient_ctx_get_state(struct oaclient_ctx *ctx)
{
    return ctx->state;
}

int oaclient_ctx_set_filename(struct oaclient_ctx *self, const char *fn)
{
    if (self->db_filename)
	free(self->db_filename);
    self->db_filename = NULL;

    if (!fn)
	return OAC_OK;

    self->db_filename = strdup(fn);
    if (!self->db_filename)
	return OAC_NOMEM;

    return OAC_OK;
}

const char *oaclient_ctx_get_filename(struct oaclient_ctx *self)
{
    return self->db_filename;
}

sqlite3 *oaclient_ctx_get_db(struct oaclient_ctx *self)
{
    return self->db;
}
