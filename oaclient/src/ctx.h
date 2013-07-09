/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
#ifndef INCLUDED_OACLIENT_CTX_H
#define INCLUDED_OACLIENT_CTX_H

#include "oaclient.h"
#include <sqlite3.h>

struct oaclient_ctx {
    struct oaclient_callbacks *callbacks;
    void *rock;
    enum oaclient_ctx_state state;    
    sqlite3 *db;
    char *db_filename;
};

int oaclient_ctx_set_filename(struct oaclient_ctx *self, const char *fn);
const char *oaclient_ctx_get_filename(struct oaclient_ctx *self);

sqlite3 *oaclient_ctx_get_db(struct oaclient_ctx *self);


#endif /* INCLUDED_OACLIENT_CTX_H */
