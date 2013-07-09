/*
** Contants and such we need for sorting out 
*/
/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
#ifndef _SQL_DB_H
#define _SQL_DB_H

#include <sqlite3.h>
#include "ctx.h"


#define SQL_DB_DEFAILT_FILENAME "oaclient_store.db"
#define SQL_DB_NAME oaclient_store


int oac_db_open(struct oaclient_ctx *ctx, const char *path);
void oac_db_close(struct oaclient_ctx *ctx);

int oac_db_update_id(struct oaclient_ctx *ctx,
		     struct oaclient_identity *id);
int oac_db_update_ep(struct oaclient_ctx *ctx,
		     struct oaclient_identity *id,
		     struct oaclient_endpoint *ep);
int oac_db_update_cred(struct oaclient_ctx *ctx,
		       struct oaclient_identity *id,
		       struct oaclient_credential *cred);

/* */
#endif

