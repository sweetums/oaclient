/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
/* Oauth SASL plugin
 * Bill Mills, Tim Showalter
 * $Id:  $
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "accessor.h"
#include "endpoint.h"

#include <sqlite3.h>
#include "sql_db.h"
#include "ctx.h"

int oaclient_endpoint_create(struct oaclient_endpoint **out)
{
    struct oaclient_endpoint *self = calloc(sizeof(**out), 1);
    if (!self) {
        return ENOMEM;
    }

    *out = self;
    return 0;
}

void oaclient_endpoint_destroy(struct oaclient_endpoint *self)
{
    free(self->username);
    free(self->hostname);
    free(self->path);
    free(self);
}

int oaclient_endpoint_set_username(struct oaclient_endpoint *self, const char *username)
{
    if (self->username) 
	free(self->username);
    if (username) {
      self->username = strdup(username);
    } else {
      self->username = NULL;
      return OAC_OK;
    }
    if (!self->username)
	return ENOMEM;

    return 0;
}

const char *oaclient_endpoint_get_username(struct oaclient_endpoint *self)
{
    return self->username;
}

int oaclient_endpoint_set_hostname(struct oaclient_endpoint *self, const char *hostname)
{
    if (self->hostname) 
	free(self->hostname);
    if (hostname) {
      self->hostname = strdup(hostname);
    } else {
      self->hostname = NULL;
      return OAC_OK;
    }
    if (!self->hostname)
	return ENOMEM;

    return 0;
}

const char *oaclient_endpoint_get_hostname(struct oaclient_endpoint *self)
{
    return self->hostname;
}


int oaclient_endpoint_set_port(struct oaclient_endpoint *self, oac_u32 port)
{
    self->port = port;
    return 0;
}

oac_u32 oaclient_endpoint_get_port(struct oaclient_endpoint *self)
{
    return self->port;
}

int oaclient_endpoint_set_path(struct oaclient_endpoint *self, const char *path)
{
    if (self->path) 
	free(self->path);
    if (path) {
      self->path = strdup(path);
    } else {
      self->path = NULL;
      return OAC_OK;
    }
    if (!self->path)
	return ENOMEM;

    return 0;
}

const char *oaclient_endpoint_get_path(struct oaclient_endpoint *self)
{
    return self->path;
}

int oaclient_endpoint_get_rowid(struct oaclient_endpoint *self)
{
    return self->rowid;
}

void oaclient_endpoint_set_rowid(struct oaclient_endpoint *self, unsigned int rowid)
{
    self->rowid = rowid;
}

/*
**
 */
int oaclient_endpoint_isCached(struct oaclient_ctx *ctx, struct oaclient_endpoint *ep)
{
  int result = OAC_FAIL, sqlresult;

  if (NULL == ctx)
    return result;

  sqlite3 *db = ctx->db;
  sqlite3_stmt *stmt;
  const char *tail;

  const char *query = "SELECT ROWID FROM endpoints "
                      "WHERE ( username==:1 AND hostname==:2 AND port==:3);";

  if (ep->rowid)
    return OAC_OK;

  if (NULL == db)
    return OAC_FAIL;

  sqlresult = sqlite3_prepare(db, query, -1, &stmt, &tail);
  if (SQLITE_OK == sqlresult) {

    sqlite3_bind_text(stmt, 1, ep->username, -1, NULL);
    sqlite3_bind_text(stmt, 2, ep->hostname, -1, NULL);
    sqlite3_bind_int(stmt, 3, ep->port);

    sqlresult = sqlite3_step(stmt);

    switch (sqlresult) {
    case SQLITE_ROW:
      ep->rowid = sqlite3_column_int(stmt, 0);
      result = OAC_OK;
      break;    
    default:
      break;
    }
    /* cleanup */
    sqlite3_finalize(stmt);
  }

  return result;
}


