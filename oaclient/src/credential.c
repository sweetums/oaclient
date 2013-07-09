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
#include <time.h>

#include "oaclient.h"

#include "accessor.h"
#include "credential.h"
#include "endpoint.h"
#include "tunnel.h"




int oaclient_credential_create(struct oaclient_credential **out, struct oaclient_identity *ident /*, ... */)
{
    struct oaclient_credential *self = calloc(sizeof(**out), 1);
    memset(self, 0, sizeof(*self));

    if (!self) {
        return ENOMEM;
    }

    if (ident) {
	if (ENOMEM == oaclient_identity_clone(&self->ident, ident)) {
	    free(self);
	    return ENOMEM;
	}
    } else {
	if (ENOMEM == oaclient_identity_create(&self->ident)) {
            free(self);
            return ENOMEM;
	}
    }

    *out = self;
    return 0;
}

void oaclient_credential_destroy(struct oaclient_credential *self)
{
    if (!self) return;
    if (self->scheme) free(self->scheme);
    if (self->token) free(self->token);
    if (self->secret) free(self->secret);
    if (self->session) free(self->session);
    if (self->ident) oaclient_identity_destroy(self->ident);
    
    free(self);
}

int oaclient_credential_clone(struct oaclient_credential **dst,
                              struct oaclient_credential *src)
{
  struct oaclient_credential *self;

  if (ENOMEM == oaclient_credential_create(&self, src->ident)) {
      return ENOMEM;
  }

  if (src->token && (NULL == (self->token = strdup(src->token)))) {
      oaclient_credential_destroy(self);
      return ENOMEM;
  }
  
  if (src->secret && (NULL == (self->secret = strdup(src->secret)))) {
      oaclient_credential_destroy(self);
      return ENOMEM;
  }
  
  *dst = self;
  return 0;
}

int oaclient_credential_set_identity(struct oaclient_credential *self, struct oaclient_identity *ident)
{
  /* XXXXXX Should this destroy the previously set ->ident? */
    if (!ident) 
	return 0;

    if (self->ident) {
	oaclient_identity_destroy(self->ident);
	self->ident = NULL;
    }

    if (ENOMEM == oaclient_identity_clone(&self->ident, ident)) {
	return ENOMEM;
    }

    return 0;
}

struct oaclient_identity * oaclient_credential_get_identity(struct oaclient_credential *self)
{
  return self->ident;
}

#define CC_ACCESSORS(field)                                     \
    DEFINE_GETTER(const char *, oaclient_credential, field);      \
    DEFINE_SETTER(const char *, oaclient_credential, field, v);

#define CC_TIME_T_ACCESSORS(field)                                     \
    DEFINE_GETTER(time_t, oaclient_credential, field);	       \
    DEFINE_INT_SETTER(time_t, oaclient_credential, field, v);

CC_ACCESSORS(token);
CC_ACCESSORS(secret);
CC_ACCESSORS(session);
CC_ACCESSORS(scheme);
CC_ACCESSORS(signing_method);

#undef CC_ACCESSORS
#undef CC_INT_ACCESSORS

void oaclient_credential_reset(struct oaclient_credential *self)
{
    oaclient_credential_set_token(self, NULL);
    oaclient_credential_set_session(self, NULL);
    oaclient_credential_set_secret(self, NULL);
}

/*
 * oaclient_credential_set_expiry
 *
 * Updates the expiry, taking the number of seconds returned by the auth
 * server until the credential probably expires.
 */
int oaclient_credential_set_expiry(struct oaclient_credential *self, unsigned int when)
{
    self->expiry = time(NULL) + when;
    return OAC_OK;
}
time_t oaclient_credential_get_expiry(struct oaclient_credential *self)
{
    return self->expiry;
}

/*
 *
 */
int oaclient_credential_set_rowid(struct oaclient_credential *self, unsigned row)
{
    self->rowid = row;
    return OAC_OK;
}
int oaclient_credential_get_rowid(struct oaclient_credential *self)
{
    return self->rowid;
}

/*
 *
 */
int oaclient_credential_update_from_discovery(struct oaclient_credential *self,
                                              struct oaclient_ctx *ctx,
                                              const char *discovery_header_value)
{
    return tunnel_parse_discovery(ctx, self, discovery_header_value);
}

/*
 * Get a cached credential if there is one for an endpoint.
 */
int oaclient_get_credential_from_cache(struct oaclient_credential **out,
                                       struct oaclient_ctx *ctx,
                                       struct oaclient_identity *ident)
{
    int result = OAC_FAIL;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *stmt;
    const char *tail;
    struct oaclient_credential *win;
    
    const char *query = "SELECT scheme, token, secret, session, expiry FROM creds "
	                "WHERE ( creds.identity=="
	                "       (SELECT ROWID FROM identities WHERE "
                        "        (username==:1 AND realm=:2 AND scope=:3)));";

    if (NULL == db)
	return OAC_FAIL;
    
    /* 
     * 
     */
    result = sqlite3_prepare(db, query, -1, &stmt, &tail);
    if (SQLITE_OK == result) {
	
	sqlite3_bind_text(stmt, 1, ident->user, -1, NULL);
	sqlite3_bind_text(stmt, 2, ident->realm, -1, NULL);
	sqlite3_bind_text(stmt, 3, ident->scope, -1, NULL);
 
	result = sqlite3_step(stmt);
	
	switch (result) {
	case SQLITE_ROW:
	    if (NULL == (win = malloc(sizeof(*win)))) {
		result = OAC_NOMEM;
		break;
	    }
	    memset(win, 0, sizeof(*win));

	    win->scheme = strdup((char *)sqlite3_column_text(stmt, 1));
	    win->token = strdup((char *)sqlite3_column_text(stmt, 2));
	    win->secret = strdup((char *)sqlite3_column_text(stmt, 3));
	    win->session = strdup((char *)sqlite3_column_text(stmt, 4));
	    win->expiry = sqlite3_column_int(stmt, 5);

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

int oaclient_get_credential_for_endpoint(struct oaclient_credential **out,
					 struct oaclient_ctx *ctx,
					 struct oaclient_endpoint *ep)
{
  int result = OAC_FAIL, sqlresult;
    sqlite3 *db = ctx->db;
    sqlite3_stmt *stmt;
    const char *tail;
    struct oaclient_credential *win;
    
    const char *query = "SELECT scheme, token, secret, session, expiry FROM creds "
	"WHERE ( creds.identity==(select identity from endpoints where rowid == :1 ));";


    if (NULL == db)
	return OAC_FAIL;
    
    /* do we know about the endpoint? */
    if (!(OAC_OK == oaclient_endpoint_isCached(ctx, ep)))
	return OAC_FAIL;

    /* OK, we're picking the first credential we have, there could be several
     * and eventually we probably need to be able to select for the correct
     * scheme.  Not sure though.
     */
    sqlresult = sqlite3_prepare(db, query, -1, &stmt, &tail);
    if (SQLITE_OK == sqlresult) {
	
	sqlite3_bind_int(stmt, 1, oaclient_endpoint_get_rowid(ep));
	
	sqlresult = sqlite3_step(stmt);
	
	switch (sqlresult) {
	case SQLITE_ROW:
	    if (NULL == (win = malloc(sizeof(*win)))) {
		result = OAC_NOMEM;
		break;
	    }
	    memset(win, 0, sizeof(*win));

	    win->scheme = strdup((char *)sqlite3_column_text(stmt, 1));
	    win->token = strdup((char *)sqlite3_column_text(stmt, 2));
	    win->secret = strdup((char *)sqlite3_column_text(stmt, 3));
	    win->session = strdup((char *)sqlite3_column_text(stmt, 4));
	    win->expiry = sqlite3_column_int(stmt, 5);

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


